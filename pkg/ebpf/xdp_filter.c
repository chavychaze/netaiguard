// XDP програма для фільтрації HTTP flood атак
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Структура для зберігання лічильників пакетів за IP
struct ip_count {
    __u64 packets;      // Кількість пакетів
    __u64 bytes;        // Кількість байтів
    __u64 last_seen;    // Час останнього пакету
};

// Карта для відстеження кількості пакетів за IP-адресою
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);           // IP-адреса (IPv4)
    __type(value, struct ip_count);
} ip_stats SEC(".maps");

// Карта для налаштувань обмеження швидкості
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);        // Поріг пакетів/с
} rate_limit SEC(".maps");

// Карта для блокованих IP-адрес
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);          // IP-адреса
    __type(value, __u8);         // 1 = заблоковано
} blocked_ips SEC(".maps");

// Допоміжні функції
static __always_inline int parse_ip(void *data, __u64 off, void *data_end) {
    struct iphdr *iph = data + off;
    
    // Перевірка довжини IP-заголовка
    if ((void*)(iph + 1) > data_end)
        return -1;
    
    return iph->protocol;
}

static __always_inline int parse_tcp(void *data, __u64 off, void *data_end) {
    struct tcphdr *tcph = data + off;
    
    // Перевірка довжини TCP-заголовка
    if ((void*)(tcph + 1) > data_end)
        return -1;
    
    return bpf_ntohs(tcph->dest);
}

static __always_inline int is_http(void *data, __u64 off, void *data_end) {
    int dest_port = parse_tcp(data, off, data_end);
    
    // Перевірка, чи це HTTP-трафік (порти 80, 8080)
    if (dest_port == 80 || dest_port == 8080)
        return 1;
    
    return 0;
}

// Основна XDP програма
SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Парсинг Ethernet заголовка
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Перевірка, чи це IP-пакет
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Парсинг IP заголовка
    __u64 nh_off = sizeof(*eth);
    int ipproto = parse_ip(data, nh_off, data_end);
    if (ipproto == -1)
        return XDP_PASS;
    
    // Отримання IP-адреси відправника
    struct iphdr *iph = data + nh_off;
    __u32 ip_src = iph->saddr;
    
    // Перевірка, чи IP вже заблоковано
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip_src);
    if (blocked && *blocked == 1)
        return XDP_DROP; // Дропаємо пакети з заблокованих IP
    
    // Для TCP-пакетів перевіряємо, чи це HTTP
    if (ipproto == IPPROTO_TCP) {
        __u64 tcp_off = nh_off + sizeof(*iph);
        
        // Перевірка, чи це HTTP-трафік
        if (is_http(data, tcp_off, data_end)) {
            // Отримання поточної статистики для цієї IP
            struct ip_count *count = bpf_map_lookup_elem(&ip_stats, &ip_src);
            struct ip_count new_count = {0};
            
            // Отримання поточного часу
            __u64 now = bpf_ktime_get_ns();
            
            // Якщо статистика вже існує, оновлюємо її
            if (count) {
                new_count.packets = count->packets + 1;
                new_count.bytes = count->bytes + (data_end - data);
                new_count.last_seen = now;
                
                // Розрахунок пакетів за секунду
                __u64 time_diff = now - count->last_seen;
                // Якщо пройшло менше секунди і досягнуто поріг
                if (time_diff < 1000000000 && new_count.packets > count->packets) {
                    // Перевірка поточного обмеження швидкості
                    __u32 key = 0;
                    __u32 *limit = bpf_map_lookup_elem(&rate_limit, &key);
                    
                    if (limit && (new_count.packets - count->packets) > *limit) {
                        // Перевищено поріг - маркуємо IP як заблоковану
                        __u8 block_value = 1;
                        bpf_map_update_elem(&blocked_ips, &ip_src, &block_value, BPF_ANY);
                        return XDP_DROP;
                    }
                }
            } else {
                // Створюємо нову статистику
                new_count.packets = 1;
                new_count.bytes = data_end - data;
                new_count.last_seen = now;
            }
            
            // Оновлюємо запис статистики
            bpf_map_update_elem(&ip_stats, &ip_src, &new_count, BPF_ANY);
        }
    }
    
    // За замовчуванням пропускаємо пакет
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";