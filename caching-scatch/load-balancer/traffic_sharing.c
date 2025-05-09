// Traffic shaping eBPF program with priority-based QoS
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Карта для конфігурації QoS на основі DSCP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);  // 64 можливих значень DSCP
    __type(key, __u32);       // DSCP значення як ключ
    __type(value, __u32);     // Пріоритет (0-7, де 7 - найвищий)
} dscp_priority SEC(".maps");

// Карта для обліку трафіку за DSCP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);     // Лічильник байт
} traffic_counters SEC(".maps");

// Карта для обмеження швидкості за DSCP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);     // Ліміт швидкості в Kbps
} rate_limits SEC(".maps");

// Структура метаданих для класифікованого пакета
struct packet_metadata {
    __u32 dscp;           // DSCP значення
    __u32 priority;       // Розрахований пріоритет
    __u32 rate_limit;     // Обмеження швидкості
    __u64 size;           // Розмір пакета
};

// Функція для класифікації пакета на основі DSCP
static __always_inline struct packet_metadata classify_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct packet_metadata metadata = {0};
    
    // Перевірка довжини Ethernet-заголовка
    if (data + sizeof(*eth) > data_end)
        return metadata;
        
    // Перевірка, чи це IP-пакет
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return metadata;
        
    // Парсинг IP-заголовка
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return metadata;
        
    // Отримання DSCP з IP TOS (перші 6 біт поля TOS)
    __u8 dscp = (iph->tos >> 2) & 0x3F;
    metadata.dscp = dscp;
    metadata.size = data_end - data;
    
    // Отримання пріоритету з карти
    __u32 key = dscp;
    __u32 *priority = bpf_map_lookup_elem(&dscp_priority, &key);
    if (priority)
        metadata.priority = *priority;
    
    // Отримання обмеження швидкості
    __u32 *rate_limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (rate_limit)
        metadata.rate_limit = *rate_limit;
    
    // Оновлення лічильника трафіку
    __u64 *counter = bpf_map_lookup_elem(&traffic_counters, &key);
    if (counter)
        *counter += metadata.size;
    
    return metadata;
}

// Основна XDP-функція для QoS і трафік-шейпінгу
SEC("xdp")
int traffic_shaper(struct xdp_md *ctx) {
    // Класифікація пакета
    struct packet_metadata metadata = classify_packet(ctx);
    
    // Якщо пакет не класифіковано, пропускаємо без змін
    if (metadata.dscp == 0 && metadata.priority == 0)
        return XDP_PASS;
    
    // Логіка трафік-шейпінгу на основі пріоритету та обмеження швидкості
    // У реальності тут може бути складніша логіка з використанням часових міток,
    // tokens і т.д. для реалізації алгоритмів token bucket або leaky bucket
    
    // У цьому спрощеному прикладі ми просто пріоритизуємо трафік
    if (metadata.priority >= 6) {
        // Критичний трафік - пропускаємо без затримки
        return XDP_PASS;
    } else if (metadata.priority >= 4) {
        // Середньопріоритетний трафік - пропускаємо,
        // але можна було б застосувати більш складну логіку
        return XDP_PASS;
    } else if (metadata.priority >= 2) {
        // Низькопріоритетний трафік - можна застосувати обмеження
        // В реальній системі тут була б перевірка на перевищення швидкості
        return XDP_PASS;
    } else {
        // Найнижчий пріоритет - можливе обмеження або скидання при перевантаженні
        // Тут також може бути перевірка на перевищення швидкості
        return XDP_PASS;
    }
}

char __license[] SEC("license") = "GPL";