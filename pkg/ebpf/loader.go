package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// XDPProgram представляє завантажену eBPF/XDP програму
type XDPProgram struct {
	Program     *ebpf.Program
	Link        link.Link
	IPStats     *ebpf.Map
	RateLimit   *ebpf.Map
	BlockedIPs  *ebpf.Map
	Interface   string
}

// IPStats представляє статистику за IP-адресою
type IPStats struct {
	Packets  uint64
	Bytes    uint64
	LastSeen uint64
}

// CompileXDPFilter компілює eBPF програму
func CompileXDPFilter(sourcePath, outputPath string) error {
	// Компіляція XDP програми за допомогою clang
	cmd := exec.Command("clang",
		"-O2",                   // Оптимізація
		"-target", "bpf",        // Цільова платформа BPF
		"-c", sourcePath,        // Вхідний файл
		"-o", outputPath,        // Вихідний файл
		"-I", "/usr/include",    // Включення заголовків
		"-I", "/usr/include/linux",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error compiling BPF program: %v, stderr: %s", err, stderr.String())
	}

	return nil
}

// LoadXDPProgram завантажує скомпільовану eBPF програму
func LoadXDPProgram(objectPath, interfaceName string, rateLimit uint32) (*XDPProgram, error) {
	// Завантаження eBPF програми
	var objs struct {
		XdpFilterProg *ebpf.Program `ebpf:"xdp_filter_prog"`
		IPStats       *ebpf.Map     `ebpf:"ip_stats"`
		RateLimit     *ebpf.Map     `ebpf:"rate_limit"`
		BlockedIPs    *ebpf.Map     `ebpf:"blocked_ips"`
	}

	// Завантаження eBPF об'єкта
	if err := ebpf.LoadFile(objectPath, &objs); err != nil {
		return nil, fmt.Errorf("error loading BPF objects: %v", err)
	}

	// Отримання інтерфейсу
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("error getting interface %s: %v", interfaceName, err)
	}

	// Прикріплення XDP програми до інтерфейсу
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterProg,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("error attaching XDP program: %v", err)
	}

	// Встановлення порогу швидкості
	var key uint32 = 0
	if err := objs.RateLimit.Update(&key, &rateLimit, ebpf.UpdateAny); err != nil {
		l.Close()
		return nil, fmt.Errorf("error setting rate limit: %v", err)
	}

	return &XDPProgram{
		Program:    objs.XdpFilterProg,
		Link:       l,
		IPStats:    objs.IPStats,
		RateLimit:  objs.RateLimit,
		BlockedIPs: objs.BlockedIPs,
		Interface:  interfaceName,
	}, nil
}

// Close закриває eBPF програму і звільняє ресурси
func (p *XDPProgram) Close() error {
	if p.Link != nil {
		return p.Link.Close()
	}
	return nil
}

// GetIPStats отримує статистику за всіма IP
func (p *XDPProgram) GetIPStats() (map[string]IPStats, error) {
	result := make(map[string]IPStats)
	var key uint32
	var value IPStats

	// Ітерація по всім записам у карті
	iter := p.IPStats.Iterate()
	for iter.Next(&key, &value) {
		ip := convertIPv4(key)
		result[ip] = value
	}

	return result, nil
}

// BlockIP блокує IP-адресу
func (p *XDPProgram) BlockIP(ipAddress string) error {
	ip := net.ParseIP(ipAddress).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipAddress)
	}

	key := binary.LittleEndian.Uint32(ip)
	var value uint8 = 1 // 1 = заблоковано

	return p.BlockedIPs.Update(&key, &value, ebpf.UpdateAny)
}

// UnblockIP розблоковує IP-адресу
func (p *XDPProgram) UnblockIP(ipAddress string) error {
	ip := net.ParseIP(ipAddress).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipAddress)
	}

	key := binary.LittleEndian.Uint32(ip)
	return p.BlockedIPs.Delete(&key)
}

// GetBlockedIPs отримує список заблокованих IP
func (p *XDPProgram) GetBlockedIPs() ([]string, error) {
	var blockedIPs []string
	var key uint32
	var value uint8

	// Ітерація по всім записам у карті
	iter := p.BlockedIPs.Iterate()
	for iter.Next(&key, &value) {
		if value == 1 {
			ip := convertIPv4(key)
			blockedIPs = append(blockedIPs, ip)
		}
	}

	return blockedIPs, nil
}

// UpdateRateLimit оновлює поріг швидкості
func (p *XDPProgram) UpdateRateLimit(rateLimit uint32) error {
	var key uint32 = 0
	return p.RateLimit.Update(&key, &rateLimit, ebpf.UpdateAny)
}

// GetRateLimit отримує поточний поріг швидкості
func (p *XDPProgram) GetRateLimit() (uint32, error) {
	var key uint32 = 0
	var value uint32

	if err := p.RateLimit.Lookup(&key, &value); err != nil {
		return 0, err
	}

	return value, nil
}

// convertIPv4 конвертує uint32 в IPv4 адресу
func convertIPv4(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipInt)
	return ip.String()
}