package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yourusername/netaiguard/pkg/ebpf"
)

var (
	interfaceName = flag.String("interface", "eth0", "Interface to attach XDP program")
	sourceFile    = flag.String("source", "pkg/ebpf/xdp_filter.c", "eBPF program source file")
	outputFile    = flag.String("output", "/tmp/xdp_filter.o", "Compiled eBPF program output file")
	rateLimit     = flag.Uint("rate-limit", 100, "Rate limit in packets per second")
	aiServerURL   = flag.String("ai-server", "http://localhost:5000", "URL of AI analysis server")
	listenAddr    = flag.String("listen", ":8080", "Address to listen for API requests")
)

type IPStatsMap map[string]IPStats

type IPStats struct {
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	LastSeen uint64 `json:"last_seen"`
}

type AIAnalysisRequest struct {
	IPStats       map[string]IPStats `json:"ip_stats"`
	WindowSeconds int                `json:"window_seconds"`
}

type AIAnalysisResponse struct {
	Status            string              `json:"status"`
	Message           string              `json:"message"`
	Timestamp         string              `json:"timestamp"`
	TotalIPs          int                 `json:"total_ips"`
	AnomaliesCount    int                 `json:"anomalies_count"`
	TopIPsByTraffic   []map[string]interface{} `json:"top_ips_by_traffic"`
	TopIPsByPackets   []map[string]interface{} `json:"top_ips_by_packets"`
	Recommendations   []Recommendation     `json:"recommendations"`
}

type Recommendation struct {
	IP         string                 `json:"ip"`
	Action     string                 `json:"action"`
	Reason     string                 `json:"reason"`
	Metrics    map[string]float64     `json:"metrics"`
	Confidence float64                `json:"confidence"`
}

func main() {
	flag.Parse()

	log.Printf("NetAIGuard eBPF Agent starting...")
	log.Printf("Interface: %s", *interfaceName)
	log.Printf("Rate limit: %d packets/sec", *rateLimit)
	log.Printf("AI Server: %s", *aiServerURL)

	// Компіляція eBPF програми
	log.Printf("Compiling eBPF program: %s -> %s", *sourceFile, *outputFile)
	if err := ebpf.CompileXDPFilter(*sourceFile, *outputFile); err != nil {
		log.Fatalf("Failed to compile eBPF program: %v", err)
	}

	// Завантаження eBPF програми
	log.Printf("Loading eBPF program to interface %s", *interfaceName)
	program, err := ebpf.LoadXDPProgram(*outputFile, *interfaceName, uint32(*rateLimit))
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer program.Close()

	// Обробники сигналів для коректного завершення
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v", sig)
		cancel()
	}()

	// Запуск HTTP API
	api := setupAPI(program)
	server := &http.Server{
		Addr:    *listenAddr,
		Handler: api,
	}

	// Запуск сервера в окремій горутині
	go func() {
		log.Printf("Starting API server on %s", *listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Запуск періодичного аналізу трафіку
	go runPeriodicAnalysis(ctx, program)

	// Очікування завершення контексту
	<-ctx.Done()

	// Коректне завершення сервера
	log.Printf("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Printf("NetAIGuard eBPF Agent stopped")
}

func setupAPI(program *ebpf.XDPProgram) http.Handler {
	mux := http.NewServeMux()

	// Перевірка стану
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"timestamp": time.Now(),
		})
	})

	// Отримання статистики
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := program.GetIPStats()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get stats: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// Отримання заблокованих IP
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		blocked, err := program.GetBlockedIPs()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get blocked IPs: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"blocked_ips": blocked,
			"count":       len(blocked),
		})
	})

	// Блокування IP
	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if data.IP == "" {
			http.Error(w, "IP address is required", http.StatusBadRequest)
			return
		}

		if err := program.BlockIP(data.IP); err != nil {
			http.Error(w, fmt.Sprintf("Failed to block IP: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Blocked IP: %s", data.IP)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("IP %s blocked successfully", data.IP),
		})
	})

	// Розблокування IP
	mux.HandleFunc("/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if data.IP == "" {
			http.Error(w, "IP address is required", http.StatusBadRequest)
			return
		}

		if err := program.UnblockIP(data.IP); err != nil {
			http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Unblocked IP: %s", data.IP)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("IP %s unblocked successfully", data.IP),
		})
	})

	// Оновлення порогу швидкості
	mux.HandleFunc("/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			RateLimit uint32 `json:"rate_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if data.RateLimit == 0 {
			http.Error(w, "Rate limit must be greater than 0", http.StatusBadRequest)
			return
		}

		if err := program.UpdateRateLimit(data.RateLimit); err != nil {
			http.Error(w, fmt.Sprintf("Failed to update rate limit: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Updated rate limit to %d packets/sec", data.RateLimit)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "success",
			"message":    "Rate limit updated successfully",
			"rate_limit": data.RateLimit,
		})
	})

	// Ручний запуск аналізу
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		result, err := performAnalysis(program)
		if err != nil {
			http.Error(w, fmt.Sprintf("Analysis error: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	return mux
}

func runPeriodicAnalysis(ctx context.Context, program *ebpf.XDPProgram) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("Running periodic traffic analysis...")
			
			result, err := performAnalysis(program)
			if err != nil {
				log.Printf("Failed to perform analysis: %v", err)
				continue
			}

			applyRecommendations(program, result)
		}
	}
}

func performAnalysis(program *ebpf.XDPProgram) (*AIAnalysisResponse, error) {
	// Отримання статистики трафіку
	stats, err := program.GetIPStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get traffic stats: %v", err)
	}

	if len(stats) == 0 {
		log.Println("No traffic data available for analysis")
		return nil, nil
	}

	// Підготовка запиту до AI сервера
	request := AIAnalysisRequest{
		IPStats:       stats,
		WindowSeconds: 10,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Відправка запиту до AI сервера
	resp, err := http.Post(
		fmt.Sprintf("%s/analyze", strings.TrimRight(*aiServerURL, "/")),
		"application/json",
		strings.NewReader(string(jsonData)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to AI server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI server returned non-OK status: %d", resp.StatusCode)
	}

	// Розбір відповіді
	var result AIAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode AI server response: %v", err)
	}

	log.Printf("Analysis completed: %d IPs analyzed, %d anomalies detected",
		result.TotalIPs, result.AnomaliesCount)

	return &result, nil
}

func applyRecommendations(program *ebpf.XDPProgram, result *AIAnalysisResponse) {
	if result == nil || len(result.Recommendations) == 0 {
		return
	}

	// Отримання поточних заблокованих IP
	blockedIPs, err := program.GetBlockedIPs()
	if err != nil {
		log.Printf("Failed to get blocked IPs: %v", err)
		return
	}

	// Створення мапи для швидкого пошуку
	blockedMap := make(map[string]bool)
	for _, ip := range blockedIPs {
		blockedMap[ip] = true
	}

	// Обробка рекомендацій
	for _, rec := range result.Recommendations {
		switch rec.Action {
		case "block":
			// Якщо IP ще не заблоковано і є висока впевненість
			if !blockedMap[rec.IP] && rec.Confidence >= 0.8 {
				if err := program.BlockIP(rec.IP); err != nil {
					log.Printf("Failed to block IP %s: %v", rec.IP, err)
					continue
				}
				log.Printf("Automatically blocked IP %s (confidence: %.2f): %s",
					rec.IP, rec.Confidence, rec.Reason)
			}
		case "rate_limit":
			// Для спрощення, ми не реалізуємо індивідуальне обмеження швидкості
			log.Printf("Rate limit recommendation for IP %s (confidence: %.2f): %s",
				rec.IP, rec.Confidence, rec.Reason)
		case "monitor":
			log.Printf("Monitoring recommendation for IP %s (confidence: %.2f): %s",
				rec.IP, rec.Confidence, rec.Reason)
		}
	}
}