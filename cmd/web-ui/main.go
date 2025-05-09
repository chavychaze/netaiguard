package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	listenAddr = flag.String("listen", ":8082", "Address to listen for HTTP requests")
	staticDir  = flag.String("static", "pkg/web", "Directory with static files")
)

func main() {
	flag.Parse()

	log.Printf("NetAIGuard Web UI starting...")
	log.Printf("Static files directory: %s", *staticDir)
	log.Printf("Listen address: %s", *listenAddr)

	// Переконайтеся, що директорія існує
	if _, err := os.Stat(*staticDir); os.IsNotExist(err) {
		log.Fatalf("Static directory does not exist: %s", *staticDir)
	}

	// Створення HTTP сервера для статичних файлів
	http.Handle("/", http.FileServer(http.Dir(*staticDir)))

	// Запуск HTTP сервера в окремій горутині
	server := &http.Server{
		Addr: *listenAddr,
	}

	go func() {
		log.Printf("Starting Web UI server on %s", *listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Обробка сигналів для коректного завершення
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	log.Println("Shutting down Web UI server...")

	log.Println("Web UI server stopped")
}