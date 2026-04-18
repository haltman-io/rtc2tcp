package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rtc2tcp/internal/config"
	"rtc2tcp/internal/rendezvous"
)

func main() {
	build := config.CurrentBuild()

	var (
		listen  = flag.String("listen", ":8080", "HTTP listen address")
		version = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		log.Printf("rtc2tcp-broker version=%s commit=%s default-broker=%s", build.Version, build.Commit, build.DefaultBrokerURL)
		return
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	broker := rendezvous.NewBroker(logger)

	server := &http.Server{
		Addr:              *listen,
		Handler:           broker.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Print(rendezvous.FormatEvent("listening",
			"addr", *listen,
			"version", build.Version,
			"commit", build.Commit,
		))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal(rendezvous.FormatEvent("listen_failed", "err", err.Error()))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Print(rendezvous.FormatEvent("http_shutdown_failed", "err", err.Error()))
	}
	if err := broker.Shutdown(ctx); err != nil {
		logger.Print(rendezvous.FormatEvent("shutdown_failed", "err", err.Error()))
	}
}
