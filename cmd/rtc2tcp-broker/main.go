package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haltman-io/rtc2tcp/internal/banner"
	"github.com/haltman-io/rtc2tcp/internal/config"
	"github.com/haltman-io/rtc2tcp/internal/rendezvous"
)

const toolName = "rtc2tcp-broker"

func main() {
	build := config.CurrentBuild()

	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		listen             = fs.String("listen", ":8080", "HTTP listen address")
		trustedProxies     = fs.String("trusted-proxies", "", "comma-separated list of IPs or CIDRs whose X-Forwarded-For / proxy headers are honoured (e.g. \"127.0.0.1,10.0.0.0/8\"). Empty disables forwarded-for parsing.")
		trustedProxyHeader = fs.String("trusted-proxy-header", "X-Forwarded-For", "HTTP header consulted for the real client IP when the request arrives from a trusted proxy. Typical values: X-Forwarded-For, X-Real-IP, CF-Connecting-IP.")
		ratePerMinute      = fs.Int("rate-limit-per-minute", rendezvous.DefaultUpgradeRatePerMinute, "per-client-IP WebSocket upgrade rate (requests/minute)")
		rateBurst          = fs.Int("rate-limit-burst", rendezvous.DefaultUpgradeBurst, "per-client-IP burst size for WebSocket upgrades")
		versionOnly        = fs.Bool("version", false, "print version and exit")
		quiet              = fs.Bool("quiet", false, "suppress banner")
		silent             = fs.Bool("silent", false, "alias for --quiet")
		noColor            = fs.Bool("no-color", false, "disable ANSI colours")
	)
	fs.BoolVar(versionOnly, "V", false, "alias for --version")
	fs.BoolVar(quiet, "q", false, "alias for --quiet")

	fs.Usage = func() {
		banner.Print(os.Stderr, banner.Options{
			Build: build,
			Tool:  toolName,
		})
		fmt.Fprintln(os.Stderr, "Usage: "+toolName+" [flags]")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *versionOnly {
		fmt.Fprintln(os.Stdout, banner.VersionLine(toolName, build))
		return
	}

	banner.Print(os.Stderr, banner.Options{
		Quiet:   *quiet || *silent,
		NoColor: *noColor,
		Build:   build,
		Tool:    toolName,
	})

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	opts := rendezvous.Options{
		TrustedProxyHeader: *trustedProxyHeader,
		RatePerMinute:      *ratePerMinute,
		RateBurst:          *rateBurst,
	}
	if *trustedProxies != "" {
		opts.TrustedProxies = []string{*trustedProxies}
	}

	broker, err := rendezvous.NewBrokerWithOptions(logger, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "broker: invalid configuration:", err)
		os.Exit(2)
	}

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
			"trusted_proxies", *trustedProxies,
			"trusted_proxy_header", *trustedProxyHeader,
			"rate_per_minute", *ratePerMinute,
			"rate_burst", *rateBurst,
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
