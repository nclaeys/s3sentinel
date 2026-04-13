package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dataminded/s3-fine-grained-access/internal/auth"
	"github.com/dataminded/s3-fine-grained-access/internal/config"
	"github.com/dataminded/s3-fine-grained-access/internal/observability"
	"github.com/dataminded/s3-fine-grained-access/internal/opa"
	"github.com/dataminded/s3-fine-grained-access/internal/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// ── Observability ────────────────────────────────────────────────────────
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	metrics := observability.NewMetrics(registry)

	// ── Core dependencies ────────────────────────────────────────────────────
	jwtValidator, err := auth.NewJWTValidator(cfg.JWKSEndpoint, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		logger.Error("failed to initialise JWT validator", "error", err)
		os.Exit(1)
	}

	opaClient := opa.NewClient(cfg.OPAEndpoint)

	// ── S3 proxy server ──────────────────────────────────────────────────────
	handler := proxy.NewHandler(proxy.Config{
		BackendEndpoint: cfg.BackendEndpoint,
		BackendRegion:   cfg.BackendRegion,
		BackendKey:      cfg.BackendKey,
		BackendSecret:   cfg.BackendSecret,
		ProxyHost:       cfg.ProxyHost,
		JWTValidator:    jwtValidator,
		OPAClient:       opaClient,
		Metrics:         metrics,
		Logger:          logger,
	})

	proxySrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
		// Generous read timeout; write timeout disabled to allow large streaming
		// downloads and uploads to complete without hitting a deadline.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	// ── Admin server (/healthz, /readyz, /metrics) ───────────────────────────
	adminMux := http.NewServeMux()
	adminMux.Handle("/healthz", observability.NewHealthHandler())
	adminMux.Handle("/readyz", observability.NewReadyHandler(map[string]observability.Checker{
		"opa":  opaClient,
		"jwks": jwtValidator,
	}))
	adminMux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	adminSrv := &http.Server{
		Addr:         cfg.AdminAddr,
		Handler:      adminMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// ── Startup ──────────────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if cfg.TLSEnabled() {
			logger.Info("s3 proxy starting",
				"addr", cfg.ListenAddr,
				"backend", cfg.BackendEndpoint,
				"tls", true,
				"cert", cfg.TLSCertFile,
			)
			if err := proxySrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("proxy server error", "error", err)
				os.Exit(1)
			}
		} else {
			logger.Info("s3 proxy starting",
				"addr", cfg.ListenAddr,
				"backend", cfg.BackendEndpoint,
				"tls", false,
			)
			if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("proxy server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	go func() {
		logger.Info("admin server starting", "addr", cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server error", "error", err)
			os.Exit(1)
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	<-ctx.Done()
	logger.Info("shutting down gracefully")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown error", "error", err)
	}
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin shutdown error", "error", err)
	}
}
