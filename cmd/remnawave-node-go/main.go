package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/httpapi"
	nodeapp "github.com/remnawave/remnawave-node-go/internal/node"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/system"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	runtimeState := state.New(cfg.NodeVersion)
	networkMonitor := system.NewNetworkMonitor(logger)
	supervisorClient := supervisor.New(cfg.SupervisordSocket, cfg.SupervisordUser, cfg.SupervisordPass)
	manager, err := nodeapp.NewManager(cfg, runtimeState, logger, supervisorClient, networkMonitor)
	if err != nil {
		logger.Error("failed to initialize core API clients", "error", err)
		os.Exit(1)
	}
	defer manager.Close()
	manager.SyncEnvironment(context.Background())

	server, err := httpapi.NewServer(cfg, manager, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 2)
	go func() { errs <- server.ListenAndServeTLS() }()
	go func() { errs <- server.ListenAndServeInternal() }()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	usageTicker := time.NewTicker(time.Duration(cfg.UsageSnapshotInterval) * time.Second)
	defer usageTicker.Stop()
	forwardingDNSTicker := time.NewTicker(time.Minute)
	defer forwardingDNSTicker.Stop()

	go func() {
		for range ticker.C {
			networkMonitor.Tick()
			manager.SyncProcessStatus(context.Background())
		}
	}()
	go func() {
		for range usageTicker.C {
			manager.CaptureUsageSnapshot(context.Background())
		}
	}()
	go func() {
		for range forwardingDNSTicker.C {
			manager.RefreshForwardingDNS(context.Background())
		}
	}()

	logger.Info("remnawave node go started", "port", cfg.NodePort, "internal_socket", cfg.InternalSocketPath, "version", cfg.NodeVersion)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, httpapi.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "error", err)
		os.Exit(1)
	}
}
