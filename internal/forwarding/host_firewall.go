package forwarding

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	hostFilterTable       = "filter"
	hostFilterParentChain = "DOCKER-USER"
	hostFilterChain       = "REMNANODE_FORWARD"
	hostJumpComment       = "remnanode-forward-host-jump"
)

func (s *Service) reconcileHostFirewall(ctx context.Context, cfg Config, ingress string, routes map[string]string) error {
	managedChainExists := nftChainExists(ctx, hostFilterTable, hostFilterChain)
	enabled := cfg.Enabled && enabledRuleCount(cfg) > 0

	if !enabled || firewallForwardPolicy(ctx) != "drop" {
		if !managedChainExists {
			return nil
		}
		return runHostFirewallScript(ctx, fmt.Sprintf("flush chain ip %s %s\n", hostFilterTable, hostFilterChain))
	}

	if !nftChainExists(ctx, hostFilterTable, hostFilterParentChain) {
		return errors.New("host FORWARD policy is drop but Docker DOCKER-USER chain is unavailable")
	}
	parent, err := exec.CommandContext(ctx, "nft", "list", "chain", "ip", hostFilterTable, hostFilterParentChain).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect Docker DOCKER-USER chain: %w (%s)", err, strings.TrimSpace(string(parent)))
	}
	jumpExists := strings.Contains(string(parent), hostJumpComment)
	script := renderHostFirewallRules(cfg, ingress, routes, !managedChainExists, !jumpExists)
	return runHostFirewallScript(ctx, script)
}

func nftChainExists(ctx context.Context, table, chain string) bool {
	return exec.CommandContext(ctx, "nft", "list", "chain", "ip", table, chain).Run() == nil
}

func runHostFirewallScript(ctx context.Context, script string) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	if err := runNFTScript(ctx, script, true); err != nil {
		return fmt.Errorf("validate managed host firewall: %w", err)
	}
	if err := runNFTScript(ctx, script, false); err != nil {
		return fmt.Errorf("update managed host firewall: %w", err)
	}
	return nil
}

func renderHostFirewallRules(cfg Config, ingress string, routes map[string]string, createChain, createJump bool) string {
	var b strings.Builder
	if createChain {
		fmt.Fprintf(&b, "add chain ip %s %s\n", hostFilterTable, hostFilterChain)
	} else {
		fmt.Fprintf(&b, "flush chain ip %s %s\n", hostFilterTable, hostFilterChain)
	}
	if createJump {
		fmt.Fprintf(&b, "insert rule ip %s %s jump %s comment %q\n", hostFilterTable, hostFilterParentChain, hostFilterChain, hostJumpComment)
	}
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		egress := routes[rule.TargetAddress]
		for _, protocol := range expandedProtocols(rule.Protocol) {
			fmt.Fprintf(&b,
				"add rule ip %s %s iifname %q oifname %q ip daddr %s %s dport %d ct original proto-dst %d ct state new,related,established counter accept comment %q\n",
				hostFilterTable, hostFilterChain, ingress, egress, rule.TargetAddress, protocol, rule.TargetPort, rule.ListenPort,
				hostAllowComment(rule.ID, protocol, "up"),
			)
			fmt.Fprintf(&b,
				"add rule ip %s %s iifname %q oifname %q ip saddr %s %s sport %d ct original proto-dst %d ct state related,established counter accept comment %q\n",
				hostFilterTable, hostFilterChain, egress, ingress, rule.TargetAddress, protocol, rule.TargetPort, rule.ListenPort,
				hostAllowComment(rule.ID, protocol, "down"),
			)
		}
	}
	return b.String()
}
