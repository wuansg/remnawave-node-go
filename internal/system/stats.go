package system

import (
	"bufio"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type InterfaceRate struct {
	Interface     string  `json:"interface"`
	RXBytesPerSec float64 `json:"rxBytesPerSec"`
	TXBytesPerSec float64 `json:"txBytesPerSec"`
	RXTotal       uint64  `json:"rxTotal"`
	TXTotal       uint64  `json:"txTotal"`
}

type SystemInfo struct {
	Arch              string   `json:"arch"`
	CPUs              int      `json:"cpus"`
	CPUModel          string   `json:"cpuModel"`
	MemoryTotal       uint64   `json:"memoryTotal"`
	Hostname          string   `json:"hostname"`
	Platform          string   `json:"platform"`
	Release           string   `json:"release"`
	Type              string   `json:"type"`
	Version           string   `json:"version"`
	NetworkInterfaces []string `json:"networkInterfaces"`
}

type SystemStats struct {
	MemoryFree uint64         `json:"memoryFree"`
	MemoryUsed uint64         `json:"memoryUsed"`
	Uptime     float64        `json:"uptime"`
	LoadAvg    [3]float64     `json:"loadAvg"`
	Interface  *InterfaceRate `json:"interface"`
}

type ProcessStats struct {
	NumGoroutine int    `json:"numGoroutine"`
	NumGC        uint32 `json:"numGC"`
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"totalAlloc"`
	Sys          uint64 `json:"sys"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	LiveObjects  uint64 `json:"liveObjects"`
	PauseTotalNs uint64 `json:"pauseTotalNs"`
	Uptime       int64  `json:"uptime"`
}

type Snapshot struct {
	Info  SystemInfo  `json:"info"`
	Stats SystemStats `json:"stats"`
}

type NetworkMonitor struct {
	logger       *slog.Logger
	startedAt    time.Time
	mu           sync.RWMutex
	lastRead     map[string]rawInterfaceStat
	currentRates map[string]InterfaceRate
	defaultIface string
}

type rawInterfaceStat struct {
	rx        uint64
	tx        uint64
	timestamp time.Time
}

func NewNetworkMonitor(logger *slog.Logger) *NetworkMonitor {
	monitor := &NetworkMonitor{
		logger:       logger,
		startedAt:    time.Now(),
		lastRead:     map[string]rawInterfaceStat{},
		currentRates: map[string]InterfaceRate{},
		defaultIface: resolveDefaultInterface(),
	}
	monitor.tick()
	return monitor
}

func (m *NetworkMonitor) Tick() {
	m.tick()
}

func (m *NetworkMonitor) Default() *InterfaceRate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.defaultIface == "" {
		return nil
	}
	rate, ok := m.currentRates[m.defaultIface]
	if !ok {
		return nil
	}
	copied := rate
	return &copied
}

func (m *NetworkMonitor) Uptime() int64 {
	return int64(time.Since(m.startedAt).Seconds())
}

func SystemSnapshot(monitor *NetworkMonitor) Snapshot {
	info := systemInfo()
	free := memoryFree()
	used := uint64(0)
	if info.MemoryTotal > free {
		used = info.MemoryTotal - free
	}
	return Snapshot{
		Info: info,
		Stats: SystemStats{
			MemoryFree: free,
			MemoryUsed: used,
			Uptime:     uptimeSeconds(),
			LoadAvg:    loadAverage(),
			Interface:  monitor.Default(),
		},
	}
}

func CurrentProcessStats(uptime int64) ProcessStats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return ProcessStats{
		NumGoroutine: runtime.NumGoroutine(),
		NumGC:        mem.NumGC,
		Alloc:        mem.Alloc,
		TotalAlloc:   mem.TotalAlloc,
		Sys:          mem.Sys,
		Mallocs:      mem.Mallocs,
		Frees:        mem.Frees,
		LiveObjects:  mem.Mallocs - mem.Frees,
		PauseTotalNs: mem.PauseTotalNs,
		Uptime:       uptime,
	}
}

func (m *NetworkMonitor) tick() {
	current := readProcNetDev()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	for iface, stat := range current {
		if previous, ok := m.lastRead[iface]; ok {
			elapsed := stat.timestamp.Sub(previous.timestamp).Seconds()
			if elapsed > 0 {
				m.currentRates[iface] = InterfaceRate{
					Interface:     iface,
					RXBytesPerSec: float64(stat.rx-previous.rx) / elapsed,
					TXBytesPerSec: float64(stat.tx-previous.tx) / elapsed,
					RXTotal:       stat.rx,
					TXTotal:       stat.tx,
				}
			}
		}
	}
	m.lastRead = current
	if m.defaultIface == "" {
		m.defaultIface = resolveDefaultInterface()
	}
	if _, ok := current[m.defaultIface]; !ok && len(current) > 0 {
		for iface := range current {
			m.defaultIface = iface
			break
		}
	}
	_ = now
}

func systemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	cpus := runtime.NumCPU()
	cpuModel := "unknown"
	if model := cpuModelFromCPUInfo(); model != "" {
		cpuModel = model
	}
	return SystemInfo{
		Arch:              runtime.GOARCH,
		CPUs:              cpus,
		CPUModel:          cpuModel,
		MemoryTotal:       memoryTotal(),
		Hostname:          hostname,
		Platform:          runtime.GOOS,
		Release:           kernelRelease(),
		Type:              runtime.GOOS,
		Version:           runtime.Version(),
		NetworkInterfaces: networkInterfaceNames(),
	}
}

func readProcNetDev() map[string]rawInterfaceStat {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return map[string]rawInterfaceStat{}
	}
	defer file.Close()

	out := map[string]rawInterfaceStat{}
	scanner := bufio.NewScanner(file)
	index := 0
	for scanner.Scan() {
		index++
		if index <= 2 {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		iface := strings.TrimSuffix(fields[0], ":")
		rx, _ := strconv.ParseUint(fields[1], 10, 64)
		tx, _ := strconv.ParseUint(fields[9], 10, 64)
		out[iface] = rawInterfaceStat{rx: rx, tx: tx, timestamp: time.Now()}
	}
	return out
}

func resolveDefaultInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func networkInterfaceNames() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Name())
	}
	sortStrings(out)
	return out
}

func cpuModelFromCPUInfo() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func kernelRelease() string {
	content, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func loadAverage() [3]float64 {
	var out [3]float64
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out
	}
	fields := strings.Fields(string(content))
	for index := 0; index < 3 && index < len(fields); index++ {
		value, _ := strconv.ParseFloat(fields[index], 64)
		out[index] = value
	}
	return out
}

func uptimeSeconds() float64 {
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func memoryTotal() uint64 {
	return memInfoValue("MemTotal")
}

func memoryFree() uint64 {
	return memInfoValue("MemAvailable")
}

func memInfoValue(key string) uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.TrimSuffix(fields[0], ":") != key {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		return value * 1024
	}
	return 0
}

func sortStrings(values []string) {
	if len(values) < 2 {
		return
	}
	for i := 0; i < len(values)-1; i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
