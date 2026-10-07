package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 256*1024 {
		return 0, errors.New("tool output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nice", append([]string{"-n", "10", name}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	output := &limitedOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	return output.Bytes(), nil
}

var cpuPattern = regexp.MustCompile(`events per second:\s*([0-9.]+)`)
var memoryPattern = regexp.MustCompile(`\(([0-9.]+) MiB/sec\)`)

func (r *Runner) hardware(ctx context.Context, req Request, item string) Item {
	result := Item{Name: item, Status: "COMPLETED", Metrics: map[string]any{"architecture": runtime.GOARCH, "threads": req.Threads, "durationLimitSeconds": req.Seconds}}
	result.Metrics["logicalCPUs"] = runtime.NumCPU()
	result.Metrics["environment"] = environment()
	if reason := resourcePressure(item, req.Threads); reason != "" {
		result.Status = "SKIPPED"
		result.Message = reason
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	version, _ := command(ctx, "sysbench", "--version")
	result.Metrics["toolVersion"] = strings.TrimSpace(string(version))
	switch item {
	case "cpu", "memory":
		if item == "memory" {
			result.Metrics["bufferBytesPerThread"] = 1 << 20
		}
		args := []string{item, "--time=" + strconv.Itoa(req.Seconds), "--threads=" + strconv.Itoa(req.Threads)}
		if item == "cpu" {
			args = append(args, "--cpu-max-prime=20000")
		} else {
			args = append(args, "--memory-block-size=1M", "--memory-total-size=4G", "--memory-oper=write", "--memory-scope=local")
		}
		args = append(args, "run")
		data, err := command(ctx, "sysbench", args...)
		if err != nil {
			result.Status = "FAILED"
			result.Message = err.Error()
			return result
		}
		pattern := cpuPattern
		key := "eventsPerSecond"
		if item == "memory" {
			pattern = memoryPattern
			key = "mibPerSecond"
		}
		match := pattern.FindSubmatch(data)
		if len(match) != 2 {
			result.Status = "FAILED"
			result.Message = "Unexpected sysbench output"
			return result
		}
		v, _ := strconv.ParseFloat(string(match[1]), 64)
		result.Metrics[key] = v
		if item == "cpu" {
			result.Metrics["algorithm"] = "sysbench prime search, max prime 20000"
		} else {
			result.Metrics["algorithm"] = "sysbench sequential 1 MiB writes; maximum 4 GiB total"
		}
	case "disk":
		var stats syscall.Statfs_t
		if err := syscall.Statfs(r.dir, &stats); err != nil || stats.Bavail*uint64(stats.Bsize) < 1<<30 {
			result.Status = "SKIPPED"
			result.Message = "Disk test requires at least 1 GiB available"
			return result
		}
		dir, err := os.MkdirTemp(r.dir, "disk-benchmark-")
		if err != nil {
			result.Status = "FAILED"
			result.Message = err.Error()
			return result
		}
		defer os.RemoveAll(dir)
		filename := filepath.Join(dir, "test.bin")
		// Pre-create only a sparse, sized file. Disable fio's file creation and
		// preallocation so hidden setup writes cannot exceed the I/O budget.
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			err = file.Truncate(64 << 20)
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			result.Status = "FAILED"
			result.Message = "Could not create isolated test file"
			return result
		}
		version, _ = command(ctx, "fio", "--version")
		result.Metrics["toolVersion"] = strings.TrimSpace(string(version))
		result.Metrics["directory"] = r.dir
		result.Metrics["fileBytes"] = 64 << 20
		result.Metrics["writeBudgetBytes"] = 128 << 20
		for _, rw := range []string{"write", "read", "randwrite", "randread"} {
			if ctx.Err() != nil {
				result.Status = "FAILED"
				result.Message = "Disk test cancelled"
				return result
			}
			block := "1m"
			if strings.HasPrefix(rw, "rand") {
				block = "4k"
			}
			data, err := command(ctx, "fio", "--name="+rw, "--filename="+filename, "--rw="+rw, "--bs="+block, "--size=64m", "--io_size=64m", "--direct=1", "--ioengine=psync", "--iodepth=1", "--numjobs=1", "--allow_file_create=0", "--fallocate=none", "--runtime="+strconv.Itoa(req.Seconds), "--output-format=json", "--group_reporting=1", "--unlink=0")
			if err != nil {
				result.Status = "FAILED"
				result.Message = err.Error()
				return result
			}
			var output struct {
				Jobs []struct {
					Error int            `json:"error"`
					Read  map[string]any `json:"read"`
					Write map[string]any `json:"write"`
				} `json:"jobs"`
			}
			if err = json.Unmarshal(data, &output); err != nil || len(output.Jobs) != 1 || output.Jobs[0].Error != 0 {
				result.Status = "FAILED"
				result.Message = "fio failed; direct I/O may be unsupported"
				return result
			}
			metrics := output.Jobs[0].Read
			if strings.Contains(rw, "write") {
				metrics = output.Jobs[0].Write
			}
			result.Metrics[rw] = map[string]any{"bytesPerSecond": metrics["bw_bytes"], "iops": metrics["iops"], "latencyNs": metrics["lat_ns"], "bytes": metrics["io_bytes"], "runtimeMs": metrics["runtime"], "blockSize": block, "directIO": true, "queueDepth": 1}
			if n, ok := metrics["io_bytes"].(float64); rw == "write" && (!ok || n < 64<<20) {
				result.Status = "FAILED"
				result.Message = "Initial write timed out; remaining tests skipped to avoid measuring sparse-file reads. Increase phase duration."
				return result
			}
		}
	}
	return result
}

// Record the execution environment so container limits and current system load
// are not mistaken for the capabilities of an otherwise idle physical host.
func environment() map[string]any {
	info := map[string]any{}
	for key, path := range map[string]string{
		"loadAverage":      "/proc/loadavg",
		"memoryInfo":       "/proc/meminfo",
		"cpuQuotaV2":       "/sys/fs/cgroup/cpu.max",
		"memoryLimitV2":    "/sys/fs/cgroup/memory.max",
		"memoryCurrentV2":  "/sys/fs/cgroup/memory.current",
		"cpuPressureV2":    "/sys/fs/cgroup/cpu.pressure",
		"memoryPressureV2": "/sys/fs/cgroup/memory.pressure",
		"ioPressureV2":     "/sys/fs/cgroup/io.pressure",
		"cpuQuotaV1":       "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
		"cpuPeriodV1":      "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
		"memoryLimitV1":    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		if data, err := os.ReadFile(path); err == nil && len(data) < 16*1024 {
			info[key] = strings.TrimSpace(string(data))
		}
	}
	return info
}

func pressureExceeded(data []byte, limit float64) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "avg10=") {
				value, err := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
				return err == nil && value > limit
			}
		}
	}
	return false
}

func resourcePressure(item string, threads int) string {
	resource := map[string]string{"cpu": "cpu", "memory": "memory", "disk": "io"}[item]
	limit := 25.0
	if item == "memory" {
		limit = 5
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/" + resource + ".pressure"); err == nil && pressureExceeded(data, limit) {
		return "Container resource pressure is high; retry when the node is less busy"
	}
	if item == "memory" {
		limitBytes, errLimit := os.ReadFile("/sys/fs/cgroup/memory.max")
		currentBytes, errCurrent := os.ReadFile("/sys/fs/cgroup/memory.current")
		limit, err := strconv.ParseUint(strings.TrimSpace(string(limitBytes)), 10, 64)
		current, currentErr := strconv.ParseUint(strings.TrimSpace(string(currentBytes)), 10, 64)
		reserve := uint64(16+threads) << 20
		if errLimit == nil && errCurrent == nil && err == nil && currentErr == nil && (current >= limit || limit-current < reserve) {
			return "Container has insufficient memory headroom for the bounded test"
		}
	}
	return ""
}
