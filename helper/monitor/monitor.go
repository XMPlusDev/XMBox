package monitor

import (
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/xmplusdev/xmbox/api"
)

var (
	prevNetIn  uint64
	prevNetOut uint64
	prevTime   time.Time
)

func init() {
	counters, _ := net.IOCounters(true)
	for _, c := range counters {
		if isSkippedInterface(c.Name) {
			continue
		}
		prevNetIn += c.BytesRecv
		prevNetOut += c.BytesSent
	}
	prevTime = time.Now()
}

// Collect gathers current machine health metrics.
func Collect() (*api.ServerStatus, error) {
	s := &api.ServerStatus{}

	// Uptime
	if u, err := host.Uptime(); err == nil {
		s.Uptime = u
	}

	// CPU percent (non-blocking; samples over 500 ms)
	if cpuPct, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(cpuPct) > 0 {
		s.CPU = cpuPct[0]
	}

	// Load averages
	if avg, err := load.Avg(); err == nil {
		s.Load1 = avg.Load1
		s.Load5 = avg.Load5
		s.Load15 = avg.Load15
	}

	// Memory
	if vm, err := mem.VirtualMemory(); err == nil {
		s.MemUsed = vm.Used
		s.MemTotal = vm.Total
	}

	// Swap
	if sm, err := mem.SwapMemory(); err == nil {
		s.SwapUsed = sm.Used
		s.SwapTotal = sm.Total
	}

	// Disk (root filesystem)
	if du, err := disk.Usage("/"); err == nil {
		s.DiskUsed = du.Used
		s.DiskTotal = du.Total
	}

	// Network speed (bytes/s since last call)
	s.NetIn, s.NetOut = collectNetSpeed()

	return s, nil
}

func collectNetSpeed() (inSpeed, outSpeed float64) {
	counters, err := net.IOCounters(true)
	if err != nil {
		return 0, 0
	}

	var totalIn, totalOut uint64
	for _, c := range counters {
		if isSkippedInterface(c.Name) {
			continue
		}
		totalIn += c.BytesRecv
		totalOut += c.BytesSent
	}

	now := time.Now()
	elapsed := now.Sub(prevTime).Seconds()
	if elapsed > 0 {
		if totalIn >= prevNetIn {
			inSpeed = float64(totalIn-prevNetIn) / elapsed
		}
		if totalOut >= prevNetOut {
			outSpeed = float64(totalOut-prevNetOut) / elapsed
		}
	}

	prevNetIn = totalIn
	prevNetOut = totalOut
	prevTime = now
	return inSpeed, outSpeed
}

func isSkippedInterface(name string) bool {
	skip := []string{"lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap"}
	for _, prefix := range skip {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
