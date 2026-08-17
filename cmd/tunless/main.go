package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bojieli/tunless"
	linuxbackend "github.com/bojieli/tunless/backend/linux"
	"github.com/bojieli/tunless/backend/loopback"
	windowsbackend "github.com/bojieli/tunless/backend/windows"
	"github.com/bojieli/tunless/dnsobserver"
	"github.com/bojieli/tunless/metadata"
	"github.com/bojieli/tunless/socks5"
	statusapi "github.com/bojieli/tunless/status"
)

var version = "dev"

type stringsFlag []string

func (f *stringsFlag) String() string     { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	if err := run(); err != nil {
		slog.Error("tunless stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var upstream, listen, logLevel, backendName, cgroupPath, networkNamespace, containerID, dnsListen, dnsUpstream, metadataSocket, statusListen string
	var showVersion, check bool
	var metadataUsername bool
	var containerPID, maxFlows int
	var checkTarget string
	var containerDNS []string
	var includeProc, excludeProc, includeDst, excludeDst stringsFlag
	flag.StringVar(&upstream, "upstream", os.Getenv("TUNLESS_UPSTREAM"), "SOCKS5 upstream, e.g. 127.0.0.1:7890 or socks5://user:pass@host:port")
	flag.StringVar(&listen, "listen", "127.0.0.1:1080", "reference SOCKS5 listener address")
	flag.StringVar(&backendName, "backend", "auto", "capture backend: auto, linux, or loopback")
	flag.StringVar(&cgroupPath, "cgroup", os.Getenv("TUNLESS_CGROUP"), "cgroup v2 path captured by the Linux backend")
	flag.StringVar(&networkNamespace, "network-namespace", "", "optional Linux network namespace path for namespace-local redirect listeners")
	flag.IntVar(&containerPID, "container-pid", 0, "optional Linux container init PID; derives its cgroup and network namespace")
	flag.StringVar(&containerID, "container-id", "", "expected container ID; protects --container-pid from PID reuse")
	flag.StringVar(&dnsListen, "dns-listen", "", "optional real-answer DNS observer listen address")
	flag.StringVar(&dnsUpstream, "dns-upstream", "1.1.1.1:53", "resolver used by the optional DNS observer")
	flag.StringVar(&logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.BoolVar(&check, "check", false, "run machine-readable preflight checks without starting capture")
	flag.StringVar(&checkTarget, "check-target", "1.1.1.1:443", "numeric TCP destination used by --check SOCKS5 CONNECT")
	flag.BoolVar(&metadataUsername, "metadata-username", false, "encode process identity in the SOCKS5 username")
	flag.StringVar(&metadataSocket, "metadata-socket", "", "optional Unix socket exposing process metadata by SOCKS source port")
	flag.StringVar(&statusListen, "status-listen", "", "optional loopback HTTP health/status address, e.g. 127.0.0.1:6060")
	flag.IntVar(&maxFlows, "max-flows", 4096, "maximum concurrent captured flows before fail-fast rejection")
	flag.Var(&includeProc, "include-process", "capture executable path/name glob (repeatable)")
	flag.Var(&excludeProc, "exclude-process", "exclude executable path/name glob (repeatable)")
	flag.Var(&includeDst, "include-destination", "capture CIDR prefix (repeatable)")
	flag.Var(&excludeDst, "exclude-destination", "exclude CIDR prefix (repeatable)")
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return nil
	}
	if upstream == "" {
		return errors.New("--upstream is required")
	}
	if maxFlows < 1 {
		return errors.New("--max-flows must be positive")
	}
	if statusListen != "" {
		var statusErr error
		statusListen, statusErr = statusapi.ValidateAddress(statusListen)
		if statusErr != nil {
			return statusErr
		}
	}
	if containerPID != 0 {
		if runtime.GOOS != "linux" || containerPID < 1 {
			return errors.New("--container-pid requires a positive PID on Linux")
		}
		var scopeErr error
		cgroupPath, networkNamespace, scopeErr = containerScope(containerPID, containerID)
		if scopeErr != nil {
			return scopeErr
		}
		containerDNS = containerDNSPrefixes(containerPID)
		excludeDst = append(excludeDst, containerDNS...)
	} else if containerID != "" {
		return errors.New("--container-id requires --container-pid")
	}
	if runtime.GOOS == "linux" && cgroupPath == "" && (backendName == "auto" || backendName == "linux") {
		const defaultCgroup = "/sys/fs/cgroup/user.slice"
		if _, statErr := os.Stat(defaultCgroup); statErr == nil {
			cgroupPath = defaultCgroup
		}
	}
	level := new(slog.LevelVar)
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	if len(containerDNS) > 0 {
		logger.Info("preserving container-local DNS", "destinations", containerDNS)
	}
	client, err := parseUpstream(upstream)
	if err != nil {
		return err
	}
	client.MetadataUsername = metadataUsername
	filter := tunless.Filter{IncludeProcesses: includeProc, ExcludeProcesses: excludeProc}
	if filter.IncludeDestinations, err = prefixes(includeDst); err != nil {
		return err
	}
	if filter.ExcludeDestinations, err = prefixes(excludeDst); err != nil {
		return err
	}
	var backend tunless.Backend
	coreFilter := filter
	if backendName == "auto" {
		if runtime.GOOS == "linux" {
			backendName = "linux"
		} else if runtime.GOOS == "windows" {
			backendName = "windows"
		} else {
			backendName = "loopback"
		}
	}
	switch backendName {
	case "linux":
		if len(filter.IncludeProcesses) > 0 || len(filter.ExcludeProcesses) > 0 {
			return errors.New("linux process selection is the --cgroup scope; process glob flags are only supported by metadata-capable backends")
		}
		backend = &linuxbackend.Backend{Address: listen, CgroupPath: cgroupPath, NetworkNamespace: networkNamespace, Filter: filter}
		coreFilter = tunless.Filter{}
	case "loopback":
		if networkNamespace != "" {
			return errors.New("--network-namespace requires the Linux backend")
		}
		backend = &loopback.Backend{Address: listen}
	case "windows":
		if networkNamespace != "" {
			return errors.New("--network-namespace requires the Linux backend")
		}
		if len(filter.IncludeProcesses)+len(filter.ExcludeProcesses)+len(filter.IncludeDestinations)+len(filter.ExcludeDestinations) > 0 {
			return errors.New("windows capture filters require driver-side enforcement and are unavailable until the Windows runtime gate is complete")
		}
		backend = &windowsbackend.Backend{Address: listen}
	default:
		return fmt.Errorf("unknown backend %q", backendName)
	}
	if check {
		target, targetErr := netip.ParseAddrPort(checkTarget)
		if targetErr != nil || target.Port() == 0 {
			return errors.New("--check-target must be a numeric IP:port")
		}
		checkCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return runDoctor(checkCtx, backendName, cgroupPath, networkNamespace, filter, client, target)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if containerPID != 0 {
		go watchContainerScope(ctx, stop, cgroupPath, networkNamespace)
	}
	if metadataSocket != "" {
		server := &metadata.Server{Path: metadataSocket}
		client.Registry = server
		go func() {
			if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
				logger.Error("metadata API stopped", "error", err)
				stop()
			}
		}()
		defer server.Close()
		logger.Info("metadata API enabled", "socket", metadataSocket)
	}
	var resolver tunless.NameResolver
	if dnsListen != "" {
		observer := &dnsobserver.Observer{Listen: dnsListen, Upstream: dnsUpstream}
		resolver = observer
		go func() {
			if err := observer.Serve(ctx); err != nil && ctx.Err() == nil {
				logger.Error("DNS observer stopped", "error", err)
				stop()
			}
		}()
		defer observer.Close()
		logger.Info("DNS observer enabled", "listen", dnsListen, "upstream", dnsUpstream)
	}
	stats := &tunless.Stats{}
	if statusListen != "" {
		server := &statusapi.Server{
			Address:       statusListen,
			Version:       version,
			BackendName:   backendName,
			Upstream:      client.Address,
			MaxConcurrent: maxFlows,
			Stats:         stats,
			Backend:       backend,
		}
		go func() {
			if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
				logger.Error("status API stopped", "error", err)
				stop()
			}
		}()
		defer server.Close()
		logger.Info("status API enabled", "listen", statusListen)
	}
	logger.Info("starting tunless", "backend", backendName, "listen", listen, "upstream", client.Address)
	return (&tunless.Core{
		Backend:       backend,
		Emitter:       client,
		Filter:        coreFilter,
		Logger:        logger,
		Resolver:      resolver,
		Stats:         stats,
		MaxConcurrent: maxFlows,
	}).Run(ctx)
}

func containerDNSPrefixes(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid))
	if err != nil {
		return nil
	}
	return privateDNSPrefixes(data)
}

func privateDNSPrefixes(data []byte) []string {
	seen := make(map[netip.Addr]struct{})
	var prefixes []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(fields[1], "[]"))
		if err != nil || !(address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()) {
			continue
		}
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		prefixes = append(prefixes, fmt.Sprintf("%s/%d", address, bits))
	}
	return prefixes
}

func watchContainerScope(ctx context.Context, stop context.CancelFunc, cgroupPath, networkNamespace string) {
	cgroupInfo, cgroupErr := os.Stat(cgroupPath)
	namespaceInfo, namespaceErr := os.Stat(networkNamespace)
	if cgroupErr != nil || namespaceErr != nil {
		stop()
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentCgroup, err := os.Stat(cgroupPath)
			if err != nil || !os.SameFile(cgroupInfo, currentCgroup) {
				stop()
				return
			}
			currentNamespace, err := os.Stat(networkNamespace)
			if err != nil || !os.SameFile(namespaceInfo, currentNamespace) {
				stop()
				return
			}
		}
	}
}

func containerScope(pid int, containerID string) (string, string, error) {
	proc := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(filepath.Join(proc, "ns/net")); err != nil {
		return "", "", fmt.Errorf("container network namespace: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return "", "", fmt.Errorf("read container cgroup: %w", err)
	}
	cgroup, err := cgroupPathFromProc(data)
	if err != nil {
		return "", "", err
	}
	if containerID != "" {
		if err = validateContainerID(containerID); err != nil {
			return "", "", err
		}
		if !cgroupMatchesContainer(cgroup, containerID) {
			return "", "", errors.New("container PID no longer belongs to the expected container")
		}
	}
	if _, err = os.Stat(cgroup); err != nil {
		return "", "", fmt.Errorf("container cgroup: %w", err)
	}
	return cgroup, filepath.Join(proc, "ns/net"), nil
}

func cgroupMatchesContainer(cgroup, containerID string) bool {
	for _, component := range strings.Split(path.Clean(cgroup), "/") {
		candidate := strings.TrimSuffix(component, ".scope")
		for _, prefix := range []string{"docker-", "cri-containerd-", "crio-", "libpod-"} {
			candidate = strings.TrimPrefix(candidate, prefix)
		}
		if candidate == containerID {
			return true
		}
	}
	return false
}

func validateContainerID(value string) error {
	if len(value) < 12 || len(value) > 64 {
		return errors.New("container ID must contain 12 to 64 hexadecimal characters")
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return errors.New("container ID must contain lowercase hexadecimal characters")
		}
	}
	return nil
}

func cgroupPathFromProc(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		raw := fields[2]
		if !strings.HasPrefix(raw, "/") {
			return "", errors.New("unsafe container cgroup-v2 path")
		}
		for _, component := range strings.Split(raw, "/") {
			if component == ".." {
				return "", errors.New("unsafe container cgroup-v2 path")
			}
		}
		relative := path.Clean(raw)
		if relative == "/" || relative == "." {
			return "", errors.New("unsafe container cgroup-v2 path")
		}
		return path.Join("/sys/fs/cgroup", strings.TrimPrefix(relative, "/")), nil
	}
	return "", errors.New("container does not have a cgroup-v2 entry")
}

func parseUpstream(value string) (*socks5.Client, error) {
	if !strings.Contains(value, "://") {
		address, err := normalizeHostPort(value)
		if err != nil {
			return nil, fmt.Errorf("upstream: %w", err)
		}
		return &socks5.Client{Address: address}, nil
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return nil, errors.New("upstream must be host:port or a socks5 URL")
	}
	if u.Opaque != "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("SOCKS5 upstream URL must contain only credentials, host, and port")
	}
	address, err := normalizeHostPort(net.JoinHostPort(u.Hostname(), u.Port()))
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	c := &socks5.Client{Address: address}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
		if len(c.Username) > 255 || len(c.Password) > 255 {
			return nil, errors.New("SOCKS5 upstream credentials exceed 255 bytes")
		}
	}
	return c, nil
}

func normalizeHostPort(value string) (string, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("address must be host:port (IPv6 addresses require brackets)")
	}
	if host == "" {
		return "", errors.New("host is empty")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

func prefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid destination prefix %q: %w", value, err)
		}
		result = append(result, p)
	}
	return result, nil
}
