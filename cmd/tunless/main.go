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
	"github.com/bojieli/tunless/workload"
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
	var showVersion, check, disableDNSOverride bool
	var metadataUsername bool
	var containerPID, maxFlows int
	var flowIdleTimeout, udpIdleTimeout time.Duration
	var checkTarget string
	var containerDNS []string
	var includeProc, excludeProc, includeDst, excludeDst stringsFlag
	dnsDefault := os.Getenv("TUNLESS_DNS_UPSTREAM")
	if dnsDefault == "" {
		dnsDefault = "1.1.1.1:53"
	}
	flag.StringVar(&upstream, "upstream", os.Getenv("TUNLESS_UPSTREAM"), "SOCKS5 upstream, e.g. 127.0.0.1:7890 or socks5://user:pass@host:port")
	flag.StringVar(&listen, "listen", "127.0.0.1:1080", "numeric loopback address for redirect/reference listeners")
	flag.StringVar(&backendName, "backend", "auto", "capture backend: auto, linux, redirect, or loopback")
	flag.StringVar(&cgroupPath, "cgroup", os.Getenv("TUNLESS_CGROUP"), "cgroup v2 path captured by the Linux backend, or \"kubernetes\" to select the node's pod hierarchy without capturing this process")
	flag.StringVar(&networkNamespace, "network-namespace", "", "optional Linux network namespace path for namespace-local redirect listeners")
	flag.IntVar(&containerPID, "container-pid", 0, "optional Linux container init PID; derives its cgroup and network namespace")
	flag.StringVar(&containerID, "container-id", "", "expected container ID; protects --container-pid from PID reuse")
	flag.StringVar(&dnsListen, "dns-listen", "", "optional real-answer DNS observer listen address")
	flag.StringVar(&dnsUpstream, "dns-upstream", dnsDefault, "numeric trusted resolver used for captured port-53 traffic and the optional DNS observer")
	flag.BoolVar(&disableDNSOverride, "disable-dns-override", false, "preserve each application's original DNS resolver instead of rewriting port-53 traffic")
	flag.StringVar(&logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.BoolVar(&check, "check", false, "run machine-readable preflight checks without starting capture")
	flag.StringVar(&checkTarget, "check-target", "1.1.1.1:443", "numeric TCP destination used by --check SOCKS5 CONNECT")
	flag.BoolVar(&metadataUsername, "metadata-username", false, "encode process identity in the SOCKS5 username")
	flag.StringVar(&metadataSocket, "metadata-socket", "", "optional Unix socket exposing process metadata by SOCKS source port")
	flag.StringVar(&statusListen, "status-listen", "", "optional loopback HTTP health/status address, e.g. 127.0.0.1:6060")
	flag.IntVar(&maxFlows, "max-flows", 4096, "maximum concurrent captured flows before fail-fast rejection")
	flag.DurationVar(&flowIdleTimeout, "flow-idle-timeout", 5*time.Minute, "maximum TCP inactivity before completing a stalled flow (zero disables)")
	flag.DurationVar(&udpIdleTimeout, "udp-idle-timeout", 2*time.Minute, "maximum UDP association inactivity before completion (zero disables)")
	flag.Var(&includeProc, "include-process", "capture executable path/name glob (repeatable)")
	flag.Var(&excludeProc, "exclude-process", "exclude executable path/name glob (repeatable)")
	flag.Var(&includeDst, "include-destination", "capture CIDR prefix (repeatable)")
	flag.Var(&excludeDst, "exclude-destination", "exclude CIDR prefix (repeatable)")
	flag.Parse()
	disableFlagSet := false
	flag.Visit(func(item *flag.Flag) {
		if item.Name == "disable-dns-override" {
			disableFlagSet = true
		}
	})
	if raw := os.Getenv("TUNLESS_DISABLE_DNS_OVERRIDE"); raw != "" && !disableFlagSet {
		value, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			return errors.New("TUNLESS_DISABLE_DNS_OVERRIDE must be a boolean")
		}
		disableDNSOverride = value
	}
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
	if flowIdleTimeout < 0 || udpIdleTimeout < 0 {
		return errors.New("flow idle timeouts cannot be negative")
	}
	var dnsTarget netip.AddrPort
	if !disableDNSOverride || dnsListen != "" {
		var dnsErr error
		dnsTarget, dnsErr = netip.ParseAddrPort(dnsUpstream)
		if dnsErr != nil || dnsTarget.Port() == 0 {
			return errors.New("--dns-upstream must be a numeric IP:port (IPv6 addresses require brackets)")
		}
		dnsTarget = netip.AddrPortFrom(dnsTarget.Addr().Unmap(), dnsTarget.Port())
	}
	if dnsListen != "" {
		var listenErr error
		dnsListen, listenErr = dnsobserver.ValidateAddress(dnsListen)
		if listenErr != nil {
			return listenErr
		}
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
		if disableDNSOverride {
			excludeDst = append(excludeDst, containerDNS...)
		}
	} else if containerID != "" {
		return errors.New("--container-id requires --container-pid")
	}
	if runtime.GOOS == "linux" && cgroupPath == "kubernetes" {
		resolved, resolveErr := kubernetesCaptureScope()
		if resolveErr != nil {
			return resolveErr
		}
		cgroupPath = resolved
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
	if len(containerDNS) > 0 && disableDNSOverride {
		logger.Info("preserving container-local DNS", "destinations", containerDNS)
	} else if len(containerDNS) > 0 {
		logger.Info("capturing container DNS for trusted-resolver override", "destinations", containerDNS, "dns_upstream", dnsTarget)
	}
	client, err := parseUpstream(upstream)
	if err != nil {
		return err
	}
	named := client.Address
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), 10*time.Second)
	pinned, err := pinUpstreamAddresses(resolveCtx, client.Address, net.DefaultResolver.LookupNetIP)
	cancelResolve()
	if err != nil {
		return err
	}
	client.Address, client.Alternates = pinned[0], pinned[1:]
	if client.Address != named {
		logger.Info("pinned the upstream address at startup", "upstream", named, "address", client.Address, "alternates", client.Alternates)
	}
	client.MetadataUsername = metadataUsername
	client.FlowIdleTimeout = flowIdleTimeout
	client.UDPIdleTimeout = udpIdleTimeout
	if !disableDNSOverride {
		client.DNSOverride = dnsTarget
	}
	filter := tunless.Filter{IncludeProcesses: includeProc, ExcludeProcesses: excludeProc}
	if filter.IncludeDestinations, err = prefixes(includeDst); err != nil {
		return err
	}
	if filter.ExcludeDestinations, err = prefixes(excludeDst); err != nil {
		return err
	}
	reserved, err := reservedDestinations(pinned, client.DNSOverride, includeDst)
	if err != nil {
		return err
	}
	if len(reserved) > 0 {
		filter.ExcludeDestinations = append(filter.ExcludeDestinations, reserved...)
		logger.Info("reserving datapath destinations from capture", "destinations", reserved)
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
	case "redirect":
		if runtime.GOOS != "linux" {
			return errors.New("the redirect backend is Linux only")
		}
		backend = newRedirectBackend(listen, filter)
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
		return runDoctor(checkCtx, backendName, listen, cgroupPath, networkNamespace, filter, client, target)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serviceErrors := make(chan error, 1)
	reportServiceError := func(name string, err error) {
		wrapped := fmt.Errorf("%s stopped: %w", name, err)
		logger.Error(name+" stopped", "error", err)
		select {
		case serviceErrors <- wrapped:
		default:
		}
		stop()
	}
	if containerPID != 0 {
		go watchContainerScope(ctx, stop, cgroupPath, networkNamespace)
	}
	if metadataSocket != "" {
		server := &metadata.Server{Path: metadataSocket}
		client.Registry = server
		go func() {
			if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
				reportServiceError("metadata API", err)
			}
		}()
		defer server.Close()
		if err = waitForService(ctx, serviceErrors, server.Ready); err != nil {
			return err
		}
		logger.Info("metadata API enabled", "socket", metadataSocket)
	}
	var resolver tunless.NameResolver
	if dnsListen != "" {
		observer := &dnsobserver.Observer{
			Listen:   dnsListen,
			Upstream: dnsUpstream,
			UDPExchange: func(exchangeCtx context.Context, query []byte) ([]byte, error) {
				return client.ExchangeDNSUDP(exchangeCtx, dnsTarget, query)
			},
			TCPExchange: func(exchangeCtx context.Context, query []byte) ([]byte, error) {
				return client.ExchangeDNSTCP(exchangeCtx, dnsTarget, query)
			},
		}
		resolver = observer
		go func() {
			if err := observer.Serve(ctx); err != nil && ctx.Err() == nil {
				reportServiceError("DNS observer", err)
			}
		}()
		defer observer.Close()
		if err = waitForService(ctx, serviceErrors, observer.Ready); err != nil {
			return err
		}
		logger.Info("DNS observer enabled", "listen", dnsListen, "upstream", dnsUpstream)
	}
	stats := &tunless.Stats{}
	if statusListen != "" {
		dnsStatus := ""
		if dnsTarget.IsValid() {
			dnsStatus = dnsTarget.String()
		}
		server := &statusapi.Server{
			Address:       statusListen,
			Version:       version,
			BackendName:   backendName,
			Upstream:      client.Address,
			DNSUpstream:   dnsStatus,
			DNSOverride:   !disableDNSOverride,
			MaxConcurrent: maxFlows,
			Stats:         stats,
			Backend:       backend,
		}
		go func() {
			if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
				reportServiceError("status API", err)
			}
		}()
		defer server.Close()
		if err = waitForService(ctx, serviceErrors, server.Ready); err != nil {
			return err
		}
		logger.Info("status API enabled", "listen", statusListen)
	}
	logger.Info("starting tunless", "backend", backendName, "listen", listen, "upstream", client.Address, "dns_override", !disableDNSOverride, "dns_upstream", dnsTarget)
	coreErr := (&tunless.Core{
		Backend:       backend,
		Emitter:       client,
		Filter:        coreFilter,
		Logger:        logger,
		Resolver:      resolver,
		Stats:         stats,
		MaxConcurrent: maxFlows,
	}).Run(ctx)
	select {
	case serviceErr := <-serviceErrors:
		return serviceErr
	default:
		return coreErr
	}
}

func waitForService(ctx context.Context, serviceErrors <-chan error, ready func() bool) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-serviceErrors:
			return err
		default:
		}
		if ready() {
			return nil
		}
		select {
		case err := <-serviceErrors:
			return err
		case <-ctx.Done():
			select {
			case err := <-serviceErrors:
				return err
			default:
				return ctx.Err()
			}
		case <-ticker.C:
		case <-timer.C:
			return errors.New("timed out waiting for auxiliary service startup")
		}
	}
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
	data, err := os.ReadFile(filepath.Join(proc, "cgroup")) // #nosec G304 -- pid is a positive integer selected by the administrator
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

// reservedDestinations returns the addresses capture must leave direct because
// tunless itself relays through them.
//
// The upstream is the obvious one: handing traffic aimed at the proxy back to
// the proxy is a loop with no exit. The trusted resolver is the subtle one, and
// it is what takes DNS down host-wide. Capture rewrites every port-53 flow to
// that resolver and relays it to the upstream; the upstream then dials the
// resolver itself, and if that dial is captured too, the query is handed back
// to the upstream that is waiting on it. Nothing errors — every lookup on the
// host simply recurses until it times out, which reads as a dead network rather
// than as a proxy loop.
//
// Excluding the upstream process is the usual advice, but it means knowing
// which process to name, and being wrong is only discovered once resolution is
// already gone. The destinations are known from the configuration, so reserve
// those instead. An explicit --include-destination for the same prefix is left
// alone: naming it is the operator saying they know.
func reservedDestinations(upstream []string, dnsTarget netip.AddrPort, included []string) ([]netip.Prefix, error) {
	requested, err := prefixes(included)
	if err != nil {
		return nil, err
	}
	var reserved []netip.Prefix
	add := func(addr netip.Addr) {
		if !addr.IsValid() || addr.IsLoopback() {
			// Loopback is already skipped in the capture path itself.
			return
		}
		prefix := netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		for _, existing := range append(append([]netip.Prefix{}, requested...), reserved...) {
			if existing == prefix {
				return
			}
		}
		reserved = append(reserved, prefix)
	}
	for _, address := range upstream {
		if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
			if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
				add(addr)
			}
		}
	}
	if dnsTarget.IsValid() {
		add(dnsTarget.Addr())
	}
	return reserved, nil
}

// pinUpstreamAddresses resolves a named SOCKS5 upstream once, before capture
// starts, and returns the numeric addresses the datapath will dial from then
// on, in the order the resolver returned them.
//
// Resolving it per flow instead is a loop with no exit, because tunless
// normally shares the captured cgroup with the applications it is capturing.
// Dialing the upstream needs the name, resolving the name is a port-53 flow,
// and capturing that flow hands it to the emitter, which dials the upstream,
// which needs the name again. Nothing errors along the way: resolution simply
// recurses until the flow ceiling starts rejecting it, and what the operator
// sees is a machine whose DNS stopped working. The trusted resolver has to be
// numeric for exactly this reason, and the upstream is the other half of the
// same datapath.
//
// What the name resolved to is fixed for the life of the process. A record
// that changes is picked up by restarting, which is a smaller surprise than a
// datapath that depends on the traffic it carries.
func pinUpstreamAddresses(ctx context.Context, address string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	if _, parseErr := netip.ParseAddr(host); parseErr == nil {
		return []string{address}, nil
	}
	found, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream %q: %w", host, err)
	}
	// Every address the name carries is kept, not just the first. A proxy on
	// `localhost` answers on 127.0.0.1 while the resolver commonly names ::1
	// first, and pinning one of the two would quietly stop connecting.
	pinned := make([]string, 0, len(found))
	for _, addr := range found {
		addr = addr.Unmap()
		if addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() {
			pinned = append(pinned, net.JoinHostPort(addr.String(), port))
		}
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("upstream %q resolved without a usable address", host)
	}
	return pinned, nil
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

// kubernetesCaptureScope picks the cgroup a node-level capture may attach to.
//
// Attaching above the pods is the whole point of running on a node, and the
// obstacle is that a DaemonSet is itself a pod: attaching at the pod root would
// capture this process's own connection to its upstream, and every packet it
// forwarded would be captured again on the way out. Loop avoidance here is
// cgroup separation, exactly as it is on the desktop, and not an exception
// list -- an exception keyed on this agent's own address is the first thing a
// misconfiguration silently removes.
//
// A single scope is required rather than attaching to several, because the
// backend attaches to one and pretending otherwise would capture a subset
// while reporting success. When several are available the operator is told
// what they are and asked to choose, which is a worse experience and a true
// one.
func kubernetesCaptureScope() (string, error) {
	self := workload.SelfCgroup()
	scopes, err := workload.CaptureScopes("/sys/fs/cgroup", self)
	if err != nil {
		if errors.Is(err, workload.ErrWouldLoop) {
			return "", fmt.Errorf("%w -- run tunless outside the pod hierarchy "+
				"(a systemd unit, or a static pod in system.slice) so it can attach at the root", err)
		}
		return "", err
	}
	if len(scopes) == 1 {
		slog.Info("kubernetes capture scope selected", "cgroup", scopes[0].Path, "scope", scopes[0].Why)
		return scopes[0].Path, nil
	}
	names := make([]string, 0, len(scopes))
	for _, s := range scopes {
		names = append(names, s.Path)
	}
	return "", fmt.Errorf("this process is inside the pod hierarchy, so capture must attach below it; "+
		"pass --cgroup with one of %s, or run tunless outside the hierarchy to capture all pods at once",
		strings.Join(names, ", "))
}
