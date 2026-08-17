# Operations

## Preflight

Run the active diagnostic with the same backend, cgroup, namespace, filters,
upstream, and credentials intended for the service:

```console
sudo tunless --backend linux --cgroup /sys/fs/cgroup/my-apps \
  --upstream socks5://user:pass@127.0.0.1:7890 --check
```

The JSON report checks kernel/cgroup access, verifies Tunless is outside the
capture cgroup, loads and attaches the exact embedded BPF programs to an empty
temporary child, and performs real SOCKS5 TCP CONNECT plus UDP ASSOCIATE
commands. It removes the temporary cgroup and attachments before returning.
Use `--check-target IP:PORT` when `1.1.1.1:443` is not suitable. A failure exits
nonzero.

On macOS/Windows or with `--backend loopback`, the report validates the
privilege-free backend selection and upstream protocol. Platform extension
activation remains a separate qualification step.

## Health and status

Enable the opt-in local API with `--status-listen 127.0.0.1:6060`. Only numeric
IPv4/IPv6 loopback addresses are accepted; wildcard, hostname, LAN, and Unix
socket listeners are rejected.

```console
curl --fail http://127.0.0.1:6060/healthz
curl --fail http://127.0.0.1:6060/v1/status
```

Status contains version/backend, the upstream address without credentials,
configured concurrency limit, accepted/completed/error/overload and active
TCP/UDP counters, open redirect listeners/sockets/BPF links, UDP associations,
and Linux map entry/capacity/memlock data. It intentionally omits destination,
process, and credential data. Protect host loopback access from untrusted local
users when these aggregate values are sensitive.
Map descriptors are cloned before occupancy is counted, so the potentially
long iteration does not hold the backend lock used by live flow correlation.
Capture diagnostics are cached for one second; polling faster only refreshes
the lock-free flow counters.

## Capacity and alerts

`--max-flows` defaults to 4096. New flows above the limit are closed and
`overloaded_flows` increases; no queue grows without bound. Choose a value below
the host file-descriptor and upstream capacity, then alert on:

- nonzero or increasing `overloaded_flows`;
- sustained `emitter_errors` or active-flow counts that never return;
- BPF map entries approaching `max_entries`;
- fewer than seven Linux BPF links while capture is meant to be running; and
- a stopped health endpoint or unexpected process restart.

The three large Linux LRU maps reserve kernel memory at load time. Consult the
measured memlock footprint in `MEASUREMENTS.md` before dense multi-container
deployment; each namespace controller owns independent maps.

## Failure and recovery

Graceful stop and process death close unpinned BPF links. New application flows
then continue directly without route or DNS repair; in-flight proxied streams
can fail and applications must reconnect. After an incident, confirm no stale
links with `bpftool link show`, run `--check`, then restart the controller.

For a container, stop/recreate changes its PID, cgroup, and namespace. The watch
helper discovers the replacement; one-shot helpers exit. Exact container-ID
validation prevents a recycled PID from being attached. An upstream restart
can break an existing association, but the next datagram recreates SOCKS5 UDP
state while retaining kernel socket correlation.

## Logs and privacy

JSON logs go to stderr. Debug flow logs may contain destinations, process paths,
or inferred domain names and should be treated as network metadata. Status
counters do not contain those fields. Never place SOCKS credentials in shared
logs, issue reports, shell history, or service files readable by other users.

## Upgrade and uninstall

Verify candidate checksums and SBOMs, run `--check` with the new binary, then
restart the service. A package upgrade must preserve `/etc/tunless.env`.
Uninstall stops/disables both the host and optional container-watcher units
through package scripts and removes the binary/units while leaving the
operator-owned config for deliberate cleanup.
Never replace a running privileged binary with an unreviewed source build.

The optional `tunless-container-watch.service` attaches only containers with
the configured `TUNLESS_CONTAINER_LABEL` (default `com.bojieli.tunless`). It is
packaged but never enabled automatically. Run it alongside `tunless.service`
when both host applications and labelled dev containers need the same upstream.
