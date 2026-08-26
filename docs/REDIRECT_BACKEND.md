# The netfilter fallback

The eBPF backend needs cgroup v2, `CAP_BPF`, and a 5.7 kernel. Plenty of Linux
hosts have none of those and all of them have netfilter: an older kernel, a
distribution that disables unprivileged BPF, a managed node whose operator will
grant `NET_ADMIN` and not `CAP_BPF`.

`--backend redirect` accepts connections netfilter has already redirected to a
local listener and recovers where each was originally going.

## What you give up

**Fail-open.** This is the important one.

The eBPF backend attaches an unpinned `bpf_link`, so the attachment dies with
the process and new traffic goes direct. A netfilter rule outlives the process
that wants it. Kill this backend and the rule keeps sending connections to a
port nobody is listening on, so they fail rather than bypass.

That's the property the main backend exists to preserve, and this one cannot.
It's why `auto` never selects it: you have to ask.

**Process attribution.** A redirected connection arrives as an ordinary socket
with no record of what opened it. Recovering that would mean matching the
source port against `/proc/net/tcp` for an inode, then scanning every process's
descriptors for it, once per connection, racing a process that may already have
exited.

So `Process` is empty here, and `--include-process` / `--exclude-process` are
**refused at startup** rather than silently matching nothing. Filter on
destinations instead, which is exactly what this backend does recover.

## Why not TUN

A TUN device delivers packets, not connections. Turning them back into the byte
streams a proxy can forward needs a second TCP/IP stack in userspace, which is
the first thing [BLUEPRINT.md](../BLUEPRINT.md) objects to about TUN mode: it
sits in the latency path, costs a copy and a boundary crossing per packet, and
is a large new surface to be wrong in.

netfilter keeps the kernel's own TCP stack. The connection arrives as a socket
and `SO_ORIGINAL_DST` says where it was headed. That's strictly less machinery
for the same result on any host that has netfilter, which is nearly every host
that has `NET_ADMIN`.

That leaves one case uncovered: a host where you can create a tunnel device but
cannot filter. We looked for it and could not find a realistic one. `NET_ADMIN`
grants both, and a kernel without netfilter is not a kernel this agent runs on
for other reasons.

So a TUN backend is a decided no rather than a pending item. Two backends cover
the hosts that exist: eBPF where `CAP_BPF` is available, netfilter where only
`NET_ADMIN` is. Adding a third would mean a second TCP/IP stack in userspace,
in the latency path, for a host nobody has produced, and it would put a virtual
interface inside a project whose [BLUEPRINT](../BLUEPRINT.md) lists not having
one as a permanent non-goal.

If you have that host, open an issue with the kernel version and the
capabilities you can grant. That is the evidence that would reopen this, and it
is the only thing that would.

## Using it

The rule is yours to install and remove. This backend does not install it,
because a rule installed by a process that can be killed is global state with
no owner the moment it is.

```sh
# send port 443 to the listener, leaving the agent's own traffic alone
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m owner ! --uid-owner tunless -j REDIRECT --to-ports 1080

tunless --backend redirect --listen 127.0.0.1:1080 --upstream 127.0.0.1:7890

# afterwards
sudo iptables -t nat -D OUTPUT -p tcp --dport 443 \
  -m owner ! --uid-owner tunless -j REDIRECT --to-ports 1080
```

The `--uid-owner` exclusion is the loop avoidance. It is the same principle the
eBPF backend uses with cgroup separation: the agent's own connection to its
upstream must not be captured, or every packet it forwards is captured again on
the way out.

The listener must be a literal loopback address. A routable one would accept
traffic from off-host, which this backend cannot distinguish from a redirect
and would forward as though it were one. That is refused at startup.

## The capture floor still applies

Loopback, the unspecified address, link-local (including the cloud metadata
service at 169.254.169.254), multicast, and broadcast are never captured,
whatever your rule says. Sending any of them upstream loses them rather than
routing them. The floor is shared with every other backend rather than copied
into each.

## Verified end to end

On a Linux host in China reaching a server in California, with an unmodified
application:

```
app -> netfilter REDIRECT -> tunless (redirect backend) -> SOCKS5
    -> queqiao client -> WAN -> queqiao gateway -> destination
```

| path | 300KB cold | warm |
|---|---|---|
| direct, not redirected | 1089.3ms | 1001.4ms |
| through the stack | **624.9ms** | **381.2ms** |

The application was never configured for any of it. It connected to the
destination normally and the rule did the rest.

Connect time through the stack is 0.2ms against 187.3ms direct, because the
application's connection terminates on loopback and the round trip is paid once
by a tunnel that was already warm. That is the whole reason for a local capture
agent in front of a transport: every constraint on a long path is credit per
round trip, and putting a zero-round-trip segment at each end confines them to
the middle.

tunless logged `flow started destination=155.103.252.95:12600 pid=0` -- the
original destination recovered from `SO_ORIGINAL_DST`, and no process, which is
what this backend documents. The rule and the agent both left no state behind.
