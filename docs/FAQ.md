# Questions people ask

*Audience: anyone deciding whether to run this, or trying to work out what it
just did.*

Most of these came from someone using tunless and asking. They are answered in
the order they tend to come up.

## Does this replace mihomo or sing-box?

No, and it would be a bad idea if it did. Your proxy is where the interesting
work happens — nodes, subscriptions, rule sets, the routing you have tuned over
months. `tunless` replaces exactly one piece of it: the part that decides which
connections your proxy gets to see. Everything downstream of that stays yours.

## Do I lose my routing rules?

Almost none of them.

`tunless` hands your proxy a normal SOCKS5 request with the hostname in it, so
domain rules, rule sets, GEOIP, node selection and subscriptions match exactly
the way they do now. If anything a TUN gives your rules *less* to work with,
because by the time a packet reaches a TUN the name is gone and the proxy is
matching on an address it had to fabricate.

The one rule type that stops working is `PROCESS-NAME`. SOCKS5 has nowhere to
put process identity, so every captured flow arrives at the proxy looking like
it came from `tunless`. You do not lose the ability to select by application,
though — see the next question.

## Does it work with my nodes — VMess, Hysteria2, WireGuard?

They are not affected, because `tunless` never sees them.

It speaks exactly one protocol, SOCKS5, to a listener on loopback. What your
proxy does on the far side of that listener — the node protocol, whether that is
VMess, VLESS, Trojan, Shadowsocks, Hysteria2, TUIC or WireGuard, along with
REALITY, multiplexing, load balancing, health checks and subscription updates —
happens after the handoff and is untouched. `tunless` replaces the inbound, not
the outbound.

That is also why it is not Clash-specific. Any local SOCKS5 listener works:
mihomo, sing-box, Xray. `--preset clash-verge` is shorthand for two process
exclusions and a default port, not an integration; the command it expands to in
full is under [running](MACOS.md#running).

What the handoff does constrain is the shape of what reaches the listener. TCP
arrives as SOCKS5 CONNECT and UDP as UDP ASSOCIATE, so an upstream that refuses
UDP ASSOCIATE — or a node that carries no UDP — fails captured UDP while TCP
keeps working. QUIC and HTTP/3 are where you notice. `check` reports both
transports before you commit to the deployment, and TUN mode hid this class of
problem because mihomo handled UDP inside itself rather than relaying it to
anybody.

Your proxy's system-proxy toggle is orthogonal to all of this and can stay
however you like it. An application that honors `HTTPS_PROXY` dials
`127.0.0.1:7897` itself, and loopback is reserved from capture, so that
connection reaches your proxy directly rather than being captured and handed
back to it. Nothing is proxied twice.

## Can I proxy only some applications?

Yes, and this is the part that gets better rather than worse.

On macOS, name them:

```console
Tunless start --preset clash-verge --upstream 127.0.0.1:7897 \
  --include-process /usr/bin/curl \
  --include-process com.apple.Safari
```

Patterns match a signing identifier, a full executable path, or just the file
name. Paths matter more than you would think: binaries built without a bundle —
most Homebrew tools, plenty of Go and Rust programs — report a generic
identifier that they share with unrelated software. `--exclude-process a.out`
is a shotgun. `--exclude-process '/opt/homebrew/*/xray'` is not.

On Linux the selection is the capture scope. Put the applications you want
proxied in one cgroup and point `--cgroup` at it.

Either way, anything you did not select never reaches your proxy at all. It goes
out normally, with no rules evaluated. That is the opposite of TUN mode, where
everything arrives at the proxy and gets sorted once it is already inside.

If you want different applications on different nodes, run one `tunless` per
group against its own listener on the proxy, and keep the per-listener rules
downstream.

## Should I turn my proxy's TUN mode off?

You can leave it on — they coexist — but if you are running `tunless` there is
not much left for the TUN to do, and a few reasons to switch it off.

**It will not make anything faster.** Capture happens at the socket layer,
before the routing table, so a flow `tunless` takes never reaches the route that
points at the TUN. Measured on the TUN interface's own byte counters: a captured
20 MB transfer put 3,798 bytes across the TUN, and the same transfer excluded
from capture put 42 MB. Throughput either way sat inside the run-to-run spread
of the link. Performance is not the reason to choose.

The reasons are fake IP and the routing table. With the TUN off, nothing hands
out addresses from `198.18.0.0/15`, so nothing caches one, logs one, or trips
over one after its mapping has expired. And nothing rewrites your default route
with an entry that no process owns.

**Turning the TUN off is two changes, not one.** The `tun` block and the `dns`
block are independent. Disabling the TUN stops the route hijack and the port-53
hijack, but `enhanced-mode: fake-ip` keeps minting `198.18.0.0/15` answers for
anything that still reaches that resolver, and an application holding one from
before the change keeps it. Switch the mode to `redir-host` at the same time —
the diff is in [migrate from mihomo TUN](../README.md#migrate-from-mihomo-tun)
— and discard what already cached a fake address, which on macOS means `sudo
killall mDNSResponder` and restarting the applications holding one. A fake
address that outlives the TUN giving it meaning still connects successfully and
then transfers nothing, so this failure arrives looking like a broken network
rather than a stale answer.

The reason to keep it is leak containment. `tunless` fails open on purpose: if
it stops, is uninstalled, or stands aside because your upstream broke, new
connections go out directly. With a TUN underneath, those connections are still
proxied. If your requirement is that nothing ever leaves unproxied, keep the TUN
and accept fake IP as the price.

Details and the measurement:
[should the upstream keep its TUN device?](MACOS.md#should-the-upstream-keep-its-tun-device)

## I turned the TUN off and some things stopped working

Then those flows were never captured, and the TUN was covering for it.

`tunless` is fail-open by construction: anything it declines is handed back to
the kernel and goes out the way it would if nothing were installed. With a TUN
underneath, "declined" still meant "proxied", so a gap in capture cost you
nothing and showed you nothing. Turning the TUN off does not create the gap; it
makes it visible. The question is therefore always *which* flows were declined,
and one diagnostic answers it before any theorizing: reproduce the failure while
watching `--telemetry` on macOS, or the debug flow logs on Linux
(`--log-level debug`, read with `journalctl -u tunless`). **A failing connection
that produced no flow record was never claimed, so the fault is in capture. One
that produced a record was claimed, so the fault is downstream in your proxy.**
The aggregate counters at `/v1/status` deliberately carry no destinations, so
they tell you whether capture is claiming flows, not which ones.

For a flow that was never claimed, these are the reasons, most common first.

**A fake address that outlived its TUN.** Covered in the previous question, and
the likeliest cause if what you see is a connection that opens and then
transfers nothing.

**Capture is not actually running.** A paused session is still a live session,
so `status` reports `connected` either way and the `capture` field is the one
that answers. Check the upstream port while you are there: the Linux unit
defaults to `127.0.0.1:7890`, which is mihomo's default rather than Clash Verge
Rev's `7897`, and an upstream nothing is listening on fails every captured flow
while leaving everything else working.

**It only carries TCP and UDP.** ESP, GRE, SCTP and raw ICMP go direct,
unmodified — the eBPF hooks return early on them and `NEAppProxyFlow` is never
handed one. This is deliberate: `ping` and `traceroute` report reality rather
than a synthesized reply, which a TUN cannot offer. It does mean a TUN that was
answering ICMP for an unreachable destination was telling you something untrue,
and turning it off replaces a false success with a true failure.

**UDP has to be relayed, and frequently is not.** Upstreams commonly relay DNS
over TCP while refusing SOCKS5 UDP ASSOCIATE, and a node that carries no UDP
does the same to QUIC and HTTP/3. `check` reports it as `dns.udpRelayWorks`
before you commit to the deployment. TUN mode hid this because mihomo handled
UDP inside itself rather than relaying it to anyone.

**The flow was outside the capture scope.** On Linux the scope is the cgroup, so
the default `/sys/fs/cgroup/user.slice` leaves system services, containers, and
other slices direct. On macOS it is the process filters, and `--preset
clash-verge` excludes the upstream itself by design. Anything not selected never
reaches the proxy at all.

**The destination is one that nothing captures.** Loopback, link-local,
multicast and broadcast are reserved by the capture path itself, and the
private, CGNAT and `198.18.0.0/15` ranges are excluded by default. A
destination you genuinely want proxied inside those ranges needs
`--include-destination`; the reserved set cannot be overridden at all. See
[destinations that are never captured](OPERATIONS.md#destinations-that-are-never-captured).

**It came from a virtual machine.** Guest socket calls happen in the guest
kernel, where no host cgroup hook or Network Extension can see them, so Docker
Desktop, UTM and Parallels traffic is packet forwarding by the time it reaches
the host. Install `tunless` inside the guest, or keep the TUN for that traffic —
whole-VM transparency is honestly a packet-layer problem. See
[boundaries](CONTAINERS.md#boundaries).

The last three are the ones worth keeping a TUN underneath for, if you need
them proxied and cannot move them into scope. The rest are configuration.

## What happens if tunless crashes?

Your traffic goes out the way it did before you installed it.

This is not a recovery path that has to run; there is nothing to roll back. The
capture belongs to the kernel — an unpinned `bpf_link` on Linux, the system
extension lifecycle on macOS — so when the process goes away the capture goes
with it. We test it with `SIGKILL` rather than describing it.

Uninstalling on macOS is worth one caveat: deleting `Tunless.app` while capture
is running leaves the host working, but does **not** stop capture, and the
binary that could stop it is now gone. Run `cleanup` first. If you have already
deleted it, System Settings → General → Login Items & Extensions → Network
Extensions will turn it off.

## My DNS broke. What happened?

Almost certainly one of three things, and the first two are fixed in current
builds.

**A loop.** Capture rewrites port-53 flows to a resolver you trust and relays
them through your proxy. The proxy then dials that resolver to answer — and if
*that* connection is captured too, the query is handed straight back to the
proxy waiting on it. Nothing errors. Every lookup on the machine just recurses
until it times out, which feels exactly like a dead network. Current builds
reserve the resolver's address from capture so this cannot happen, whichever
proxy you run and whether or not you named its process.

Giving `--upstream` a hostname was a second door into the same room: dialing the
proxy needed a lookup, and capturing that lookup needed the dial. The name is
now resolved once at startup and the address is what the datapath uses, so
nothing in the path depends on the DNS it is carrying. Restart to pick up a
record that changed.

**A stale fake IP.** If your proxy's TUN handed out an address from
`198.18.0.0/15` and something cached it, a connection to that address opens
successfully and then transfers nothing. No error anywhere. That range is
excluded from capture by default now.

**Capture stood aside and you did not notice.** If the upstream stops resolving,
the provider stops claiming flows so your machine keeps working. It resumes on
its own when the upstream recovers. `status` tells you which state you are in:

```console
Tunless status
{ "status": "connected", "capture": "capturing" }
{ "status": "connected", "capture": "paused: name resolution failed 3 times in a row..." }
```

Note that `status` alone says `connected` either way — a paused session is still
a live session. The `capture` field is the one that answers the question.

**`dig` works but curl hangs before `Trying`.** These programs do not exercise
the same macOS resolver path. `dig` opens its own DNS socket; curl and ordinary
applications call `getaddrinfo`, which asks `mDNSResponder`. An affected older
Tunless build could error-close an admitted UDP flow when its watchdog paused,
or expire a quiet port-53 flow after two minutes. `mDNSResponder` retained its
socket, but later sends failed locally with `EINVAL`, so applications waited
even though the DNS server had a valid answer. Current builds preserve admitted
UDP flows across a pause, send them directly until capture resumes, and do not
idle-expire port-53 flows.

To recover a Mac already in that state, restart the resolver. `mDNSResponder`
is managed by launchd and comes back immediately; this does not change the DNS
servers in Network Settings:

```console
sudo killall mDNSResponder
curl --connect-timeout 10 -v https://api.anthropic.com/
```

The second command should print `Host ... was resolved` and then `Trying ...`.
On an older Tunless build, upgrade before relying on this recovery because the
next watchdog pause can invalidate the replacement socket again.

## Can a website tell I am using a proxy?

Not from the DNS answers, which is the usual giveaway. Names resolve to their
real addresses, so nothing on your machine is holding an address from a reserved
range that only exists inside a proxy. Applications that inspect their own DNS —
region checks, SSRF guards in coding agents — see what they would see without
any of this.

What a remote site can still tell is whatever your proxy's exit node tells it.
That has not changed and is not something `tunless` can affect.

## Does it work with containers?

On Linux, yes: Docker, Podman, and containerd/CRI-O, capturing inside the
container's own network namespace. Docker Desktop on macOS works through a
bridge. The details, and where the boundaries are, are in
[containers and virtual machines](CONTAINERS.md).

## Is it slow?

Not measurably. On a steady link, 112.82 MB/s captured against 113.13 MB/s
direct — about a quarter of a percent — at 1.35 CPU-seconds and roughly 10 MB
of memory per gigabyte relayed.

Every number in this repository is recorded with the machine and the date it
came from, including the ones that came out badly, in
[measurements and release gates](MEASUREMENTS.md).

## Can I use it now?

0.2.0 is a release, and it says on its face how far each platform got. Linux is
generally available: capture runs against a live kernel on every pull request,
and every performance claim in the repository is backed by a dated measurement
naming the host it came from. macOS is beta. On Windows there is source code for
a driver that has never been compiled by a WDK, and you should not run it.

The reason macOS is beta rather than released is worth stating, because it is
the same reason the release is worded carefully. Nearly every serious bug found
here turned up by running the thing for hours rather than by running its tests —
the worst left a laptop resolving names unprotected for nine hours after it went
to sleep, and 0.2.0 exists to close one that a day on a live host surfaced. The
48-hour soak has still not been completed on either platform. What is unproven
is listed rather than left for you to find, in [where the project actually
is](../README.md#where-the-project-actually-is) and [measurements and release
gates](MEASUREMENTS.md).

Read [operations](OPERATIONS.md) before deploying, particularly the recovery
section.

## I have a Windows machine and want to help

That is genuinely the most useful thing anyone could offer right now. The driver
needs someone who can build it, load it, and run it under Driver Verifier, and
nobody here has the hardware. The work is broken into pieces that can be done
independently in
[the Windows notes](WINDOWS.md#deferred-to-contributors) — even a report that
says "it does not compile, here is the error" moves it forward.
