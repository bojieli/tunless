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

The reason to keep it is leak containment. `tunless` fails open on purpose: if
it stops, is uninstalled, or stands aside because your upstream broke, new
connections go out directly. With a TUN underneath, those connections are still
proxied. If your requirement is that nothing ever leaves unproxied, keep the TUN
and accept fake IP as the price.

Details and the measurement:
[should the upstream keep its TUN device?](MACOS.md#should-the-upstream-keep-its-tun-device)

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

On Linux, it works and the evidence is in the repository. On macOS it works and
is beta. On Windows there is source code for a driver that has never been
compiled by a WDK, and you should not run it.

But nothing has been released yet, and that is deliberate. Nearly every serious
bug found so far turned up by running the thing for hours rather than by running
its tests — the worst of them left a laptop resolving names unprotected for nine
hours after it went to sleep. Until a long soak stops finding things like that,
a release would mostly be handing the next one to somebody else.

If you want to try it anyway, build from source and read
[operations](OPERATIONS.md) first — particularly the recovery section.

## I have a Windows machine and want to help

That is genuinely the most useful thing anyone could offer right now. The driver
needs someone who can build it, load it, and run it under Driver Verifier, and
nobody here has the hardware. The work is broken into pieces that can be done
independently in
[the Windows notes](WINDOWS.md#deferred-to-contributors) — even a report that
says "it does not compile, here is the error" moves it forward.
