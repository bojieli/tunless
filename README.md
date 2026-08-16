# tunless

**TUN-less transparent proxying. No fake IP, no route hijack, no second TCP stack.**

`tunless` captures outbound flows at the socket layer and hands them to an
ordinary SOCKS5 proxy. Applications are unaware — they call `connect()` and get a
working connection, with no proxy environment variable and no cooperation
required. That is the same property TUN mode provides, and it is the only reason
TUN mode exists.

What changes is underneath. Because the interception point is the socket rather
than the packet, there is no fake-IP pool, no hijacked resolver, no rewritten
routing table, and no userspace TCP stack in the datapath. The real destination
and the originating process are supplied by the kernel. When the process dies,
the kernel reverts the change — including on `SIGKILL`.

| Platform | Mechanism |
| --- | --- |
| Linux | eBPF `cgroup/connect` |
| macOS | `NETransparentProxyProvider` system extension |
| Windows | WFP `ALE_CONNECT_REDIRECT` callout |

It is a capture layer and nothing else: no rule engine, no proxy protocol, no
transport, no GUI. Routing stays in whatever client you already run.

**Status: design only. Nothing is implemented.**
[`BLUEPRINT.md`](BLUEPRINT.md) is the design of record — framing, design, and
staged implementation plan, including what has not been verified yet.
