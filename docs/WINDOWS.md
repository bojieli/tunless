# Windows

The Windows backend is a WFP ALE connect-redirect callout with a Go service
behind it — the architecture is implemented, but it has never run on a Windows
machine. **Nothing on this page is runtime-qualified: treat it as
implementation source, not a shippable driver.**

*Audience: developers; nothing here is release-qualified.*

## Status

The WFP filters include `IPPROTO_TCP`. UDP is deliberately direct:
intercepting it without a tested datagram service would turn an incomplete
feature into a connectivity failure. Captured TCP connections to port 53 use
the shared numeric trusted-resolver override through SOCKS5, including the
`--disable-dns-override` switch. Ordinary Windows DNS is normally UDP, so this
does not qualify as complete Windows DNS protection until the UDP datapath is
implemented and runtime-tested.

## Architecture

The Windows implementation consists of:

- `windows/driver/tunless.c`: WFP callout at
  `ALE_CONNECT_REDIRECT_V4`/`V6`, registered with the classify-context-aware
  callback API;
- a dynamic WFP engine session tied to the service's exclusive device handle;
- redirect-state checks to avoid repeated self-redirection;
- redirect context containing the original `SOCKADDR_STORAGE`, PID, and ALE app
  ID;
- `backend/windows`: TCP listeners that query both the redirect context and the
  opaque connection redirect records, then emit the portable Go `Flow`;
- the SOCKS emitter installs those records with
  `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` through `net.Dialer.Control`,
  before the outbound socket connects. This preserves WFP redirect history and
  avoids loops with another redirecting product.

The Go service opens `\\.\Tunless`, sends its PID and listener port, starts the
dynamic filters, and keeps the handle open. Process death closes the handle;
the driver's cleanup path closes the dynamic engine session, removing every
filter. Driver unload also unregisters both callouts and destroys the redirect
handle.

## Building

Build on an isolated Windows 11 driver-development VM with Visual Studio and
the WDK:

```powershell
msbuild windows\driver\tunless.vcxproj /p:Configuration=Release /p:Platform=x64
go build -o tunless.exe .\cmd\tunless
```

## Driver signing

Windows 10 and later load a kernel-mode driver only when Microsoft itself has
signed it. `tunless.sys` is kernel-mode by necessity — the WFP
`ALE_CONNECT_REDIRECT_V4`/`V6` layers have no user-mode equivalent — so this
constrains every path that captures traffic, not just a packaged installer.

**This project holds no EV certificate and no Partner Center account, and is
not obtaining either in the current phase.** No signed `tunless.sys` is
published or planned. Contributors test-sign their own builds for their own
test machines.

### Test signing

Driver work is done against a WDK-generated test certificate on a
snapshot-capable VM with `bcdedit /set testsigning on`. This requires no
purchase and no Microsoft account. Install the test certificate only in that
VM, enable Driver Verifier for `tunless.sys`, and run the redirect-context
fuzz/conformance suite before any physical-machine trial. Do not enable test
signing on a machine you depend on.

### What production signing would require

Recorded so the cost is visible before anyone plans around it, not as work in
progress:

| Step | Requirement |
| --- | --- |
| Partner Center registration | EV code signing certificate from one of Microsoft's listed CAs |
| Key storage | EV private keys must live in a FIPS 140-2 Level 2 HSM or token |
| Submission | Sign the CAB with a registered certificate and upload it to Partner Center |
| Signature | Microsoft attestation-signs and returns the driver; that signature is the one Windows enforces |
| Windows Server | Rejects attestation-signed drivers; Server support would require full HLK/WHQL |

Two details are easy to get backwards. The EV certificate is an identity gate
for the *account*: Microsoft's registration prerequisites state you need it to
register and "don't need to sign your driver with it." And Azure Artifact
Signing (formerly Trusted Signing) is not a substitute — it issues no EV
certificates and does not sign kernel-mode drivers, which Microsoft documents
as remaining Partner Center's scope.

Preproduction signing is the intermediate option for a driver that must be
tested with Secure Boot enabled on provisioned devices. It also runs through
Partner Center and carries the same EV prerequisite.

Comparable open-source drivers (Wintun, WinFsp, Npcap, OpenVPN tap-windows6)
all resolve this the same way: the project holds an EV certificate, submits to
Partner Center, and ships prebuilt signed binaries because downstream builders
cannot sign for themselves. Adopting that model here would be a governance
decision — it concentrates release capability in whoever holds the
certificate — and is deliberately deferred, not assumed.

## Docker on Windows

For Docker Desktop running Linux containers, use:

```powershell
$env:TUNLESS_UPSTREAM = '127.0.0.1:7890'
.\scripts\tunless-docker.ps1 my-container
```

This builds a Linux controller image, gives only that controller access to the
Desktop VM's host PID/cgroup namespaces, and attaches Linux eBPF to the target
container. A temporary host loopback bridge makes SOCKS TCP and UDP association
relay ports reachable through `host.docker.internal`. The application image,
environment, routes, and capabilities are not changed. Use
`tunless-docker-watch.ps1` to cover all containers or set
`TUNLESS_DOCKER_LABEL=devcontainer.local_folder` to cover Dev Containers.

When Docker runs Windows containers, the script starts the global elevated WFP
backend. Windows containers share the host kernel; the driver's filters have no
network-compartment condition, so the intended scope is host and container TCP
through the same service. This exact path still requires the Windows runtime
gate below and is not represented as tested.

## Release gates

Current gate: the Go service cross-compiles, but this environment has no
Windows/WDK host. The driver has not been compiled, loaded, fuzzed,
verifier-run, attestation-signed, or tested with Secure Boot. Treat it as
implementation source, not a shippable driver.

The signing portion of that gate is deferred by decision rather than pending
work: production signing is out of scope for this phase, as recorded under
[Driver signing](#driver-signing). The build, load, fuzz, Driver Verifier,
runtime, coexistence, and rollback portions remain open and are unaffected.
Windows stays recorded as unsupported; the gate is not weakened to match the
deferral.

## Deferred to contributors

The maintainer has no Windows host, and no amount of care on Linux or macOS
substitutes for one: a driver that has never been compiled by the WDK, loaded
by a kernel, or run under Driver Verifier is source code with a plausible
shape, and saying otherwise would be the one claim this project cannot back.
So the Windows gates are deferred to anyone who has the hardware and wants to
close them, rather than held open indefinitely against a machine that does not
exist.

What is needed, in the order it becomes useful:

1. **Build.** Compile the callout driver with a current WDK and record the
   toolchain versions. This alone tells everyone whether the source is
   buildable, which nobody currently knows.
2. **Load and run.** Install on a test machine with test-signing enabled,
   exercise TCP capture against a SOCKS5 upstream, and record what works.
3. **Driver Verifier.** Run the standard flags across a reboot cycle and
   record the result, because a callout that faults takes the machine with it.
4. **UDP.** UDP is intentionally left direct today; capturing it needs design
   work as well as testing.
5. **Coexistence and rollback.** Behaviour alongside other WFP filters, and
   what happens when the service dies with filters installed.
6. **Signing.** Production signing needs an EV certificate and a Partner
   Center account with Microsoft attestation. That is an organisational
   commitment rather than a technical one, and it is the last step, not the
   first.

Steps 1 through 5 need only a Windows machine and are worth doing on their own:
each closes a specific unknown and can be contributed independently. Open an
issue describing what you ran and what happened — including a failure, which is
more useful than silence. Until at least steps 1 through 3 are recorded by
somebody, Windows stays documented as unsupported and no binary is published.

See also: [../README.md](../README.md) · [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
