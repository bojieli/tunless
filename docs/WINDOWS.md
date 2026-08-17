# Windows WFP backend

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
  `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` through `net.Dialer.Control`, before
  the outbound socket connects. This preserves WFP redirect history and avoids
  loops with another redirecting product.

The WFP filters include `IPPROTO_TCP`. UDP is deliberately direct: intercepting
it without a tested datagram service would turn an incomplete feature into a
connectivity failure.

Build on an isolated Windows 11 driver-development VM with Visual Studio and the
WDK:

```powershell
msbuild windows\driver\tunless.vcxproj /p:Configuration=Release /p:Platform=x64
go build -o tunless.exe .\cmd\tunless
```

The driver must then be catalog-signed/attestation-signed before normal loading
with Secure Boot. Development tests should use a snapshot-capable VM, install
the test certificate only in that VM, enable Driver Verifier for `tunless.sys`,
and run the redirect-context fuzz/conformance suite before any physical-machine
trial.

The Go service opens `\\.\Tunless`, sends its PID and listener port, starts the
dynamic filters, and keeps the handle open. Process death closes the handle;
the driver's cleanup path closes the dynamic engine session, removing every
filter. Driver unload also unregisters both callouts and destroys the redirect
handle.

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

Current gate: the Go service cross-compiles, but this environment has no
Windows/WDK host. The driver has not been compiled, loaded, fuzzed, verifier-run,
attestation-signed, or tested with Secure Boot. Treat it as implementation
source, not a shippable driver.
