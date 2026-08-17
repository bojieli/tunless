[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Container,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $TunlessArguments
)

$ErrorActionPreference = 'Stop'

function Get-TunlessUpstream {
    $value = if ($env:TUNLESS_UPSTREAM) { $env:TUNLESS_UPSTREAM } else { '127.0.0.1:7890' }
    for ($index = 0; $index -lt $TunlessArguments.Count; $index++) {
        if ($TunlessArguments[$index] -eq '--upstream' -and $index + 1 -lt $TunlessArguments.Count) {
            $value = $TunlessArguments[$index + 1]
        } elseif ($TunlessArguments[$index] -like '--upstream=*') {
            $value = $TunlessArguments[$index].Substring('--upstream='.Length)
        }
    }
    return $value
}

$running = & docker inspect --format '{{.State.Running}}' $Container
if ($running -ne 'true') { throw "Container is not running: $Container" }
$containerID = & docker inspect --format '{{.Id}}' $Container
$engineOS = & docker info --format '{{.OSType}}'
$upstream = Get-TunlessUpstream

if ($engineOS -eq 'windows') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Windows WFP backend must be run from an elevated PowerShell session.'
    }
    $binary = if ($env:TUNLESS_BINARY) { $env:TUNLESS_BINARY } else { 'tunless.exe' }
    Write-Host 'Windows containers share the host kernel; starting the global WFP backend for host and container TCP flows.'
    & $binary @TunlessArguments --upstream $upstream --backend windows
    exit $LASTEXITCODE
}

if ($engineOS -ne 'linux') { throw "Unsupported Docker engine OS: $engineOS" }

$pidInDesktopVM = & docker inspect --format '{{.State.Pid}}' $Container
if ($pidInDesktopVM -notmatch '^[1-9][0-9]*$') { throw "Container has no usable Linux PID: $Container" }

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$image = if ($env:TUNLESS_DOCKER_IMAGE) { $env:TUNLESS_DOCKER_IMAGE } else { 'tunless:local' }
if ($env:TUNLESS_DOCKER_BUILD -ne 'never') {
    & docker build --quiet --tag $image --file (Join-Path $repositoryRoot 'packaging/docker/Dockerfile') $repositoryRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build the Tunless Docker controller image.' }
} else {
    & docker image inspect $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker controller image is unavailable: $image" }
}

$desktopUpstream = $upstream
if ($upstream -match '^(socks5h?://(?:[^/@]+@)?)(?:127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)$') {
    $desktopUpstream = $Matches[1] + 'host.docker.internal' + $Matches[2]
} elseif ($upstream -match '^(?:127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)$') {
    $desktopUpstream = 'host.docker.internal' + $Matches[1]
}
$bridgeProcess = $null
$bridgeDirectory = $null
if ($env:TUNLESS_DOCKER_BRIDGE -ne 'never' -and $upstream -match '^(socks5h?://([^/@]+@)?)?(127\.0\.0\.1|localhost|\[::1\]):') {
    $bridgeBinary = if ($env:TUNLESS_DOCKER_BRIDGE_BINARY) {
        $env:TUNLESS_DOCKER_BRIDGE_BINARY
    } elseif ($env:TUNLESS_BINARY) {
        $env:TUNLESS_BINARY
    } elseif (Get-Command tunless.exe -ErrorAction SilentlyContinue) {
        (Get-Command tunless.exe).Source
    } else {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
            throw 'Go or TUNLESS_DOCKER_BRIDGE_BINARY is required for Docker Desktop UDP bridging.'
        }
        $bridgeDirectory = Join-Path ([IO.Path]::GetTempPath()) ("tunless-docker-bridge-{0}" -f [guid]::NewGuid())
        New-Item -ItemType Directory $bridgeDirectory | Out-Null
        $built = Join-Path $bridgeDirectory 'tunless.exe'
        & go build -o $built (Join-Path $repositoryRoot 'cmd/tunless')
        if ($LASTEXITCODE -ne 0) { throw 'Failed to build the Docker Desktop host bridge.' }
        $built
    }
    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $reservation.Start()
    $bridgePort = ([Net.IPEndPoint] $reservation.LocalEndpoint).Port
    $reservation.Stop()
    $bridgeProcess = Start-Process -FilePath $bridgeBinary -ArgumentList @(
        '--backend', 'loopback', '--listen', "127.0.0.1:$bridgePort",
        '--upstream', $upstream, '--log-level', 'warn'
    ) -NoNewWindow -PassThru
	$bridgeReady = $false
	for ($attempt = 0; $attempt -lt 20; $attempt++) {
		if ($bridgeProcess.HasExited) { break }
		$probe = [Net.Sockets.TcpClient]::new()
		try {
			$task = $probe.ConnectAsync([Net.IPAddress]::Loopback, $bridgePort)
			if ($task.Wait(100) -and $probe.Connected) { $bridgeReady = $true; break }
		} catch {
			# The listener may still be starting.
		} finally {
			$probe.Dispose()
		}
		Start-Sleep -Milliseconds 50
	}
	if (-not $bridgeReady) {
		if (-not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
		throw 'The Docker Desktop host SOCKS bridge did not become ready.'
	}
    $desktopUpstream = "host.docker.internal:$bridgePort"
    Write-Host "Bridging Docker Desktop TCP/UDP to host upstream $upstream"
}
$controllerName = 'tunless-{0}-{1}' -f $containerID.Substring(0, 12), $PID

# Image builds and host-bridge startup can outlive a fast container restart.
# Refresh the PID immediately before attaching so a recycled PID is never used.
$running = & docker inspect --format '{{.State.Running}}' $Container
$pidInDesktopVM = & docker inspect --format '{{.State.Pid}}' $Container
if ($running -ne 'true' -or $pidInDesktopVM -notmatch '^[1-9][0-9]*$') {
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force }
    throw "Container stopped while preparing Tunless: $Container"
}

$dockerArguments = @(
    'run', '--rm',
    '--name', $controllerName,
    '--label', "com.bojieli.tunless.container=$containerID",
    '--privileged',
    '--pid', 'host',
    '--cgroupns', 'host',
    '--mount', 'type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup',
    '--add-host', 'host.docker.internal:host-gateway',
    $image
) + $TunlessArguments + @(
    '--upstream', $desktopUpstream,
    '--backend', 'linux',
    '--container-pid', $pidInDesktopVM,
    '--container-id', $containerID,
    '--listen', '127.0.0.1:0'
)

try {
    & docker @dockerArguments
    exit $LASTEXITCODE
} finally {
    & docker stop --time 2 $controllerName 2>$null | Out-Null
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force }
}
