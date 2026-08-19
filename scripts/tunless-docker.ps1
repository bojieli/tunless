[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Container,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $TunlessArguments
)

$ErrorActionPreference = 'Stop'
if ($Container.StartsWith('-')) { throw 'Container name or ID must not start with a hyphen.' }

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

$containerState = & docker inspect --format '{{.Id}} {{.State.Running}} {{.State.Pid}}' -- $Container
$containerFields = @($containerState -split '\s+')
if ($containerFields.Count -ne 3 -or $containerFields[0] -notmatch '^[0-9a-f]{12,64}$') {
    throw "Docker returned invalid container identity data: $Container"
}
$containerID, $running, $pidInDesktopVM = $containerFields
if ($running -ne 'true') { throw "Container is not running: $Container" }
$engineOS = & docker info --format '{{.OSType}}'
$upstream = Get-TunlessUpstream
$controllerDNSArguments = @()
$hasDNSUpstream = $false
$hasDNSOverridePolicy = $false
foreach ($argument in $TunlessArguments) {
    if ($argument -eq '--dns-upstream' -or $argument -like '--dns-upstream=*') { $hasDNSUpstream = $true }
    if ($argument -eq '--disable-dns-override' -or $argument -like '--disable-dns-override=*') { $hasDNSOverridePolicy = $true }
}
if (-not $hasDNSUpstream -and $env:TUNLESS_DNS_UPSTREAM) {
    $controllerDNSArguments += @('--dns-upstream', $env:TUNLESS_DNS_UPSTREAM)
}
if (-not $hasDNSOverridePolicy -and $env:TUNLESS_DISABLE_DNS_OVERRIDE) {
    $controllerDNSArguments += "--disable-dns-override=$($env:TUNLESS_DISABLE_DNS_OVERRIDE)"
}

if ($engineOS -eq 'windows') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Windows WFP backend must be run from an elevated PowerShell session.'
    }
    $binary = if ($env:TUNLESS_BINARY) { $env:TUNLESS_BINARY } else { 'tunless.exe' }
    Write-Host 'Windows containers share the host kernel; starting the global WFP backend for host and container TCP flows.'
    & $binary @TunlessArguments @controllerDNSArguments --upstream $upstream --backend windows
    exit $LASTEXITCODE
}

if ($engineOS -ne 'linux') { throw "Unsupported Docker engine OS: $engineOS" }

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
  try {
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
        '--upstream', $upstream, '--disable-dns-override', '--log-level', 'warn'
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
  } catch {
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    throw
  }
}
$controllerName = 'tunless-{0}-{1}' -f $containerID.Substring(0, 12), $PID

# Image builds and host-bridge startup can outlive a fast container restart.
# Refresh the PID immediately before attaching so a recycled PID is never used.
$currentState = & docker inspect --format '{{.Id}} {{.State.Running}} {{.State.Pid}}' -- $Container
$currentFields = @($currentState -split '\s+')
if ($currentFields.Count -ne 3 -or $currentFields[0] -ne $containerID -or
    $currentFields[1] -ne 'true' -or $currentFields[2] -notmatch '^[1-9][0-9]*$') {
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force }
    throw "Container stopped or was replaced while preparing Tunless: $Container"
}
$pidInDesktopVM = $currentFields[2]

$controllerStateDirectory = Join-Path ([IO.Path]::GetTempPath()) ("tunless-controller-{0}" -f [guid]::NewGuid())
try {
    New-Item -ItemType Directory $controllerStateDirectory | Out-Null
} catch {
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    throw
}
$controllerCIDFile = Join-Path $controllerStateDirectory 'cid'

$dockerArguments = @(
    'run', '--rm',
    '--name', $controllerName,
    '--cidfile', $controllerCIDFile,
    '--label', "com.bojieli.tunless.container=$containerID",
    '--privileged',
    '--pid', 'host',
    '--cgroupns', 'host',
    '--mount', 'type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup',
    '--add-host', 'host.docker.internal:host-gateway',
    $image
) + $TunlessArguments + $controllerDNSArguments + @(
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
    if (Test-Path -LiteralPath $controllerCIDFile -PathType Leaf) {
        $controllerID = (Get-Content -LiteralPath $controllerCIDFile -Raw).Trim()
        if ($controllerID -match '^[0-9a-f]{12,64}$') {
            & docker stop --time 2 $controllerID 2>$null | Out-Null
        }
        Remove-Item -LiteralPath $controllerCIDFile -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $controllerStateDirectory -Force -ErrorAction SilentlyContinue
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { Stop-Process -Id $bridgeProcess.Id -Force }
    if ($bridgeDirectory) { Remove-Item -LiteralPath $bridgeDirectory -Recurse -Force }
}
