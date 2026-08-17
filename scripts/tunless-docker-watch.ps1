[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $TunlessArguments
)

$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'tunless-docker.ps1'
$engineOS = & docker info --format '{{.OSType}}'

if ($engineOS -eq 'windows') {
    $first = & docker ps --quiet | Select-Object -First 1
    if (-not $first) { throw 'No running Windows container was found.' }
    & $helper $first @TunlessArguments
    exit $LASTEXITCODE
}
if ($engineOS -ne 'linux') { throw "Unsupported Docker engine OS: $engineOS" }

# Build the shared Linux controller once before jobs fan out. Child jobs inherit
# the environment and only inspect the image, avoiding concurrent rebuilds.
if ($env:TUNLESS_DOCKER_BUILD -ne 'never') {
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    $image = if ($env:TUNLESS_DOCKER_IMAGE) { $env:TUNLESS_DOCKER_IMAGE } else { 'tunless:local' }
    & docker build --quiet --tag $image --file (Join-Path $repositoryRoot 'packaging/docker/Dockerfile') $repositoryRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build the Tunless Docker controller image.' }
    $env:TUNLESS_DOCKER_BUILD = 'never'
}

$jobs = @{}
$requiredLabel = if ($env:TUNLESS_CONTAINER_LABEL) { $env:TUNLESS_CONTAINER_LABEL } else { $env:TUNLESS_DOCKER_LABEL }
if ($requiredLabel -and $requiredLabel -notmatch '^[A-Za-z0-9_.:/-]+$') {
    throw "Docker label contains unsupported characters: $requiredLabel"
}
Write-Host 'Watching Docker containers for transparent Tunless attachment.'
if ($requiredLabel) { Write-Host "Requiring Docker label: $requiredLabel" }

try {
    while ($true) {
        $running = @(& docker ps --quiet)
        foreach ($id in $running) {
            $controllerLabel = & docker inspect --format '{{index .Config.Labels "com.bojieli.tunless.container"}}' $id 2>$null
            if ($controllerLabel) { continue }
            if ($requiredLabel) {
                $format = "{{index .Config.Labels `"$requiredLabel`"}}"
                $labelValue = & docker inspect --format $format $id 2>$null
                if (-not $labelValue -or $labelValue -eq '<no value>') { continue }
            }
            if ($jobs.ContainsKey($id) -and $jobs[$id].State -in @('Running', 'NotStarted')) { continue }
            if ($jobs.ContainsKey($id)) { Remove-Job -Job $jobs[$id] -Force; $jobs.Remove($id) }
            Write-Host "Attaching Tunless to container $($id.Substring(0, 12))"
            $argumentJSON = ConvertTo-Json -Compress -InputObject @($TunlessArguments)
            $jobs[$id] = Start-Job -ScriptBlock {
                param($script, $container, $json)
                $arguments = @(ConvertFrom-Json $json)
                & $script $container @arguments
            } -ArgumentList $helper, $id, $argumentJSON
        }
        foreach ($id in @($jobs.Keys)) {
            if ($id -notin $running -or $jobs[$id].State -notin @('Running', 'NotStarted')) {
                Receive-Job -Job $jobs[$id]
                Stop-Job -Job $jobs[$id] -ErrorAction SilentlyContinue
                Remove-Job -Job $jobs[$id] -Force
                $jobs.Remove($id)
            }
        }
        Start-Sleep -Seconds 1
    }
} finally {
    foreach ($job in $jobs.Values) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force
    }
}
