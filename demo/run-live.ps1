param(
    [Parameter(Mandatory = $true)]
    [string]$InputDirectory,
    [ValidateRange(0, 1000)]
    [int]$DelayMs = 75,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$demoInput = (Resolve-Path -LiteralPath $InputDirectory).Path
$requiredFiles = @('bundle.pt', 'frozen.json', 'apis.jsonl', 'scores.jsonl', 'scores.jsonl.meta.json')
foreach ($name in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $demoInput $name) -PathType Leaf)) {
        throw "Demo input is missing $name"
    }
}
$modelManifest = Get-Content -LiteralPath (Join-Path $demoInput 'frozen.json') -Raw | ConvertFrom-Json
$bundleHash = $modelManifest.bundle_sha256
if ($bundleHash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid frozen bundle checksum' }

$runArgs = @(
    'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '512m', '--cpus', '1',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
    '--mount', "type=bind,source=$demoInput,target=/inputs,readonly", 'raneval-model-demo',
    '--model-bundle', '/inputs/bundle.pt', '--bundle-sha256', $bundleHash,
    '--apis', '/inputs/apis.jsonl', '--reference-scores', '/inputs/scores.jsonl',
    '--alpha', '0.05', '--delay-ms', $DelayMs
)
if ($Json) { $runArgs += '--json' }
& docker @runArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
