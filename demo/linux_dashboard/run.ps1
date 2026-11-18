param(
    [Parameter(Mandatory)] [string] $InputDirectory,
    [ValidateRange(1024, 65535)] [int] $Port = 8765
)

$ErrorActionPreference = 'Stop'
$fixtures = (Resolve-Path -LiteralPath $InputDirectory).Path
foreach ($name in 'model.onnx', 'frozen.json', 'manifest.json', 'ransomware.jsonl', 'benign.jsonl') {
    if (!(Test-Path -LiteralPath (Join-Path $fixtures $name) -PathType Leaf)) {
        throw "Missing staged dashboard file $name"
    }
}

Write-Host "RanEval dashboard available after startup at http://127.0.0.1:$Port/"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges `
    --pids-limit 48 --memory 384m --cpus 1 `
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 `
    --mount "type=bind,source=$fixtures,target=/inputs,readonly" `
    --publish "127.0.0.1:${Port}:8080" raneval-linux-dashboard
if ($LASTEXITCODE -ne 0) {
    throw "Dashboard container exited with code $LASTEXITCODE"
}
