$ErrorActionPreference = "Stop"

$RustTarget = "x86_64-pc-windows-msvc"
# If you prefer the GNU toolchain, use "x86_64-pc-windows-gnu" instead (requires MinGW-w64).

$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutDir = Join-Path $PSScriptRoot "lib/windows"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "Building fe_age for $RustTarget ..."
# Force /MT static CRT for the Rust staticlib so it links against the same runtime as the /MT-built CLI (avoids LNK2038).
$env:RUSTFLAGS = "-C target-feature=+crt-static"
# Build from the rage workspace so age's workspace dependencies (age-core, etc.) resolve.
Push-Location $WorkspaceRoot
try {
    cargo build --release -p fe_age --target $RustTarget
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally {
    Pop-Location
}

$LibName = "fe_age.lib"
$LibSrc = Join-Path $WorkspaceRoot "target/$RustTarget/release/$LibName"
if (-not (Test-Path $LibSrc)) { throw "Expected library not found: $LibSrc" }

Copy-Item -Force $LibSrc $OutDir
Write-Host "Copied $LibName -> $OutDir"
Write-Host "Done. The CLI CMake will find it via WITH_AGE (default ON)."
