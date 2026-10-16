# ==================================================================
# Script: build.ps1
# Description: Builds Cloudflare Workers, obfuscates them with a
#              per-build ChaCha20 string cipher, verifies that nothing
#              was lost or broken, and packs them into zip files.
# Creator: vadash
# Version: 2.0.0
#
# Pipeline (per attempt):
#   wrangler dry-run  -> uglify (AST-level minify + drop_console)
#   -> obfuscate.mjs  (js-confuser + ChaCha20 string cipher)
#   -> verify.mjs     (data-loss / plaintext-leak / syntax gate)
#   -> smoke.mjs      (behaviour must equal the pre-obfuscation build)
#   -> 7z
#
# Tuning knobs are environment variables read by obfuscate.mjs:
#   HARDEN_STRINGS (true) HARDEN_OPAQUE (0.2) HARDEN_CFF (0.05)
#   HARDEN_INTEGRITY (true) HARDEN_ANTIDEBUG (false) HARDEN_SELFDEFENDING (false)
# ==================================================================

# Constants
$howManyToBuild = 20
$sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
$workerPath = ".\output\_worker.js"
$referencePath = ".\output\_worker.reference.js"
$zipDir = ".\output\zips"
$smokeEveryBuild = $true   # set to $false to only run the behavioural gate once
$maxRetries = $howManyToBuild * 5

#region Helper Functions

function Write-Status {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Ensure-OutputDirectory {
    param([string]$Path = ".\output\")
    if (!(Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        Write-Status "Created output directory: $Path"
    }
}

# Runs an external command and turns a non-zero exit code into a PowerShell
# exception, so the retry loop can react to it. Output is inherited (not piped)
# so this also works in constrained/CI shells.
function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$Label
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NodeScript {
    param([string]$Script)
    Invoke-Checked -Command "node" -Arguments @($Script) -Label "node $Script"
}

#endregion

#region Core Functions

function Invoke-Uglify {
    param([string]$Path)
    # AST-level work only: console calls are removed by the compressor and
    # whitespace by the minifier - no regex is ever run over the source text.
    Invoke-Checked -Command "node" -Arguments @(
        "node_modules/uglify-js/bin/uglifyjs", $Path, "-o", $Path,
        "--compress", "drop_console=true",
        "--mangle",
        "-O", "keep_quoted_props"
    ) -Label "uglify-js" | Out-Null
    Write-Status "Minified '$Path' with uglify-js (drop_console, mangle)"
}

#endregion

#region Build Process

function Invoke-WranglerBuild {
    try {
        Invoke-Checked -Command "node" -Arguments @(
            "node_modules/wrangler/bin/wrangler.js", "deploy", "--dry-run", "--outdir", "output"
        ) -Label "wrangler dry-run" | Out-Null
        if (!(Test-Path ".\output\worker.js")) {
            throw "Wrangler build failed - no output file created"
        }
        Write-Status "Successfully built worker with wrangler"
    }
    catch {
        Write-Status "Wrangler build failed: $_" -Level "ERROR"
        throw
    }
}

function Initialize-WorkerFile {
    Rename-Item -Path ".\output\worker.js" -NewName "_worker.js" -Force
    Write-Status "Renamed worker.js to _worker.js"
}

function Build-Worker {
    try {
        Ensure-OutputDirectory
        Invoke-WranglerBuild
        Initialize-WorkerFile
        Invoke-Uglify -Path $workerPath

        # The reference is what every obfuscated build is compared against:
        # same wrangler output, same uglify pass, only js-confuser missing.
        Copy-Item -Path $workerPath -Destination $referencePath -Force
        Write-Status "Saved pre-obfuscation reference to '$referencePath'"
    }
    catch {
        Write-Status "Build failed: $_" -Level "ERROR"
        throw
    }
}

#endregion

#region Compression Functions

function Confirm-7ZipAvailable {
    if (!(Test-Path $sevenZipPath)) {
        Write-Status "7-Zip not found at $sevenZipPath" -Level "ERROR"
        exit 1
    }
    Write-Status "7-Zip found at $sevenZipPath"
}

function Stop-7ZipProcesses {
    # Only touch taskkill when the GUI is actually running: its stderr would
    # otherwise be pure noise, and piping native output breaks constrained shells.
    if (Get-Process -Name 7zFM -ErrorAction SilentlyContinue) {
        & taskkill /f /im 7zFM.exe
        Write-Status "Terminated 7-Zip GUI processes"
    }
}

function Compress-WorkerFile {
    param(
        [string]$Path,
        [string]$OutputDir
    )
    Ensure-OutputDirectory -Path $OutputDir
    $zipName = "worker-$(New-Guid).zip"

    Invoke-Checked -Command $sevenZipPath -Arguments @(
        "a", "-tzip", "-mx=0", "$OutputDir\$zipName", $Path
    ) -Label "7-Zip" | Out-Null
    Write-Status "Created compressed worker: $zipName"
}

#endregion

#region Main Execution

try {
    Confirm-7ZipAvailable
    Stop-7ZipProcesses
    Remove-Item -Recurse -Force -Path .\output\ -ErrorAction SilentlyContinue

    # Guard the cipher itself before spending time on a build.
    Invoke-NodeScript "tools/cipher.test.mjs"

    Build-Worker

    $successCount = 0
    $retryCount = 0

    while ($successCount -lt $howManyToBuild -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            Write-Status "Build attempt $retryCount (successful so far: $successCount/$howManyToBuild)"

            Copy-Item -Path $referencePath -Destination $workerPath -Force
            Invoke-NodeScript "obfuscate.mjs"
            Invoke-NodeScript "verify.mjs"
            if ($smokeEveryBuild -or $successCount -eq 0) {
                Invoke-NodeScript "smoke.mjs"
            }

            Compress-WorkerFile -Path $workerPath -OutputDir $zipDir

            $successCount++
            Write-Status "Successfully created worker $successCount/$howManyToBuild" -Level "SUCCESS"
        }
        catch {
            Write-Status "Build attempt $retryCount rejected: $_" -Level "WARNING"
        }
    }

    # Keep only the zips
    Get-ChildItem -Path .\output\ -Exclude zips | Remove-Item -Recurse -Force

    if ($successCount -eq $howManyToBuild) {
        Write-Status "Build process completed successfully" -Level "SUCCESS"
    }
    else {
        Write-Status "Build process completed with only $successCount/$howManyToBuild successful builds" -Level "WARNING"
    }
}
catch {
    Write-Status "Critical error in main execution: $_" -Level "ERROR"
    pause
    exit 1
}

#endregion
