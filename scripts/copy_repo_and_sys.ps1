param(
    [Parameter(Mandatory=$true)]
    [string]$RemoteHost,
    [Parameter(Mandatory=$true)]
    [string]$Username,
    [Parameter(Mandatory=$true)]
    [string]$Password,
    [Parameter(Mandatory=$false)]
    [string]$RepoRoot = (Get-Location).Path,
    [Parameter(Mandatory=$false)]
    [string]$RemoteBase = "\\$RemoteHost\c$\Users\Public\UserModeHookHelper",
    [Parameter(Mandatory=$false)]
    [string]$LocalSysPath = "$RepoRoot\x64\Debug\UserModeHookHelper.sys",
    [Parameter(Mandatory=$false)]
    [string]$LocalBootSysPath = "$RepoRoot\x64\Debug\UMHH.BootStart.sys",
    [Parameter(Mandatory=$false)]
    [string]$LocalObCallbackSysPath = "$RepoRoot\x64\Debug\UMHH.ObCallback.sys",
    [Parameter(Mandatory=$false)]
    [string]$LocalObCallbackInfPath = "$RepoRoot\x64\Debug\UMHH.ObCallback.inf",
    [Parameter(Mandatory=$false)]
    [string]$LocalInfPath = "$RepoRoot\x64\Debug\UserModeHookHelper.inf",
    [Parameter(Mandatory=$false)]
    [string]$RemoteSysDestDir = "\\$RemoteHost\c$\Users\Public\UserModeHookHelper\x64\Debug"
)

# Disconnect any previous connection (ignore errors)
try {
    net use "\\${RemoteHost}\c$" /delete *>$null
} catch {
    # ignore
}

# Map share
$mapOutput = net use "\\${RemoteHost}\c$" /user:$Username $Password 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error ("Failed to map share: " + ($mapOutput -join "`n"))
    exit 1
}

# Ensure destination exists
$null = New-Item -Path $RemoteBase -ItemType Directory -Force


# Copy git-tracked and unignored files
$filesRaw = git -C $RepoRoot ls-files --cached --others --exclude-standard -z 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error ("git ls-files failed: " + ($filesRaw -join "`n"))
    try { net use "\\${RemoteHost}\c$" /delete *>$null } catch {}
    exit 1
}
# Determine changed files using git (modified, staged, and untracked).
# This will catch changes even if they are not committed.
$changed = @()
try {
    $modifiedRaw = git -C $RepoRoot ls-files -m -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git ls-files -m failed: {0}" -f ($modifiedRaw -join "`n")); $modifiedRaw = "" }
    $stagedRaw = git -C $RepoRoot diff --name-only --cached -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git diff --cached failed: {0}" -f ($stagedRaw -join "`n")); $stagedRaw = "" }
    $untrackedRaw = git -C $RepoRoot ls-files --others --exclude-standard -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git ls-files --others failed: {0}" -f ($untrackedRaw -join "`n")); $untrackedRaw = "" }

    if ($modifiedRaw) { $changed += ($modifiedRaw -split "`0" | Where-Object {$_ -ne ''}) }
    if ($stagedRaw) { $changed += ($stagedRaw -split "`0" | Where-Object {$_ -ne ''}) }
    if ($untrackedRaw) { $changed += ($untrackedRaw -split "`0" | Where-Object {$_ -ne ''}) }
} catch {
    Write-Warning ("Failed to compute git changed files: {0}" -f $_.Exception.Message)
}

# Detect changes in submodules
$submoduleChanges = @()
$submodules = git -C $RepoRoot submodule foreach --quiet 'echo $path' 2>$null
if ($submodules) {
    foreach ($submodulePath in $submodules) {
        if (![string]::IsNullOrWhiteSpace($submodulePath)) {
            $submoduleChanged = @()
            try {
                # Check for modified files in submodule
                $subModifiedRaw = git -C "$RepoRoot\$submodulePath" ls-files -m -z 2>&1
                if ($LASTEXITCODE -eq 0 -and $subModifiedRaw) {
                    $submoduleChanged += ($subModifiedRaw -split "`0" | Where-Object {$_ -ne ''} | ForEach-Object { Join-Path $submodulePath $_ })
                }
                
                # Check for staged changes in submodule
                $subStagedRaw = git -C "$RepoRoot\$submodulePath" diff --name-only --cached -z 2>&1
                if ($LASTEXITCODE -eq 0 -and $subStagedRaw) {
                    $submoduleChanged += ($subStagedRaw -split "`0" | Where-Object {$_ -ne ''} | ForEach-Object { Join-Path $submodulePath $_ })
                }
                
                # Check for untracked files in submodule
                $subUntrackedRaw = git -C "$RepoRoot\$submodulePath" ls-files --others --exclude-standard -z 2>&1
                if ($LASTEXITCODE -eq 0 -and $subUntrackedRaw) {
                    $submoduleChanged += ($subUntrackedRaw -split "`0" | Where-Object {$_ -ne ''} | ForEach-Object { Join-Path $submodulePath $_ })
                }
            } catch {
                Write-Warning ("Failed to check submodule '$submodulePath': {0}" -f $_.Exception.Message)
            }
            
            if ($submoduleChanged.Count -gt 0) {
                $submoduleChanges += $submoduleChanged
                Write-Output ("Detected $($submoduleChanged.Count) changed file(s) in submodule: $submodulePath")
            }
        }
    }
}

# Combine parent repo changes and submodule changes
$allChanges = @()
if ($changed.Count -gt 0) { $allChanges += $changed }
if ($submoduleChanges.Count -gt 0) { $allChanges += $submoduleChanges }

if ($allChanges.Count -gt 0) {
    # Remove duplicates and normalize
    # Filter out build intermediates and unnecessary files
    $exclusionPatterns = @(
        '*.sln',         # Visual Studio solution files
        '*.obj',         # Object files
        '*.pdb',         # Debug symbols
        '*.ilk',         # Linker intermediate files
        '*.exp',         # Export files
        '*.lib',         # Library files (unless source controlled)
        '*.exe',         # Executables (build output)
        '*.dll',         # DLLs (build output)
        '*.tmp',         # Temporary files
        '*.log',         # Log files
        '*~',            # Backup files
        '*.orig',        # Original backup files
        'x64\*',          # x64 build output directory
        'x86\*',          # x86 build output directory
        'Debug\*',       # Debug build output
        'Release\*',     # Release build output
        'bin\*',         # Binary output directories
        'obj\*',         # Object file directories
        '.vs\*',         # Visual Studio user-specific files
        '.vscode\*'      # VS Code user-specific files (if not source controlled)
    )
    
    $files = $allChanges | Where-Object {
        $file = $_
        $shouldInclude = $true
        
        # Check each exclusion pattern
        foreach ($pattern in $exclusionPatterns) {
            # Handle wildcard patterns
            if ($pattern -like '*\*') {
                # Directory-based pattern (e.g., x64/*, Debug/*)
                $dirPattern = $pattern.TrimEnd('*')
                if ($file -like "$dirPattern*" -or $file -like "*\$dirPattern*") {
                    $shouldInclude = $false
                    break
                }
            } elseif ($pattern -like '**') {
                # Simple extension pattern (e.g., *.obj)
                $extension = $pattern.TrimStart('*')
                if ($file -like "*$extension") {
                    $shouldInclude = $false
                    break
                }
            } else {
                # Exact match or simple pattern
                if ($file -like $pattern) {
                    $shouldInclude = $false
                    break
                }
            }
        }
        
        return $shouldInclude
    } | Sort-Object -Unique
    
    $filteredCount = $allChanges.Count - $files.Count
    if ($filteredCount -gt 0) {
        Write-Output "Filtered out $filteredCount build/unnecessary file(s)"
    }
} else {
    # Fallback: if no changes detected, do nothing (skip copying tracked files)
    Write-Output "No changed or untracked files detected by git; nothing to copy."
}

foreach ($f in $files) {
    $src = Join-Path $RepoRoot $f
    if (!(Test-Path $src)) { Write-Warning ("Skipping missing file: {0}" -f $src); continue }
    $dst = Join-Path $RemoteBase $f
    $dir = Split-Path $dst -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
        Write-Output ("Copied: $f")
    } catch {
        Write-Warning ("Copy failed (ignored): {0} -> {1} : {2}" -f $src, $dst, $_.Exception.Message)
    }
}

# Ensure remote driver destination directory exists
try {
    New-Item -Path $RemoteSysDestDir -ItemType Directory -Force | Out-Null
} catch {
    Write-Warning ("Failed to create remote sys directory: {0} : {1}" -f $RemoteSysDestDir, $_.Exception.Message)
}

# Copy both driver .sys files if present: UMHH.BootStart.sys and UserModeHookHelper.sys
$sysFiles = @($LocalBootSysPath, $LocalSysPath, $LocalObCallbackSysPath, $LocalInfPath, $LocalObCallbackInfPath)

foreach ($local in $sysFiles) {
    $leaf = Split-Path $local -Leaf
    if (Test-Path $local) {
        $dst = Join-Path $RemoteSysDestDir $leaf
        try {
            Copy-Item -LiteralPath $local -Destination $dst -Force -ErrorAction Stop
            Write-Output ("DriverSysCopied: {0} -> {1}" -f $local, $dst)
        } catch {
            Write-Warning ("Driver copy failed (ignored): {0} -> {1} : {2}" -f $local, $dst, $_.Exception.Message)
            Write-Output ("DriverSysCopyIgnored: {0} -> {1}" -f $local, $dst)
        }
    } else {
        Write-Output ("DriverSysNotFound: {0}" -f $local)
    }
}

# Unmap (ignore errors)
try {
    net use "\\${RemoteHost}\c$" /delete *>$null
} catch {
    # ignore
}
try {
    # Update remote marker to now (UTC) if we can write to the remote base
    $nowUtc = [DateTime]::UtcNow
    $markerContent = $nowUtc.ToString("o")
    try {
        $markerPathDir = Split-Path $markerFile -Parent
        if (!(Test-Path $markerPathDir)) { New-Item -ItemType Directory -Path $markerPathDir -Force | Out-Null }
        Set-Content -LiteralPath $markerFile -Value $markerContent -Force -ErrorAction Stop
        Write-Output ("Updated remote marker: $markerFile -> $markerContent")
    } catch {
        Write-Warning ("Failed to update remote marker file: {0}" -f $_.Exception.Message)
    }
} catch {
    # ignore marker update errors
}
Write-Output "Done"
