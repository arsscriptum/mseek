#╔════════════════════════════════════════════════════════════════════════════════╗
#║                                                                                ║
#║   Install.ps1                                                                  ║
#║                                                                                ║
#╟────────────────────────────────────────────────────────────────────────────────╢
#║   Guillaume Plante <codegp@icloud.com>                                         ║
#║   Code licensed under the GNU GPL v3.0. See the LICENSE file for details.      ║
#╚════════════════════════════════════════════════════════════════════════════════╝

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $False, HelpMessage = "Platform")]
    [ValidateSet("x86", "x64")]
    [string]$Platform = "x64",

    [Parameter(Mandatory = $False, HelpMessage = "Configuration")]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory = $False, HelpMessage = "AddToPath")]
    [switch]$AddToPath
)



function Install-Memgrep {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $False, HelpMessage = "Platform")]
        [ValidateSet("x86", "x64")]
        [string]$Platform = "x64",

        [Parameter(Mandatory = $False, HelpMessage = "Configuration")]
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release",

        [Parameter(Mandatory = $False, HelpMessage = "AddToPath")]
        [switch]$AddToPath
    )

    try {
        # Construct binary path
        $BinPath = "bin\{0}\{1}\mseek.exe" -f $Platform, $Configuration
        $RootPath = (Resolve-Path -Path "$PSScriptRoot\..").Path
        $ExeResolvedPath = Resolve-Path -Path "$RootPath\$BinPath" -ErrorAction Stop
        $ExePath = $ExeResolvedPath.Path
        $ExeDirectory = (Get-Item $ExePath).DirectoryName

        # Validate $ENV:Programs
        if (-not $ENV:Programs -or -not (Test-Path -Path $ENV:Programs)) {
            throw "Environment variable 'Programs' is not defined or path does not exist: $ENV:Programs"
        }

        # Create install path if it doesn't exist
        $InstallPath = Join-Path -Path $ENV:Programs -ChildPath "memseek"
        if (-not (Test-Path -Path $InstallPath)) {
            Write-Verbose "Creating installation directory: $InstallPath"
            New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        }
        $CopiedFiles=0

        # Copy all .dll and .exe files from $ExeDirectory to $InstallPath
        Get-ChildItem -Path $ExeDirectory -File | Where Extension -Match "exe|dll" | ForEach-Object {
            $dest = Join-Path -Path $InstallPath -ChildPath $_.Name
            Write-Host "Copying $($_.Name) to $InstallPath"
            Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction Stop
            $CopiedFiles++
        }
        if(!$CopiedFiles){
            throw "no files copied"
        }

        Write-Host "$CopiedFiles Files Copied. memgrep installed successfully to: $InstallPath" -f DarkGreen

        # Add to user PATH if requested
        if ($AddToPath) {
            $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($currentUserPath -notlike "*$InstallPath*") {
                $newUserPath = "$currentUserPath;$InstallPath"
                [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
                Write-Host "Install path added to user PATH."
            }
            else {
                Write-Host "Install path already exists in user PATH."
            }
        }
    }
    catch {
        Write-Error "Installation failed: $_"
    }
}

Write-Output "==================================="
Write-Output " Install.ps1"
Write-Output "==================================="
Install-Memgrep -Platform $Platform -Configuration $Configuration -AddToPath:$AddToPath
Write-Output "==================================="