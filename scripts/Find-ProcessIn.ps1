#╔════════════════════════════════════════════════════════════════════════════════╗
#║                                                                                ║
#║   Find-ProcessIn.ps1                                                           ║
#║                                                                                ║
#╟────────────────────────────────────────────────────────────────────────────────╢
#║   Guillaume Plante <codegp@icloud.com>                                         ║
#║   Code licensed under the GNU GPL v3.0. See the LICENSE file for details.      ║
#╚════════════════════════════════════════════════════════════════════════════════╝



function Find-ProcessIn {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Path to search for process executables')]
        [string]$Path,

        [Parameter(HelpMessage = 'Include child processes of matching executables')]
        [switch]$IncludeChildren
    )

    begin {
        # Ensure path is resolved and normalized
        try {
            $ResolvedPath = (Resolve-Path -Path $Path).ProviderPath.TrimEnd('\')
        } catch {
            Write-Error "Could not resolve path: $Path"
            return
        }

        # Check for admin rights
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error "You must run this script as an administrator."
            return
        }

        # Helper to get normalized path if it exists
        function Get-NormalizedPath {
            param ([string]$rawPath)
            try {
                return (Resolve-Path -Path $rawPath -ErrorAction Stop).ProviderPath
            } catch {
                return $null
            }
        }

        # Build a process map to track parent-child relationships
        $allProcesses = Get-CimInstance Win32_Process
        $processMap = @{}
        foreach ($p in $allProcesses) {
            $processMap[$p.ProcessId] = $p
        }

        $matching = @()
        $matchedIds = @{}
    }

    process {
        foreach ($proc in $allProcesses) {
            $cmd = $proc.CommandLine
            if (-not $cmd) { continue }

            # Extract executable path from command line
            if ($cmd -match '^\s*"([^"]+)"') {
                $exePath = $matches[1]
            } elseif ($cmd -match '^\s*(\S+)') {
                $exePath = $matches[1]
            } else {
                continue
            }

            $normalizedExe = Get-NormalizedPath -rawPath $exePath
            if (-not $normalizedExe) { continue }

            if ($normalizedExe -like "$ResolvedPath\*") {
                $obj = [PSCustomObject]@{
                    Id          = $proc.ProcessId
                    Name        = $proc.Name
                    CommandLine = $cmd
                }
                $matching += $obj
                $matchedIds[$proc.ProcessId] = $true
            }
        }

        if ($IncludeChildren) {
            # Recursively find all children of matched PIDs
            $childQueue = $matchedIds.Keys
            while ($childQueue.Count -gt 0) {
                $process_id = $childQueue[0]
                $childQueue = $childQueue[1..($childQueue.Count - 1)]

                $children = $allProcesses | Where-Object { $_.ParentProcessId -eq $process_id -and -not $matchedIds.ContainsKey($_.ProcessId) }

                foreach ($child in $children) {
                    $matchedIds[$child.ProcessId] = $true
                    $childQueue += $child.ProcessId
                    $matching += [PSCustomObject]@{
                        Id          = $child.ProcessId
                        Name        = $child.Name
                        CommandLine = $child.CommandLine
                    }
                }
            }
        }

        return $matching | Sort-Object Id
    }
}

#Find-ProcessIn -Path 'C:\Windows\System32\' -IncludeChildren
Find-ProcessIn -Path "C:\Program Files\F-Secure\TOTAL\x64" -IncludeChildren
