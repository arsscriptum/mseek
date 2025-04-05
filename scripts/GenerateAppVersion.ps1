#╔════════════════════════════════════════════════════════════════════════════════╗
#║                                                                                ║
#║   GenerateAppVersion.ps1                                                       ║
#║                                                                                ║
#╟────────────────────────────────────────────────────────────────────────────────╢
#║   Guillaume Plante <codegp@icloud.com>                                         ║
#║   Code licensed under the GNU GPL v3.0. See the LICENSE file for details.      ║
#╚════════════════════════════════════════════════════════════════════════════════╝

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $False)]
    [switch]$Update
)

$DefaultVersionValue = "1.0.0"

$RootPath = (Resolve-Path -Path "$PSScriptRoot\..").Path

Push-Location "$RootPath"

$ConfigPath = (Resolve-Path -Path "$RootPath\config").Path
$SourcesPath = (Resolve-Path -Path "$RootPath\src").Path
$BuildInfo = Join-Path "$RootPath" "build.nfo" 
$GeneratedVersionSourceFile = Join-Path "$SourcesPath" "version.cpp" 

$VerFileContent = @"
//==============================================================================
//
//  version.cpp
//
//==============================================================================
//  automatically generated on {0}
//==============================================================================

#include "stdafx.h"
#include <string.h>
#include "version.h"

#ifdef _RELEASE
unsigned int memgrep::version::major  = {1};
unsigned int memgrep::version::minor  = {2};
unsigned int memgrep::version::build  = {3};
unsigned int memgrep::version::rev    = release;
std::string  memgrep::version::sha    = `"{5}`";
std::string  memgrep::version::branch = `"{6}`";
#else
unsigned int memgrep::version::major  = {1};
unsigned int memgrep::version::minor  = {2};
unsigned int memgrep::version::build  = {3};
unsigned int memgrep::version::rev    = {4};
std::string  memgrep::version::sha    = `"{5}`";
std::string  memgrep::version::branch = `"{6}`";
#endif // _RELEASE
"@

$VersionRegexPattern ="(?<fullver>(?<major>\d+)+\.(?<minor>\d+)+\.(?<build>\d+)+(?<dot>[\.])*(?<revision>[\d])*)"
$GitCmd = Get-Command 'git.exe' -ErrorAction Stop
$GitExe = $GitCmd.Source
$BranchName = &"$GitExe" 'rev-parse' '--abbrev-ref' 'HEAD'

# Get the Most Recent Tag (Sorted by Date)
[string[]]$RecenTags = (&"$GitExe" tag --sort=-creatordate) -as [string[]]

$HasValidTag = $False 
$MostRecentValidTag = ""

if(([string]::IsNullOrEmpty($RecenTags) -eq $False) -And ($RecenTags -is [string[]])){
    $tmp_latest = $RecenTags | Select -First 1
    if($tmp_latest -match $VersionRegexPattern){
        Write-Output "Found most recent tag! It's valid! $tmp_latest"
        $HasValidTag = $True 
        $MostRecentValidTag = $tmp_latest
    }else{
        ForEach($t in $RecenTags){
            if($t -match $VersionRegexPattern){
                Write-Output "Found a valid tag! It's not the most recent though! $t"
                $HasValidTag = $True 
                $MostRecentValidTag = $t
            }else{
                Write-Output "Invalid version tag: $t"
            }
        }
    }
}else{
    Write-Output "No tags in repo"
}

[bool]$ShortHash = $True 
$CommitHash = &"$GitExe" 'rev-parse' 'HEAD'
if($ShortHash){
    $CommitHash = $CommitHash.Substring(0,8)
}

# Get the Shortened Commit Hash (7 characters)





if(-not(Test-Path -Path "$BuildInfo")){
    Write-Warning "missing version info file, generating a new one"
    New-Item -Path "$BuildInfo" -ItemType file -Force -ErrorAction Ignore | Out-Null
    if($HasValidTag){
        Set-Content -Path "$BuildInfo" -Value "$MostRecentValidTag"
    }else{
        Set-Content -Path "$BuildInfo" -Value "$DefaultVersionValue"
    }

    if (&"$GitExe" 'status' '--porcelain' | Select-String "^\?\? build.nfo") {
        Write-Warning "build.nfo is untracked ignoring index"
        &"$GitExe" 'update-index' '--assume-unchanged' "$BuildInfo"
    } else {
        Write-Host "build.nfo is tracked or ignored"
    }
}

[string[]]$FileData = (Get-Content -Path "$BuildInfo") -as [string[]]
[string]$VersionString = $FileData[0]

Write-Output "==================================="
Write-Output " GenerateAppVersion.ps1"
Write-Output "==================================="
#Write-Output " RootPath      $RootPath"
#Write-Output " ConfigPath    $ConfigPath"
#Write-Output " BuildInfo     $BuildInfo"
Write-Output " BranchName    $BranchName"
Write-Output " RecenTag      $MostRecentValidTag"
Write-Output " CommitHash    $CommitHash"

if($VersionString -match $VersionRegexPattern){

    [version]$v = $VersionString

    [int]$NewRev = $v.Revision + 1
    $CurrentTime = [datetime]::now.GetDateTimeFormats()[13]
    [version]$LatestVersion = [version]::new($Matches.major, $Matches.minor, $Matches.build, $NewRev)
    $Source = $VerFileContent -f $CurrentTime, $Matches.major, $Matches.minor, $Matches.build, $NewRev, $BranchName, $CommitHash
    Write-Output " Version(curr) $VersionString"
    Write-Output " New Version   $($LatestVersion.ToString())"
    Set-Content -Path "$BuildInfo" -Value ($LatestVersion.ToString())
    Set-Content -Path "$GeneratedVersionSourceFile" -Value "$Source"
}else{
    Write-Error "cannot parse version string $VersionString"
}

Write-Output "==================================="