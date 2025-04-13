#╔════════════════════════════════════════════════════════════════════════════════╗
#║                                                                                ║
#║   GetDllsExports.ps1                                                           ║
#║                                                                                ║
#╟────────────────────────────────────────────────────────────────────────────────╢
#║   Guillaume Plante <codegp@icloud.com>                                         ║
#║   Code licensed under the GNU GPL v3.0. See the LICENSE file for details.      ║
#╚════════════════════════════════════════════════════════════════════════════════╝


function Get-DllExports {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Full path to the DLL to inspect.")]
        [ValidateScript({
                if (-not ($_ | Test-Path)) {
                    throw "File does not exist: $_"
                }
                if (-not ($_ | Test-Path -PathType Leaf)) {
                    throw "The path must point to a file: $_"
                }
                if ([System.IO.Path]::GetExtension($_).ToLower() -ne ".dll") {
                    throw "The file must have a .dll extension: $_"
                }
                return $true
            })]
        [string]$DllPath,

        [switch]$Headers,
        [switch]$Imports,

        [string]$OutFile
    )

    $dumpbinPath = $null
    $DumbinCmd = Get-Command 'dumpbin.exe' -ErrorAction Ignore
    if ($DumbinCmd) {
        $dumpbinPath = $DumbinCmd.Source
    }
    elseif ($ENV:VS140COMNTOOLS) {
        $PathInfo = Resolve-Path "$ENV:VS140COMNTOOLS\..\..\VC\bin\amd64\dumpbin.exe" -ErrorAction Ignore
        if ($PathInfo) {
            $dumpbinPath = $PathInfo.Path
        }
    }
    else {
        $dumpbinPath = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\amd64\dumpbin.exe"
    }

    if (-not (Test-Path "$dumpbinPath" -PathType Leaf)) {
        Write-Error "dumpbin.exe not found at expected path: $dumpbinPath"
        return
    }

    # Build the dumpbin argument list
    $argsList = @("/exports")

    if ($Headers) {
        $argsList += "/headers"
    }

    if ($Imports) {
        $argsList += "/imports"
    }

    $argsList += "$DllPath"

    if ($OutFile) {
        try {
            & "$dumpbinPath" @argsList | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Output saved to: $OutFile"
        } catch {
            Write-Error "Failed to write to output file: $_"
        }
    }
    else {
        & "$dumpbinPath" @argsList
    }
}


function Get-DllAllExports {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Full path to the DLL to inspect.")]
        [ValidateScript({
                if (-not ($_ | Test-Path)) {
                    throw "File does not exist: $_"
                }
                if (-not ($_ | Test-Path -PathType Leaf)) {
                    throw "The path must point to a file: $_"
                }
                if ([System.IO.Path]::GetExtension($_).ToLower() -ne ".dll") {
                    throw "The file must have a .dll extension: $_"
                }
                return $true
            })]
        [string]$DllPath
    )

    Get-DllExports -DllPath "$DllPath"
    #Get-DllExports -DllPath "$DllPath" -Headers
    #Get-DllExports -DllPath "$DllPath" -Headers -Imports
    #Get-DllExports -DllPath "$DllPath" -OutFile "$PWD\exports.txt"


}


function Get-UndecoratedName {
    param([string]$Symbol)

    $undname = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\undname.exe"
    if (-not (Test-Path $undname)) { return $Symbol } # fallback

    [string[]]$output = & $undname "$Symbol" 2>&1
    for ($j = 0; $j -lt $output.Count; $j++) {
        $line = $output[$j]
        if ($line.StartsWith('Undecoration of :- "')) {
            $lineres = $output[$j + 1]
            if ($lineres.StartsWith('is :- "')) {
                $ret = $lineres.TrimStart('is :- "').Trim().TrimEnd('"').Trim()
                return $ret

            }

        }
    }
    $output | where { $_.Length -gt 0 } | Select -Last 1
}



function Get-DllExportsList {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Full path to the DLL to inspect.")]
        [ValidateScript({
                if (-not ($_ | Test-Path)) {
                    throw "File does not exist: $_"
                }
                if (-not ($_ | Test-Path -PathType Leaf)) {
                    throw "The path must point to a file: $_"
                }
                if ([System.IO.Path]::GetExtension($_).ToLower() -ne ".dll") {
                    throw "The file must have a .dll extension: $_"
                }
                return $true
            })]
        [string]$DllPath
    )


    $parsing = $false
    $exportList = @()

    [string[]]$DumpbinOutput = (Get-DllExports -DllPath "$DllPath") -as [string[]]
    $FoundIndexes = $False
    $Start = 0
    $End = 0
    $i = 0
    [regex]$pattern = '(?<full>(?<ordinal>^\s*(\d+))\s+(?<hint>([0-9A-Fa-f]+))\s+(?<rva>([0-9A-Fa-f]{8}))\s+(?<name>(.+)))$'
    [System.Collections.ArrayList]$ObjectList = [System.Collections.ArrayList]::new()

    for ($a = 0; $a -lt $DumpbinOutput.Count; $a++) {
        $fnline = $DumpbinOutput[$a].Trim()
        if ($fnline.StartsWith('ordinal hint RVA')) {
            $Record = $True
        }
        elseif ($fnline.StartsWith('Summary')) {
            $Record = $False
            break;
        }
        elseif (($Record) -and (![string]::IsNullOrEmpty($fnline))) {
            
            $m = $pattern.Match($fnline)
            if ($m.Success) {
                [int]$v_ord = $m.Groups['ordinal'].Value -as [int]
                [int]$v_hint = [int]("0x$($m.Groups['hint'].Value)")
                [string]$v_rva = $($m.Groups['rva'].Value.ToUpper())
                [string]$v_name = $($m.Groups['name'].Value)
                [pscustomobject]$o = [pscustomobject]@{
                    Ordinal = $v_ord
                    Hint = $v_hint
                    RVA = $v_rva
                    Decorated = $v_name
                }
                $demangled = Get-UndecoratedName $v_name
                [regex]$undecor = '^(?<retval_cc>[\w\*\&\s:<>,]+)\s+(?<namespace>(?:[\w:]+)::)?(?<funcname>[\w~]+)\((?<params>.*)\)'

                $nspace = ""
                $funcname = ""
                $params = ""
                $retval_cc = ""

                if ($demangled -ne $v_name) {

                    # Attempt to extract components from demangled C++ signature
                    # Example: FSVpn::Site* __thiscall FSVpnSDK::FSVpn::getDefaultSite(void)
                    if ($demangled -match $undecor) {
                        
                        $nspace = if($matches['namespace'] -ne $Null){ $matches['namespace'].Trim(':') }else{ "" }
                        $funcname = if($matches['funcname'] -ne $Null){ $matches['funcname'] }else{ "" }
                        $params = if($matches['params'] -ne $Null){ $matches['params'].Trim(':') }else{ "" }
                        $retval_cc = if($matches['retval_cc'] -ne $Null){ $matches['retval_cc'].Trim(':') }else{ "" }

                        $div = $retval_cc.Split(' ')

                        [string]$return_value = ''
                        [string]$calling_conv = ''
                        if ($div[$div.Count - 1].StartsWith('__')) {
                            $i = $div.Count - 1
                            $calling_conv = $div[$i]

                            $return_value = 0..($i - 1) | % { "$($div[$_]) " }
                            $return_value = $return_value.Trim()
                            $colon_i = $return_value.IndexOf(':')
                            
                            if($colon_i -gt 0){
                                $class_qualifier = $return_value.Substring(0,$colon_i).Trim()
                                $return_value = $return_value.Substring($colon_i+1).Trim()
                                
                                if($class_qualifier.Length -gt 0){
                                    $nspace = "[{0}]{1}" -f $class_qualifier,$nspace
                                }
                            }


                        } else {
                            $return_value = $retval_cc
                        }
                    }
                    $o | Add-Member -MemberType NoteProperty -Name "Member" -Value $funcname -Force
                    $o | Add-Member -MemberType NoteProperty -Name "Namespace" -Value $nspace -Force
                    $o | Add-Member -MemberType NoteProperty -Name "CallingConvention" -Value $calling_conv -Force
                    $o | Add-Member -MemberType NoteProperty -Name "ReturnValue" -Value $return_value -Force
                    $o | Add-Member -MemberType NoteProperty -Name "Parameters" -Value $params -Force                    
                }else{
                    $o | Add-Member -MemberType NoteProperty -Name "Member" -Value $v_name -Force
                    $o | Add-Member -MemberType NoteProperty -Name "Namespace" -Value "" -Force
                    $o | Add-Member -MemberType NoteProperty -Name "CallingConvention" -Value "" -Force
                    $o | Add-Member -MemberType NoteProperty -Name "ReturnValue" -Value "" -Force
                    $o | Add-Member -MemberType NoteProperty -Name "Parameters" -Value "" -Force
                }
                [void]$ObjectList.Add($o)
            } else {
                Write-Warning "Parse Error $fnline"
                [pscustomobject]$o = [pscustomobject]@{
                    Ordinal = ""
                    Hint = ""
                    RVA = ""
                    Name = "$fnline"
                }
                [void]$ObjectList.Add($o)
            }
        }
    }

    return $ObjectList
}


function Test-GetDllData {
    $FsecDlls = "C:\Program Files\F-Secure\TOTAL\x64\ccf_proxy_resolver_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\dax_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_client_auth_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_cosmos_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_cosmos_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_datapipeline_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_guts2_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_ipc_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_push_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_customization_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_eult_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_events_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_feature_control_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_flyer_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_control_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_manager_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hotfix_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_oneclient_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_oneclient_core_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_subscription_reminder_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_usertasks_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsaua_api_dll64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsguts2_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fshoster64.exe", "C:\Program Files\F-Secure\TOTAL\x64\fsvpnsdk_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsvpnsdkcustomization_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\libcrypto-3-x64.dll", "C:\Program Files\F-Secure\TOTAL\x64\settings_upstream_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\vpn_configuration_plugin_64.dll"

    #ForEach($dll in $FsecDlls){
    #    Get-DllAllExports $dll
    #}

    #Get-DllAllExports "C:\Program Files\F-Secure\TOTAL\x64\fsguts2_64.dll"
    Get-DllExportsList "C:\Program Files\F-Secure\TOTAL\x64\fsvpnsdk_64.dll"
}

function Test-GetDllData {
$AllFsecDlls = "C:\Program Files\F-Secure\TOTAL\x64\ccf_proxy_resolver_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\dax_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_client_auth_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_cosmos_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_cosmos_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_datapipeline_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_guts2_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_ipc_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_ccf_push_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_customization_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_eult_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_events_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_feature_control_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_flyer_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_control_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hoster_manager_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_hotfix_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_oneclient_api_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_oneclient_core_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_subscription_reminder_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fs_usertasks_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsaua_api_dll64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsguts2_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsvpnsdk_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\fsvpnsdkcustomization_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\libcrypto-3-x64.dll", "C:\Program Files\F-Secure\TOTAL\x64\settings_upstream_plugin_64.dll", "C:\Program Files\F-Secure\TOTAL\x64\vpn_configuration_plugin_64.dll"
$dlls_subset = @("dax_64", "fsaua_api_dll64", "fs_ccf_client_auth_64", "fs_ccf_ipc_64", "fsaua_api_dll64", "fsguts2_64", "fs_flyer_api_64", "fs_ccf_datapipeline_api_64", "fs_oneclient_api_64", "fs_ccf_ipc_64", "fs_ccf_client_auth_plugin_64", "fs_ccf_client_auth_64", "fs_hoster_api_64", "fs_ccf_ipc_64", "fs_ccf_datapipeline_api_64")
 foreach($d in $dlls){ 
    $p = "C:\Program Files\F-Secure\TOTAL\x64\{0}.dll" -f $d 
    Get-DllExportsList "$p" | Select -ExpandProperty Member 
 }
 foreach($d in $AllFsecDlls){ 
    Write-Host "$d"
    $data = Get-DllExportsList "$d" | Select -ExpandProperty Member 
    foreach($t in $data){ write-host "$t`n" -f Green }
 }
}

