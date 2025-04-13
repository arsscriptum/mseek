#╔════════════════════════════════════════════════════════════════════════════════╗
#║                                                                                ║
#║   Find-FSecure.ps1                                                             ║
#║                                                                                ║
#╟────────────────────────────────────────────────────────────────────────────────╢
#║   Guillaume Plante <codegp@icloud.com>                                         ║
#║   Code licensed under the GNU GPL v3.0. See the LICENSE file for details.      ║
#╚════════════════════════════════════════════════════════════════════════════════╝


$ScriptPath = "$PSScriptRoot\Find-ProcessIn.ps1"
. "$ScriptPath"

Find-ProcessIn -Path "C:\Program Files\F-Secure\TOTAL\x64" -IncludeChildren
