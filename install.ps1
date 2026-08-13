<#
    install.ps1 - Creates a "LagCut" shortcut on the Desktop that launches the
    tool as administrator. Safe to re-run; it overwrites the existing shortcut.

    -Lang en|es  UI language for messages and the shortcut tooltip. Defaults to
                 Spanish when the Windows culture is 'es', otherwise English.
#>
param(
    [ValidateSet('en','es')]
    [string]$Lang
)
$ErrorActionPreference = 'Stop'

# ---- localization (en / es, ASCII only) --------------------------------------
$script:Msg = @{
    'notfound' = @{ en='LagCut.ps1 not found next to install.ps1.'; es='No se encontro LagCut.ps1 junto a install.ps1.' }
    'created'  = @{ en='Shortcut created: {0}'; es='Acceso directo creado: {0}' }
    'failed'   = @{ en='Failed to create shortcut.'; es='No se pudo crear el acceso directo.' }
    'tooltip'  = @{ en='LagCut: block all internet except your games (firewall).'; es='LagCut: bloquea todo el internet salvo tus juegos (firewall).' }
}
function Resolve-Lang([string]$override) {
    if ($override) { return $override.ToLowerInvariant() }
    try { if ((Get-Culture).TwoLetterISOLanguageName -eq 'es') { return 'es' } } catch {}
    return 'en'
}
function L([string]$key) {
    $entry = $script:Msg[$key]
    if (-not $entry) { return $key }
    $s = $entry[$script:Lang]
    if ($null -eq $s) { $s = $entry['en'] }
    if ($args.Count -gt 0) { return ([string]::Format($s, $args)) }
    return $s
}
$script:Lang = Resolve-Lang $Lang

$here   = $PSScriptRoot
$target = Join-Path $here 'LagCut.ps1'
if (-not (Test-Path $target)) {
    Write-Host (L 'notfound') -ForegroundColor Red
    return
}

$desktop = [Environment]::GetFolderPath('Desktop')
$lnk     = Join-Path $desktop 'LagCut.lnk'
$ps      = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

$sh = New-Object -ComObject WScript.Shell
$s  = $sh.CreateShortcut($lnk)
$s.TargetPath       = $ps
$s.Arguments        = '-NoProfile -ExecutionPolicy Bypass -File "' + $target + '"'
$s.WorkingDirectory = $here
$s.WindowStyle      = 1
$s.IconLocation     = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'lagcut.ico') + ',0'
$s.Description      = (L 'tooltip')
$s.Save()

# Mark "Run as administrator" (byte 0x15, bit 0x20) so it elevates on launch.
$bytes = [System.IO.File]::ReadAllBytes($lnk)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($lnk, $bytes)

if (Test-Path $lnk) { Write-Host (L 'created' $lnk) -ForegroundColor Green }
else { Write-Host (L 'failed') -ForegroundColor Red }
