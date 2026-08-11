<#
    LagCut-Off.ps1  -  BOTON DE PANICO del "Modo Juego"
    ------------------------------------------------------------------------
    Restaura el internet de inmediato SIN menu: pone la salida del firewall de
    vuelta a su estado previo (o Allow si no hay snapshot), borra el grupo de
    reglas "GameMode", elimina la tarea fail-safe y limpia state.json.

    Uselo si algo sale mal y no puede abrir la TUI. Se auto-eleva con UAC.
#>

[CmdletBinding()]
param(
    [switch]$Elevated,
    [ValidateSet('en','es')]
    [string]$Lang
)

$ErrorActionPreference = 'Continue'

$Group     = 'GameMode'
$TaskName  = 'GameMode-FailSafe'
$Path      = $MyInvocation.MyCommand.Path
if (-not $Path) { $Path = $PSCommandPath }
$Root      = Split-Path -Parent $Path
$StateFile = Join-Path $Root 'state.json'
$Profiles  = @('Domain','Private','Public')

# ---- localization (en / es, ASCII only) --------------------------------------
$script:Msg = @{
    'need'     = @{ en='Admin is required to restore the firewall. Accept the UAC prompt...'; es='Se necesita admin para restaurar el firewall. Acepta el aviso de UAC...' }
    'failhead' = @{ en='Could not elevate. Open a console as administrator and run:'; es='No se pudo elevar. Abre una consola como administrador y corre:' }
    'failcmd'  = @{ en='  Set-NetFirewallProfile -All -DefaultOutboundAction Allow'; es='  Set-NetFirewallProfile -All -DefaultOutboundAction Allow' }
    'header'   = @{ en='== GAME MODE OFF (panic) =='; es='== MODO JUEGO OFF (panico) ==' }
    'profset'  = @{ en='  {0} -> {1}'; es='  {0} -> {1}' }
    'proffail' = @{ en='  ! Could not touch profile {0}: {1}'; es='  ! No pude tocar el perfil {0}: {1}' }
    'rulesrm'  = @{ en="  'GameMode' rules removed."; es="  Reglas 'GameMode' eliminadas." }
    'taskrm'   = @{ en='  Fail-safe task removed.'; es='  Tarea fail-safe eliminada.' }
    'done'     = @{ en='  DONE: internet restored for all programs.'; es='  LISTO: internet restaurado para todos los programas.' }
    'close'    = @{ en='  enter to close'; es='  enter para cerrar' }
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

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host (L 'need') -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $Path + '"'),'-Elevated')
    if ($Lang) { $fwd += @('-Lang', $Lang) }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $fwd
    } catch {
        Write-Host (L 'failhead') -ForegroundColor Red
        Write-Host (L 'failcmd') -ForegroundColor Red
    }
    return
}

Write-Host (L 'header') -ForegroundColor Cyan

# Restaurar DefaultOutboundAction al snapshot si existe; si no, Allow.
$state = $null
if (Test-Path $StateFile) {
    try { $state = Get-Content $StateFile -Raw | ConvertFrom-Json } catch { $state = $null }
}
foreach ($p in $Profiles) {
    $action = 'Allow'
    if ($state -and $state.profiles -and $state.profiles.$p) {
        $v = "$($state.profiles.$p)"
        if ($v -eq 'Block' -or $v -eq 'Allow' -or $v -eq 'NotConfigured') { $action = $v }
    }
    try {
        Set-NetFirewallProfile -Profile $p -DefaultOutboundAction $action
        Write-Host (L 'profset' $p $action) -ForegroundColor Green
    } catch {
        Write-Host (L 'proffail' $p $_.Exception.Message) -ForegroundColor Red
    }
}

# Remove the GameMode rule group.
try {
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host (L 'rulesrm') -ForegroundColor Green
} catch {}

# Remove the fail-safe task.
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host (L 'taskrm') -ForegroundColor Green
    }
} catch {}

# Remove state.json.
if (Test-Path $StateFile) { Remove-Item $StateFile -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host (L 'done') -ForegroundColor Green
if ($Elevated) { Read-Host (L 'close') | Out-Null }
