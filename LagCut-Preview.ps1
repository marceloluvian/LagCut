<#
    LagCut-Preview.ps1 - Non-destructive TUI preview for LagCut.ps1
    -----------------------------------------------------------
    Mirrors the real tool's interface so it can be previewed safely:
      top    = status header (ACTIVE / INACTIVE / INCONSISTENT badge)
      row 2  = action bar (<- -> buttons): Activate / Deactivate / Detect /
               Programs / Repair / language / Quit
      left   = whitelist list (arrows move; Enter opens a context menu)
      right  = selected item detail + global firewall state

    Two focus zones (Tab toggles): the action bar and the list. Dark-background
    vivid palette; bright inverse cyan for the focused list row, white for the
    focused button, green/red for enabled/blocked states.

    Bilingual (English / Spanish, es-419). Default: Spanish when the Windows
    culture is 'es', otherwise English; override with -Lang; toggle live with
    the language button (EN/ES) in the action bar.

    READ-ONLY: never touches the firewall, never writes files. Space toggles
    Enabled IN MEMORY only; every action just reports what the real tool calls.

    Windows PowerShell 5.1, no modules. VT via P/Invoke (SetConsoleMode);
    degrades to plain ASCII (no color, +--+ borders) under -NoVt or no VT.

    Usage:
      powershell -NoProfile -File .\LagCut-Preview.ps1                # interactive
      powershell -NoProfile -File .\LagCut-Preview.ps1 -NoVt          # forced fallback
      powershell -NoProfile -File .\LagCut-Preview.ps1 -RenderTest    # headless dump
      powershell -NoProfile -File .\LagCut-Preview.ps1 -Lang en       # force English
#>
[CmdletBinding()]
param(
    [switch]$RenderTest,
    [switch]$NoVt,
    [ValidateSet('en','es')]
    [string]$Lang
)

$ErrorActionPreference = 'Stop'

$ScriptPath = $MyInvocation.MyCommand.Path
if (-not $ScriptPath) { $ScriptPath = $PSCommandPath }
$Root      = Split-Path -Parent $ScriptPath
$ListFile  = Join-Path $Root 'whitelist.json'
$StateFile = Join-Path $Root 'state.json'
$Group     = 'GameMode'
$TaskName  = 'GameMode-FailSafe'
$Profiles  = @('Domain','Private','Public')
$MinW      = 70
$MinH      = 15

# =====================================================================
#  LOCALIZATION (en / es-419). Source stays 100% ASCII in both languages.
# =====================================================================

$script:Msg = @{
    'badge.active'       = @{ en='  GAME MODE ON  '; es='  MODO JUEGO ACTIVO  ' }
    'badge.inactive'     = @{ en='  INACTIVE (internet open)  '; es='  INACTIVO (internet abierto)  ' }
    'badge.inconsistent' = @{ en='  INCONSISTENT (Repair)  '; es='  INCONSISTENTE (Reparar)  ' }
    'badge.unknown'      = @{ en='  STATE: (requires admin)  '; es='  ESTADO: (requiere admin)  ' }

    'hdr.title'        = @{ en=' GAME MODE (firewall) '; es=' MODO JUEGO (firewall) ' }
    'hdr.preview'      = @{ en=' READ-ONLY PREVIEW '; es=' PREVIEW solo lectura ' }

    'action.activate'   = @{ en='Activate'; es='Activar' }
    'action.deactivate' = @{ en='Deactivate'; es='Desactivar' }
    'action.seed'       = @{ en='Detect'; es='Detectar' }
    'action.installed'  = @{ en='Programs'; es='Programas' }
    'action.repair'     = @{ en='Repair'; es='Reparar' }
    'action.quit'       = @{ en='Quit'; es='Salir' }

    'list.title'       = @{ en='Whitelist ({0})'; es='Whitelist ({0})' }
    'list.empty'       = @{ en=' (empty) Enter here = Add; or use Detect/Programs'; es=' (vacia) Enter aqui = Agregar; o usa Detectar/Programas' }

    'det.title'        = @{ en='Detail'; es='Detalle' }
    'det.name'         = @{ en=' Name   : {0}'; es=' Nombre : {0}' }
    'det.type'         = @{ en=' Type   : {0}'; es=' Tipo   : {0}' }
    'det.target'       = @{ en=' Target : {0}'; es=' Destino: {0}' }
    'det.state'        = @{ en=' State  : {0}'; es=' Estado : {0}' }
    'det.file_missing' = @{ en=' File   : DOES NOT EXIST (skipped on activate)'; es=' Archivo: NO EXISTE (se omite al activar)' }
    'det.file_ok'      = @{ en=' File   : OK'; es=' Archivo: OK' }
    'det.none'         = @{ en=' (no selection)'; es=' (sin seleccion)' }
    'type.exe'         = @{ en='Exe (.exe)'; es='Exe (.exe)' }
    'type.pkg'         = @{ en='Package (UWP)'; es='Package (UWP)' }
    'type.svc'         = @{ en='Service (Windows)'; es='Service (Windows)' }
    'state.on'         = @{ en='on'; es='encendido' }
    'state.off'        = @{ en='off'; es='apagado' }

    'gs.title'         = @{ en='Global state'; es='Estado global' }
    'gs.profadmin'     = @{ en=' Profiles: (admin required to read)'; es=' Perfiles: (requiere admin para leer)' }
    'gs.rules'         = @{ en=' Rules   : {0} (group {1})'; es=' Reglas  : {0} (grupo {1})' }
    'gs.state_yes'     = @{ en='present (reversible)'; es='presente (reversible)' }
    'gs.state_no'      = @{ en='no'; es='no' }
    'gs.statejson'     = @{ en=' state.json : {0}'; es=' state.json : {0}' }
    'gs.fs_yes'        = @{ en='registered (AtStartup)'; es='registrada (AtStartup)' }
    'gs.fs_no'         = @{ en='not registered'; es='no registrada' }
    'gs.failsafe'      = @{ en=' Fail-safe  : {0}'; es=' Fail-safe  : {0}' }
    'gs.dirty'         = @{ en=' * preview changes NOT saved'; es=' * cambios de preview SIN guardar' }

    'keys.main'        = @{ en=' Tab: switch zone | {0} move | {1} buttons | Enter: action | Space: on/off | Esc: quit'; es=' Tab: cambia zona | {0} mueve | {1} botones | Enter: accion | Space: on/off | Esc: salir' }

    'tiny.small'       = @{ en='  Window too small: {0}x{1} (min {2}x{3}).'; es='  Ventana muy chica: {0}x{1} (minimo {2}x{3}).' }
    'tiny.grow'        = @{ en='  Enlarge the window to see the interface.'; es='  Agranda la ventana para ver la interfaz.' }
    'tiny.quit'        = @{ en='  [q] quit'; es='  [q] salir' }

    'menu.title'       = @{ en='Action'; es='Accion' }
    'menu.toggle_on'   = @{ en='Enable'; es='Encender' }
    'menu.toggle_off'  = @{ en='Disable'; es='Apagar' }
    'menu.add'         = @{ en='Add by path'; es='Agregar por ruta' }
    'menu.detail'      = @{ en='View detail'; es='Ver detalle' }
    'menu.remove'      = @{ en='Remove'; es='Quitar' }

    'msg.detail'       = @{ en='Detail of "{0}": {1}'; es='Detalle de "{0}": {1}' }
    'msg.menuclosed'   = @{ en='Menu closed.'; es='Menu cerrado.' }
    'msg.refreshed'    = @{ en='State refreshed.'; es='Estado refrescado.' }
    'msg.langchanged'  = @{ en='Language: English'; es='Idioma: Espanol' }

    'prev.hello'       = @{ en='Read-only preview: NOTHING is saved or applied to the firewall.'; es='Preview de solo lectura: NADA se guarda ni se aplica al firewall.' }
    'prev.activate'    = @{ en='(preview) ACTIVATE: the real tool asks y/n and calls Enable-GameMode.'; es='(preview) ACTIVAR: el real pediria confirmacion s/n y llamaria Enable-GameMode.' }
    'prev.deactivate'  = @{ en='(preview) DEACTIVATE: the real tool calls Disable-GameMode (restores internet).'; es='(preview) DESACTIVAR: el real llamaria Disable-GameMode (restaura internet).' }
    'prev.seed'        = @{ en='(preview) Detect: the real tool calls Seed-KnownGames (LoL/Riot/Vanguard/Xbox).'; es='(preview) Detectar: el real llamaria Seed-KnownGames (LoL/Riot/Vanguard/Xbox).' }
    'prev.installed'   = @{ en='(preview) Programs: the real tool opens the installed view (Get-InstalledPrograms).'; es='(preview) Programas: el real abriria la vista de instalados (Get-InstalledPrograms).' }
    'prev.repair'      = @{ en='(preview) Repair: the real tool confirms and calls Repair-GameMode.'; es='(preview) Reparar: el real confirmaria y llamaria Repair-GameMode.' }
    'prev.toggle'      = @{ en='(preview) Visual toggle of "{0}" - the real tool: Save-Whitelist + reapply.'; es='(preview) Toggle visual de "{0}" - el real: Save-Whitelist + Offer-Reapply.' }
    'prev.add'         = @{ en='(preview) Add by path: the real tool asks name+path and calls Add-ToWhitelist.'; es='(preview) Agregar por ruta: el real pediria nombre+ruta y llamaria Add-ToWhitelist.' }
    'prev.remove'      = @{ en='(preview) Remove: the real tool confirms y/n and calls Save-Whitelist + reapply.'; es='(preview) Quitar: el real confirmaria s/n y llamaria Save-Whitelist + Offer-Reapply.' }
    'prev.done'        = @{ en='Preview finished. The firewall and files were not touched.'; es='Preview terminado. No se toco el firewall ni ningun archivo.' }
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

# =====================================================================
#  VT PROCESSING (P/Invoke, with graceful fallback)
# =====================================================================

if (-not ('GameModeTui.Native' -as [type])) {
    Add-Type -Namespace GameModeTui -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
}

function Enable-VtProcessing {
    # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004 on STD_OUTPUT_HANDLE (-11).
    try {
        $h = [GameModeTui.Native]::GetStdHandle(-11)
        if ($h -eq [IntPtr]::Zero -or $h -eq ([IntPtr](-1))) { return $false }
        $mode = [uint32]0
        if (-not [GameModeTui.Native]::GetConsoleMode($h, [ref]$mode)) { return $false }
        return [GameModeTui.Native]::SetConsoleMode($h, ($mode -bor 0x0004))
    } catch {
        return $false
    }
}

$script:Vt = $false

function Initialize-Style {
    # Dark-background vivid palette (bright 90-97 fg, 100-107 bg). Matches
    # LagCut.ps1 exactly so the preview looks like the real tool.
    $e = [char]27
    if ($script:Vt) {
        $script:P = @{
            Reset  = "$e[0m";  Bold  = "$e[1m";  Dim   = "$e[90m"
            Cyan   = "$e[96m"; Green = "$e[92m"; Yellow= "$e[93m"
            Red    = "$e[91m"; White = "$e[97m"; Inv   = "$e[7m"
            Border = "$e[94m"
            SelItem  = "$e[1;106;30m"; SelDimBg = "$e[100;97m"
            BtnFocus = "$e[1;107;30m"; BtnDim   = "$e[90m"
            TagExe = "$e[96m"; TagUwp = "$e[95m"; TagSvc = "$e[93m"
            On     = "$e[92m"; SelDanger = "$e[1;101;30m"
            BgGreen  = "$e[1;102;30m"; BgGray = "$e[100;97m"; BgYellow = "$e[1;103;30m"
        }
        $script:B = @{
            TL=[string][char]0x250C; TR=[string][char]0x2510; BL=[string][char]0x2514; BR=[string][char]0x2518
            H =[string][char]0x2500; V =[string][char]0x2502; LT=[string][char]0x251C; RT=[string][char]0x2524
        }
        $script:ArrowUp = [string][char]0x2191
        $script:ArrowDn = [string][char]0x2193
        $script:ArrowLt = [string][char]0x2190
        $script:ArrowRt = [string][char]0x2192
    } else {
        $script:P = @{
            Reset=''; Bold=''; Dim=''; Cyan=''; Green=''; Yellow=''; Red=''; White=''; Inv=''
            Border=''; SelItem=''; SelDimBg=''; BtnFocus=''; BtnDim=''
            TagExe=''; TagUwp=''; TagSvc=''; On=''; SelDanger=''
            BgGreen=''; BgGray=''; BgYellow=''
        }
        $script:B = @{ TL='+'; TR='+'; BL='+'; BR='+'; H='-'; V='|'; LT='+'; RT='+' }
        $script:ArrowUp = '^'; $script:ArrowDn = 'v'; $script:ArrowLt = '<'; $script:ArrowRt = '>'
    }
}

# =====================================================================
#  READ-ONLY DATA (whitelist + firewall snapshot)
# =====================================================================

function Read-WhitelistItems {
    # Same parse rules as Load-Whitelist in LagCut.ps1, strictly read-only
    # (no .bak on corrupt JSON). Returns view models for the list pane.
    $items = @()
    if (Test-Path $ListFile) {
        try {
            $raw = Get-Content $ListFile -Raw
            if ($raw -and $raw.Trim()) {
                $data = $raw | ConvertFrom-Json
                if ($null -ne $data) { $items = @($data) }
            }
        } catch { $items = @() }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($it in $items) {
        $type = "$($it.Type)"
        if (-not $type) { $type = 'Exe' }
        $target  = ''
        $tag     = 'exe'
        $missing = $false
        switch ($type) {
            'Package' { $target = "$($it.Package)"; $tag = 'uwp' }
            'Service' { $target = "$($it.Service)"; $tag = 'svc' }
            default   {
                $target = "$($it.Path)"
                $tag = 'exe'
                if ($target) { if (-not (Test-Path $target)) { $missing = $true } }
            }
        }
        $out.Add([pscustomobject]@{
            Name    = "$($it.Name)"
            Type    = $type
            Tag     = $tag
            Target  = $target
            Enabled = [bool]$it.Enabled
            Missing = $missing
        })
    }
    # ToArray(): @() straight over a List[object] of PSObjects throws on PS 5.1.
    return $out.ToArray()
}

function Read-GlobalState {
    # Best-effort snapshot mirroring Get-GameModeState. Read-only; permission
    # failures degrade to 'UNKNOWN'.
    $actions = $null
    try {
        $map = @{}
        foreach ($p in $Profiles) {
            $map[$p] = "$((Get-NetFirewallProfile -Profile $p -ErrorAction Stop).DefaultOutboundAction)"
        }
        $actions = $map
    } catch { $actions = $null }

    $rules = 0
    try { $rules = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue).Count } catch { $rules = 0 }

    $hasState = Test-Path $StateFile
    $failSafe = $false
    try { $failSafe = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) } catch {}

    $status = 'UNKNOWN'
    $blocked = 0
    if ($null -ne $actions) {
        $blocked = @($Profiles | Where-Object { $actions[$_] -eq 'Block' }).Count
        if ($blocked -eq 3 -and $rules -gt 0 -and $hasState) { $status = 'ACTIVE' }
        elseif ($blocked -eq 0 -and $rules -eq 0 -and -not $hasState) { $status = 'INACTIVE' }
        else { $status = 'INCONSISTENT' }
    }

    [pscustomobject]@{
        Status = $status; ProfileActions = $actions; Rules = $rules
        HasState = $hasState; FailSafe = $failSafe; BlockedCount = $blocked
    }
}

# =====================================================================
#  RENDER HELPERS
# =====================================================================

function Fit([string]$s, [int]$w) {
    if ($null -eq $s) { $s = '' }
    if ($w -lt 1) { return '' }
    if ($s.Length -gt $w) {
        if ($w -ge 4) { $s = $s.Substring(0, $w - 3) + '...' }
        else          { $s = $s.Substring(0, $w) }
    }
    return $s.PadRight($w)
}

function Render-Segments($segs, [int]$w) {
    $p = $script:P
    $out = ''
    $used = 0
    foreach ($s in $segs) {
        if ($used -ge $w) { break }
        $t = "$($s.Text)"
        $avail = $w - $used
        if ($t.Length -gt $avail) { $t = $t.Substring(0, $avail) }
        if ($s.Color) { $out += $s.Color + $t + $p.Reset } else { $out += $t }
        $used += $t.Length
    }
    if ($used -lt $w) { $out += ' ' * ($w - $used) }
    return $out
}

function New-BoxTop([string]$title, [int]$w) {
    $b = $script:B
    $inner = $w - 2
    $t = ''
    if ($title) { $t = $b.H + ' ' + $title + ' ' }
    if ($t.Length -gt $inner) { $t = $t.Substring(0, $inner) }
    return $b.TL + $t + ($b.H * ($inner - $t.Length)) + $b.TR
}

function New-BoxSep([string]$title, [int]$w) {
    $b = $script:B
    $inner = $w - 2
    $t = ''
    if ($title) { $t = $b.H + ' ' + $title + ' ' }
    if ($t.Length -gt $inner) { $t = $t.Substring(0, $inner) }
    return $b.LT + $t + ($b.H * ($inner - $t.Length)) + $b.RT
}

function New-BoxBottom([int]$w) {
    $b = $script:B
    return $b.BL + ($b.H * ($w - 2)) + $b.BR
}

function New-BoxRow([string]$content, [int]$w, [string]$color) {
    $b = $script:B
    $p = $script:P
    $body = $content
    if ($color) { $body = $color + $content + $p.Reset }
    return $p.Border + $b.V + $p.Reset + $body + $p.Border + $b.V + $p.Reset
}

function Get-TagColor([string]$tag) {
    $p = $script:P
    switch ($tag) {
        'uwp' { return $p.TagUwp }
        'svc' { return $p.TagSvc }
        default { return $p.TagExe }
    }
}

function Get-StatusBadge($status) {
    $p = $script:P
    switch ($status) {
        'ACTIVE'       { return @{ Text = (L 'badge.active');       Color = $p.BgGreen } }
        'INACTIVE'     { return @{ Text = (L 'badge.inactive');     Color = $p.BgGray } }
        'INCONSISTENT' { return @{ Text = (L 'badge.inconsistent'); Color = $p.BgYellow } }
        default        { return @{ Text = (L 'badge.unknown');      Color = $p.BgGray } }
    }
}

function Get-ActionLabel([string]$id) {
    if ($id -eq 'lang') { return $script:Lang.ToUpperInvariant() }
    return (L ('action.' + $id))
}

# =====================================================================
#  FRAME BUILDER (whole frame -> list of full-width lines; one write)
# =====================================================================

function Build-ActionBar($ctx, [int]$uw) {
    $p = $script:P
    $out = ''
    $plain = 0
    for ($i = 0; $i -lt $ctx.Actions.Count; $i++) {
        $lab = ' ' + (Get-ActionLabel $ctx.Actions[$i].Id) + ' '
        $focused = ($ctx.Zone -eq 'actions' -and $i -eq $ctx.ActionSel)
        if ($focused) { $col = $p.BtnFocus } else { $col = $p.BtnDim }
        $out   += $col + $lab + $p.Reset
        $plain += $lab.Length
        if ($i -lt ($ctx.Actions.Count - 1)) { $out += ' '; $plain += 1 }
    }
    if ($plain -lt $uw) { $out += ' ' * ($uw - $plain) }
    return $out
}

function Build-Frame($ctx, [int]$W, [int]$H) {
    $p  = $script:P
    $uw = $W - 1
    $totalRows = $H - 1
    $lines = New-Object System.Collections.Generic.List[string]

    if ($W -lt $MinW -or $H -lt $MinH) {
        $lines.Add((Fit '' $uw))
        $lines.Add(($p.Yellow + (Fit (L 'tiny.small' $W $H $MinW $MinH) $uw) + $p.Reset))
        $lines.Add((Fit (L 'tiny.grow') $uw))
        $lines.Add(($p.Dim + (Fit (L 'tiny.quit') $uw) + $p.Reset))
        while ($lines.Count -lt $totalRows) { $lines.Add((Fit '' $uw)) }
        return $lines
    }

    $panelRows = $totalRows - 4      # header + action bar + message + key bar
    $lw = [Math]::Min(42, [int]([Math]::Floor($uw * 0.42)))
    if ($lw -lt 24) { $lw = 24 }
    $rw = $uw - $lw

    # ---- header --------------------------------------------------------------
    $badge = Get-StatusBadge $ctx.Global.Status
    $title = L 'hdr.title'
    $right = L 'hdr.preview'
    $btext = $badge.Text
    if (($title.Length + $btext.Length) -gt $uw) {
        $btext = $btext.Substring(0, [Math]::Max(0, $uw - $title.Length))
    }
    $mid = $uw - $title.Length - $btext.Length - $right.Length
    if ($mid -lt 1) { $right = ''; $mid = [Math]::Max(0, $uw - $title.Length - $btext.Length) }
    $lines.Add($p.Bold + $p.Cyan + $title + $p.Reset + $badge.Color + $btext + $p.Reset + (' ' * $mid) + $p.Dim + $right + $p.Reset)

    # ---- action bar ----------------------------------------------------------
    $lines.Add((Build-ActionBar $ctx $uw))

    # ---- left pane rows (whitelist) ------------------------------------------
    $items    = @($ctx.Items)
    $listZone = ($ctx.Zone -eq 'list')
    $visible  = $panelRows - 2
    if ($visible -lt 1) { $visible = 1 }
    if ($ctx.Sel -lt $ctx.Scroll) { $ctx.Scroll = $ctx.Sel }
    if ($ctx.Sel -ge ($ctx.Scroll + $visible)) { $ctx.Scroll = $ctx.Sel - $visible + 1 }
    if ($ctx.Scroll -lt 0) { $ctx.Scroll = 0 }

    $leftPre = New-Object System.Collections.Generic.List[string]
    if ($items.Count -eq 0) {
        $leftPre.Add($p.Dim + (Fit (L 'list.empty') ($lw - 2)) + $p.Reset)
    } else {
        for ($i = $ctx.Scroll; $i -lt [Math]::Min($ctx.Scroll + $visible, $items.Count); $i++) {
            $it    = $items[$i]
            $isSel = ($i -eq $ctx.Sel)
            $mark  = '[ ]'
            if ($it.Enabled) { $mark = '[x]' }
            $cur = '  '
            if ($isSel) { $cur = '> ' }
            $plain = $cur + $mark + ' ' + $it.Tag + ' ' + $it.Name
            if ($isSel) {
                $barColor = $p.SelDimBg
                if ($listZone) { $barColor = $p.SelItem }
                $leftPre.Add($barColor + (Fit $plain ($lw - 2)) + $p.Reset)
            } else {
                $markColor = $p.On
                if (-not $it.Enabled) { $markColor = $p.Dim }
                $nameColor = ''
                if (-not $it.Enabled) { $nameColor = $p.Dim }
                if ($it.Missing)      { $nameColor = $p.Yellow }
                $segs = @(
                    @{ Text = $cur;          Color = '' },
                    @{ Text = $mark + ' ';   Color = $markColor },
                    @{ Text = $it.Tag + ' '; Color = (Get-TagColor $it.Tag) },
                    @{ Text = "$($it.Name)"; Color = $nameColor }
                )
                $leftPre.Add((Render-Segments $segs ($lw - 2)))
            }
        }
    }
    $ltitle = L 'list.title' $items.Count
    if ($listZone) { $ltitle += ' *' }
    if ($ctx.Scroll -gt 0) { $ltitle += ' ' + $script:ArrowUp }
    if (($ctx.Scroll + $visible) -lt $items.Count) { $ltitle += ' ' + $script:ArrowDn }

    # ---- right pane rows (detail + global state) -----------------------------
    $rightInner = New-Object System.Collections.Generic.List[object]
    $sel = $null
    if ($items.Count -gt 0 -and $ctx.Sel -lt $items.Count) { $sel = $items[$ctx.Sel] }
    if ($null -ne $sel) {
        $typeLabel = L 'type.exe'
        if ($sel.Type -eq 'Package') { $typeLabel = L 'type.pkg' }
        if ($sel.Type -eq 'Service') { $typeLabel = L 'type.svc' }
        $enLabel = L 'state.off'; $enColor = $p.Dim
        if ($sel.Enabled) { $enLabel = L 'state.on'; $enColor = $p.Green }
        $rightInner.Add(@{ Text = (L 'det.name' $sel.Name);     Color = $p.White })
        $rightInner.Add(@{ Text = (L 'det.type' $typeLabel);    Color = (Get-TagColor $sel.Tag) })
        $rightInner.Add(@{ Text = (L 'det.target' $sel.Target); Color = $p.Dim })
        $rightInner.Add(@{ Text = (L 'det.state' $enLabel);     Color = $enColor })
        if ($sel.Type -eq 'Exe') {
            if ($sel.Missing) { $rightInner.Add(@{ Text = (L 'det.file_missing'); Color = $p.Yellow }) }
            else              { $rightInner.Add(@{ Text = (L 'det.file_ok'); Color = $p.Green }) }
        }
    } else {
        $rightInner.Add(@{ Text = (L 'det.none'); Color = $p.Dim })
    }
    $rightInner.Add(@{ Sep = (L 'gs.title') })

    $g = $ctx.Global
    if ($null -ne $g.ProfileActions) {
        foreach ($pr in $Profiles) {
            $v = $g.ProfileActions[$pr]
            $c = $p.Dim
            if ($v -eq 'Block') { $c = $p.Red } elseif ($v -eq 'Allow') { $c = $p.Green }
            $rightInner.Add(@{ Text = (' {0,-8}: {1}' -f $pr, $v); Color = $c })
        }
    } else {
        $rightInner.Add(@{ Text = (L 'gs.profadmin'); Color = $p.Yellow })
    }
    $rightInner.Add(@{ Text = (L 'gs.rules' $g.Rules $Group); Color = '' })
    $stLabel = L 'gs.state_no'
    if ($g.HasState) { $stLabel = L 'gs.state_yes' }
    $fsLabel = L 'gs.fs_no'
    if ($g.FailSafe) { $fsLabel = L 'gs.fs_yes' }
    $rightInner.Add(@{ Text = (L 'gs.statejson' $stLabel); Color = '' })
    $rightInner.Add(@{ Text = (L 'gs.failsafe' $fsLabel); Color = '' })
    if ($ctx.Dirty) {
        $rightInner.Add(@{ Text = (L 'gs.dirty'); Color = $p.Yellow })
    }

    # ---- compose panel rows --------------------------------------------------
    for ($r = 0; $r -lt $panelRows; $r++) {
        $lt = ''; $rt = ''
        if ($r -eq 0) {
            $lt = $p.Border + (New-BoxTop $ltitle $lw) + $p.Reset
            $rt = $p.Border + (New-BoxTop (L 'det.title') $rw) + $p.Reset
        } elseif ($r -eq ($panelRows - 1)) {
            $lt = $p.Border + (New-BoxBottom $lw) + $p.Reset
            $rt = $p.Border + (New-BoxBottom $rw) + $p.Reset
        } else {
            $li = $r - 1
            $lContent = Fit '' ($lw - 2)
            if ($li -lt $leftPre.Count) { $lContent = $leftPre[$li] }
            $lt = New-BoxRow $lContent $lw ''

            if ($li -lt $rightInner.Count -and $rightInner[$li].ContainsKey('Sep')) {
                $rt = $p.Border + (New-BoxSep $rightInner[$li].Sep $rw) + $p.Reset
            } else {
                $rContent = Fit '' ($rw - 2)
                $rColor = ''
                if ($li -lt $rightInner.Count) {
                    $rContent = Fit $rightInner[$li].Text ($rw - 2)
                    $rColor   = $rightInner[$li].Color
                }
                $rt = New-BoxRow $rContent $rw $rColor
            }
        }
        $lines.Add($lt + $rt)
    }

    # ---- message + key bar ---------------------------------------------------
    $lines.Add(($p.Yellow + (Fit (' ' + $ctx.Msg) $uw) + $p.Reset))
    $a = $script:ArrowUp + $script:ArrowDn
    $lr = $script:ArrowLt + $script:ArrowRt
    $keys = L 'keys.main' $a $lr
    $lines.Add(($p.Inv + (Fit $keys $uw) + $p.Reset))
    return $lines
}

function Add-MenuOverlay($lines, $menu, [int]$uw, [int]$totalRows) {
    $p = $script:P
    $b = $script:B
    $items = @($menu.Items)
    $title = L 'menu.title'
    $mw = $title.Length + 2
    foreach ($it in $items) { $l = $it.Label.Length + 4; if ($l -gt $mw) { $mw = $l } }
    $mw += 2
    if ($mw -gt ($uw - 2)) { $mw = $uw - 2 }
    if ($mw -lt 20) { $mw = 20 }
    $inner = $mw - 2
    $pad = [Math]::Max(0, [int](($uw - $mw) / 2))
    $padStr = ' ' * $pad

    $rows = New-Object System.Collections.Generic.List[object]
    $rows.Add(@{ Plain = (New-BoxTop $title $mw); Color = $p.Border })
    for ($i = 0; $i -lt $items.Count; $i++) {
        $it  = $items[$i]
        $isSel = ($i -eq $menu.Sel)
        $cur = '  '
        if ($isSel) { $cur = '> ' }
        $rowPlain = $b.V + (Fit ($cur + $it.Label) $inner) + $b.V
        $rowColor = ''
        if ($isSel) {
            $rowColor = $p.SelItem
            if ($it.Id -eq 'remove') { $rowColor = $p.SelDanger }
        } elseif ($it.Id -eq 'remove') {
            $rowColor = $p.Red
        }
        $rows.Add(@{ Plain = $rowPlain; Color = $rowColor })
    }
    $rows.Add(@{ Plain = (New-BoxBottom $mw); Color = $p.Border })

    $top = [Math]::Max(1, [int](($totalRows - $rows.Count) / 2))
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $li = $top + $i
        if ($li -lt ($lines.Count - 1)) {
            $rp = $rows[$i].Plain
            $suffixLen = $uw - $pad - $rp.Length
            if ($suffixLen -lt 0) { $suffixLen = 0 }
            $mid = $rp
            if ($rows[$i].Color) { $mid = $rows[$i].Color + $rp + $p.Reset }
            $lines[$li] = $padStr + $mid + (' ' * $suffixLen)
        }
    }
}

function Write-Frame($lines) {
    $frame = ($lines -join "`r`n")
    if ($script:Vt) { [Console]::Write(([char]27) + '[H' + $frame) }
    else { [Console]::SetCursorPosition(0, 0); [Console]::Write($frame) }
}

# =====================================================================
#  INTERACTIVE LOOP (read-only: actions only report what the tool would do)
# =====================================================================

function New-DemoContext {
    @{
        Zone      = 'list'
        Items     = @(Read-WhitelistItems)
        Global    = Read-GlobalState
        Sel       = 0
        Scroll    = 0
        ActionSel = 0
        Actions   = @(
            @{ Id = 'activate' },
            @{ Id = 'deactivate' },
            @{ Id = 'seed' },
            @{ Id = 'installed' },
            @{ Id = 'repair' },
            @{ Id = 'lang' },
            @{ Id = 'quit' }
        )
        Menu      = $null
        Dirty     = $false
        Running   = $true
        Msg       = (L 'prev.hello')
    }
}

function Toggle-Language($ctx) {
    if ($script:Lang -eq 'es') { $script:Lang = 'en' } else { $script:Lang = 'es' }
    $ctx.Msg = L 'msg.langchanged'
}

function Invoke-DemoAction($ctx) {
    switch ($ctx.Actions[$ctx.ActionSel].Id) {
        'activate'   { $ctx.Msg = L 'prev.activate' }
        'deactivate' { $ctx.Msg = L 'prev.deactivate' }
        'seed'       { $ctx.Msg = L 'prev.seed' }
        'installed'  { $ctx.Msg = L 'prev.installed' }
        'repair'     { $ctx.Msg = L 'prev.repair' }
        'lang'       { Toggle-Language $ctx }
        'quit'       { $ctx.Running = $false }
    }
}

function Open-DemoMenu($ctx) {
    $count = @($ctx.Items).Count
    $mi = New-Object System.Collections.Generic.List[object]
    if ($count -gt 0 -and $ctx.Sel -lt $count) {
        $it = $ctx.Items[$ctx.Sel]
        $tgl = L 'menu.toggle_off'
        if (-not $it.Enabled) { $tgl = L 'menu.toggle_on' }
        $mi.Add(@{ Id = 'toggle'; Label = $tgl })
        $mi.Add(@{ Id = 'add';    Label = (L 'menu.add') })
        $mi.Add(@{ Id = 'detail'; Label = (L 'menu.detail') })
        $mi.Add(@{ Id = 'remove'; Label = (L 'menu.remove') })
    } else {
        $mi.Add(@{ Id = 'add'; Label = (L 'menu.add') })
    }
    $ctx.Menu = @{ Items = $mi.ToArray(); Sel = 0 }
}

function Invoke-DemoMenuKey($ctx, $k) {
    $m = $ctx.Menu
    $n = @($m.Items).Count
    switch ($k.Key) {
        'UpArrow'   { if ($m.Sel -gt 0) { $m.Sel-- }; return }
        'DownArrow' { if ($m.Sel -lt ($n - 1)) { $m.Sel++ }; return }
        'Home'      { $m.Sel = 0; return }
        'End'       { $m.Sel = $n - 1; return }
        'Escape'    { $ctx.Menu = $null; $ctx.Msg = (L 'msg.menuclosed'); return }
        'Enter'     {
            $id = $m.Items[$m.Sel].Id
            $ctx.Menu = $null
            $count = @($ctx.Items).Count
            switch ($id) {
                'toggle' {
                    if ($count -gt 0) {
                        $it = $ctx.Items[$ctx.Sel]
                        $it.Enabled = -not $it.Enabled
                        $ctx.Dirty = $true
                        $ctx.Msg = L 'prev.toggle' $it.Name
                    }
                }
                'add'    { $ctx.Msg = L 'prev.add' }
                'remove' { $ctx.Msg = L 'prev.remove' }
                'detail' {
                    if ($count -gt 0) {
                        $it = $ctx.Items[$ctx.Sel]
                        $ctx.Msg = L 'msg.detail' $it.Name $it.Target
                    }
                }
            }
            return
        }
    }
    if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { $ctx.Menu = $null }
}

function Invoke-DemoKey($ctx, $k) {
    if ($k.Key -eq 'Tab') {
        if ($ctx.Zone -eq 'actions') { $ctx.Zone = 'list' } else { $ctx.Zone = 'actions' }
        return
    }
    if ($ctx.Zone -eq 'actions') {
        switch ($k.Key) {
            'LeftArrow'  { if ($ctx.ActionSel -gt 0) { $ctx.ActionSel-- }; return }
            'RightArrow' { if ($ctx.ActionSel -lt (@($ctx.Actions).Count - 1)) { $ctx.ActionSel++ }; return }
            'Home'       { $ctx.ActionSel = 0; return }
            'End'        { $ctx.ActionSel = @($ctx.Actions).Count - 1; return }
            'DownArrow'  { $ctx.Zone = 'list'; return }
            'Enter'      { Invoke-DemoAction $ctx; return }
            'Spacebar'   { Invoke-DemoAction $ctx; return }
            'F5'         { $ctx.Items = @(Read-WhitelistItems); $ctx.Global = Read-GlobalState; $ctx.Dirty = $false; $ctx.Msg = (L 'msg.refreshed'); return }
            'Escape'     { $ctx.Running = $false; return }
        }
        if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { $ctx.Running = $false }
        return
    }

    $count = @($ctx.Items).Count
    switch ($k.Key) {
        'UpArrow'   { if ($ctx.Sel -gt 0) { $ctx.Sel-- } else { $ctx.Zone = 'actions' }; return }
        'DownArrow' { if ($ctx.Sel -lt ($count - 1)) { $ctx.Sel++ }; return }
        'PageUp'    { $ctx.Sel = [Math]::Max(0, $ctx.Sel - 10); return }
        'PageDown'  { if ($count -gt 0) { $ctx.Sel = [Math]::Min($count - 1, $ctx.Sel + 10) }; return }
        'Home'      { $ctx.Sel = 0; return }
        'End'       { if ($count -gt 0) { $ctx.Sel = $count - 1 }; return }
        'Spacebar'  {
            if ($count -gt 0) {
                $it = $ctx.Items[$ctx.Sel]
                $it.Enabled = -not $it.Enabled
                $ctx.Dirty = $true
                $ctx.Msg = L 'prev.toggle' $it.Name
            }
            return
        }
        'Enter'     { Open-DemoMenu $ctx; return }
        'Delete'    { $ctx.Msg = L 'prev.remove'; return }
        'F5'        { $ctx.Items = @(Read-WhitelistItems); $ctx.Global = Read-GlobalState; $ctx.Dirty = $false; $ctx.Msg = (L 'msg.refreshed'); return }
        'Escape'    { $ctx.Running = $false; return }
    }
    if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { $ctx.Running = $false }
}

function Invoke-DemoLoop {
    $ctx = New-DemoContext
    $lastW = -1
    $lastH = -1
    while ($ctx.Running) {
        $W = [Console]::WindowWidth
        $H = [Console]::WindowHeight
        if ($W -ne $lastW -or $H -ne $lastH) {
            Clear-Host
            $lastW = $W
            $lastH = $H
        }

        $frame = Build-Frame $ctx $W $H
        if ($ctx.Menu) { Add-MenuOverlay $frame $ctx.Menu ($W - 1) ($H - 1) }
        Write-Frame $frame

        $resized = $false
        while (-not [Console]::KeyAvailable) {
            Start-Sleep -Milliseconds 80
            if ([Console]::WindowWidth -ne $lastW -or [Console]::WindowHeight -ne $lastH) { $resized = $true; break }
        }
        if ($resized) { continue }

        $k = [Console]::ReadKey($true)
        if ($ctx.Menu) { Invoke-DemoMenuKey $ctx $k }
        else { Invoke-DemoKey $ctx $k }

        $count = @($ctx.Items).Count
        if ($ctx.Sel -ge $count -and $count -gt 0) { $ctx.Sel = $count - 1 }
        if ($ctx.Sel -lt 0) { $ctx.Sel = 0 }
    }
}

# =====================================================================
#  ENTRY POINT
# =====================================================================

if ($RenderTest) {
    $script:Vt = $false
    Initialize-Style
    $ctx = New-DemoContext
    (Build-Frame $ctx 100 30) -join "`r`n" | Write-Output

    $ok = $true
    $menu = @{ Items = @(
        @{ Id = 'toggle'; Label = (L 'menu.toggle_off') },
        @{ Id = 'add';    Label = (L 'menu.add') },
        @{ Id = 'detail'; Label = (L 'menu.detail') },
        @{ Id = 'remove'; Label = (L 'menu.remove') }
    ); Sel = 3 }
    foreach ($size in @(@(100,30), @(70,15), @(120,40))) {
        foreach ($zone in @('list','actions')) {
            $ctx.Zone = $zone
            $ctx.Scroll = 0
            $f = Build-Frame $ctx $size[0] $size[1]
            Add-MenuOverlay $f $menu ($size[0] - 1) ($size[1] - 1)
            foreach ($ln in $f) {
                if ($ln.Length -gt ($size[0] - 1)) {
                    Write-Output ('RENDERTEST-FAIL: overflow ' + $zone + ' at ' + $size[0] + 'x' + $size[1] + ' len=' + $ln.Length)
                    $ok = $false
                }
            }
        }
    }
    # language-agnostic: the tiny frame always carries the [q] quit hint
    $tiny = ((Build-Frame $ctx 40 10) -join "`n")
    if ($tiny -notmatch '\[q\]') { Write-Output 'RENDERTEST-FAIL: tiny branch'; $ok = $false }
    if ($ok) { Write-Output 'RENDERTEST-OK'; exit 0 }
    exit 1
}

$origEncoding = $null
$origCtrlC    = $null
try {
    if (-not $NoVt) { $script:Vt = Enable-VtProcessing }
    Initialize-Style
    try {
        $origEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    } catch { }
    try {
        $origCtrlC = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
    } catch { }
    [Console]::CursorVisible = $false
    Clear-Host
    Invoke-DemoLoop
}
finally {
    try { if ($script:Vt) { [Console]::Write(([char]27) + '[0m') } } catch { }
    try { [Console]::CursorVisible = $true } catch { }
    try { if ($null -ne $origCtrlC) { [Console]::TreatControlCAsInput = $origCtrlC } } catch { }
    try { if ($null -ne $origEncoding) { [Console]::OutputEncoding = $origEncoding } } catch { }
    try { Clear-Host } catch { }
    Write-Host (L 'prev.done') -ForegroundColor Gray
}
