<#
    LagCut.ps1  -  "Modo Juego" para Windows (firewall whitelist + TUI)
    ------------------------------------------------------------------------
    Corta la salida a internet de TODO lo que consume banda de fondo (navegadores,
    updates de Windows/Store, nube, telemetria, launchers ajenos), EXCEPTO los
    juegos que autorices (LoL, Riot Client, Vanguard, Xbox, etc.) y lo esencial
    de red (DNS, DHCP, LAN, ICMP/ping, NTP).

    Mecanismo: pone la accion de SALIDA del firewall en "Bloquear" en los 3
    perfiles (Domain/Private/Public) y crea reglas "Permitir" bajo el grupo
    "GameMode" para cada juego + los esenciales. En WFP una regla Allow explicita
    gana sobre el Block por defecto -> solo sale lo permitido. Todo bajo el grupo
    "GameMode" -> limpieza quirurgica al desactivar.

    Reversibilidad total: antes de activar guarda el estado previo en state.json y
    al desactivar lo restaura EXACTO. Fail-safe: registra una tarea AtStartup que,
    si Windows se reinicia con el modo activo, restaura el internet sola. Ademas
    existe LagCut-Off.ps1 (boton de panico) por si algo sale mal.

    NOTA: NO baja el ping de por si (eso es ruta del ISP); libera banda de fondo
    para que no compita con el juego (menos jitter/picos por saturacion local).

    Requiere admin (cambia el firewall) -> se auto-eleva con UAC al iniciar.

    Parametros:
      -Elevated     uso interno: marca que ya se relanzo elevado (evita bucle UAC).
      -AutoRestore  uso interno de la tarea fail-safe: restaura y sale (sin TUI).
      -DryRun       previsualiza: imprime que reglas/cambios haria SIN ejecutarlos.
      -Off          desactiva el modo juego y restaura internet (sin abrir el menu).
      -On           activa el modo juego y sale (sin abrir el menu).
      -NoVt         fuerza el modo ASCII de la interfaz (sin colores ni bordes VT).
      -RenderTest   diagnostico: pinta un frame de la interfaz y sale (no requiere
                    admin, no lee teclado y NO toca el firewall).
      -RegisterFailSafe  (re)registra la tarea fail-safe de reinicio y sale.
                    NO toca el firewall ni el estado; util si quedo sin registrar.
      -Lang en|es   fuerza el idioma de la interfaz (ingles / espanol). Por
                    defecto: espanol si la cultura de Windows es 'es', si no ingles.

    Interfaz: TUI de 2 paneles (whitelist + detalle/estado) con
    teclas directas; las acciones reales corren en "modo linea" clasico y vuelven.
#>

[CmdletBinding()]
param(
    [switch]$Elevated,
    [switch]$AutoRestore,
    [switch]$DryRun,
    [switch]$Off,
    [switch]$On,
    [switch]$NoVt,
    [switch]$RenderTest,
    [switch]$RegisterFailSafe,
    [ValidateSet('en','es')]
    [string]$Lang
)

$ErrorActionPreference = 'Stop'

# ---- rutas y constantes -------------------------------------------------------
$Group      = 'GameMode'
$TaskName   = 'GameMode-FailSafe'
$ScriptPath = $MyInvocation.MyCommand.Path
if (-not $ScriptPath) { $ScriptPath = $PSCommandPath }
$Root       = Split-Path -Parent $ScriptPath
$ListFile   = Join-Path $Root 'whitelist.json'
$StateFile  = Join-Path $Root 'state.json'
$ConfigFile = Join-Path $Root 'config.json'
$OffScript  = Join-Path $Root 'LagCut-Off.ps1'
$Profiles   = @('Domain','Private','Public')

# Onboarding schema version. Bump when the wizard changes enough that a returning
# user should see it again; a stored onboardedVersion below this re-triggers it.
$OnboardVersion = 1

# =====================================================================
#  LOCALIZATION (en / es-419). Source stays 100% ASCII in both languages.
#  Add a key with { en=...; es=... } and reference it via L 'key'.
# =====================================================================

$script:Msg = @{
    'elev.need'        = @{ en='Changing the firewall needs admin rights. Accept the Windows (UAC) prompt to continue...'; es='Cambiar el firewall necesita permisos de administrador. Acepta el aviso de Windows (UAC) para continuar...' }
    'elev.fail'        = @{ en='Could not get admin rights (UAC cancelled?). Close and try again.'; es='No se pudieron obtener permisos de administrador (cancelaste el UAC?). Cierra y vuelve a intentar.' }

    'wl.corrupt'       = @{ en='  ! whitelist.json is unreadable; backed it up to {0} and starting with an empty allow list.'; es='  ! whitelist.json esta ilegible; lo respalde en {0} y empiezo con la lista de permitidos vacia.' }

    'rule.uwpfail'     = @{ en='  ! Could not find the UWP app: {0} (is Xbox installed?)'; es='  ! No encontre la app UWP: {0} (esta instalado Xbox?)' }
    'rule.noexe'       = @{ en='  ! exe not found (skipped): {0}'; es='  ! No encontre el exe (omitido): {0}' }

    'fs.m1fail'        = @{ en='  ! Fail-safe method 1 (ScheduledTasks) failed: {0}'; es='  ! Fallo el metodo 1 del seguro de reinicio (ScheduledTasks): {0}' }
    'fs.m2fail'        = @{ en='  ! Fail-safe method 2 (schtasks) failed: {0}'; es='  ! Fallo el metodo 2 del seguro de reinicio (schtasks): {0}' }

    'enable.emptywl'   = @{ en='  Your allow list is EMPTY (or everything is off). Add or enable your games first (Detect / Programs).'; es='  Tu lista de permitidos esta VACIA (o todo esta apagado). Primero agrega o enciende tus juegos (Detectar / Programas).' }
    'dry.header'       = @{ en='  == PREVIEW (nothing is applied) =='; es='  == VISTA PREVIA (no se aplica nada) ==' }
    'dry.block'        = @{ en='  Would block outbound traffic on: Domain, Private, Public'; es='  Bloquearia la salida a internet en: Domain, Private, Public' }
    'dry.end'          = @{ en='  == end of preview =='; es='  == fin de la vista previa ==' }
    'enable.statefail' = @{ en='  ! Could not write state.json ({0}). Aborting without touching the firewall.'; es='  ! No pude escribir state.json ({0}). Cancelo sin tocar el firewall.' }
    'enable.done'      = @{ en='  GAME MODE ON. Allowed: {0} game(s) + essentials (DNS/DHCP/LAN/ICMP/NTP).'; es='  MODO JUEGO ACTIVADO. Permitidos: {0} juego(s) + lo esencial (DNS/DHCP/LAN/ICMP/NTP).' }
    'enable.done2'     = @{ en='  Everything else (browsers, updates, cloud, telemetry) has NO internet until you turn it off.'; es='  Todo lo demas (navegadores, actualizaciones, nube, telemetria) queda SIN internet hasta que lo desactives.' }
    'enable.note'      = @{ en="  Note: the network icon may show 'No internet' (the NCSI check is blocked). That's NORMAL; your game still has a connection."; es="  Nota: el icono de red puede decir 'Sin internet' (se bloquea el chequeo NCSI). Es NORMAL; tu juego si tiene conexion." }
    'enable.fswarn1'   = @{ en='  ! HEADS UP: could not set up the reboot fail-safe.'; es='  ! OJO: no se pudo configurar el seguro de reinicio.' }
    'enable.fswarn2'   = @{ en='    If you reboot while it is on, restore the internet with LagCut-Off.ps1 or the Turn Off button.'; es='    Si reinicias con el modo activo, restaura el internet con LagCut-Off.ps1 o el boton Desactivar.' }

    'dis.dryprofile'   = @{ en='   [dry] {0} -> DefaultOutboundAction={1}'; es='   [dry] {0} -> DefaultOutboundAction={1}' }
    'dis.dryrule'      = @{ en='   [dry] Remove-NetFirewallRule -Group GameMode'; es='   [dry] Remove-NetFirewallRule -Group GameMode' }
    'dis.drytask'      = @{ en='   [dry] Unregister-ScheduledTask GameMode-FailSafe + delete state.json'; es='   [dry] Unregister-ScheduledTask GameMode-FailSafe + borrar state.json' }
    'disable.done'     = @{ en='  GAME MODE OFF. Internet restored to its previous state for every program.'; es='  MODO JUEGO DESACTIVADO. Internet restaurado al estado anterior para todos los programas.' }

    'repair.working'   = @{ en='  Repairing: restoring your outbound traffic and clearing the GameMode rules...'; es='  Reparando: restaurando tu salida a internet y limpiando las reglas GameMode...' }
    'repair.done'      = @{ en='  Done. Everything is back to normal (internet open, no GameMode rules).'; es='  Listo. Todo quedo normal (internet abierto, sin reglas GameMode).' }

    'add.noexist'      = @{ en='  ! Not found: {0}'; es='  ! No existe: {0}' }
    'add.notexe'       = @{ en='  ! It must be an .exe file.'; es='  ! Debe ser un archivo .exe.' }
    'add.already'      = @{ en='  It is already in the allow list.'; es='  Ya esta en la lista de permitidos.' }
    'add.added'        = @{ en='  Added: {0}'; es='  Agregado: {0}' }
    'add.addeduwp'     = @{ en='  Added (UWP): {0}'; es='  Agregado (UWP): {0}' }
    'add.addedsvc'     = @{ en='  Added (service): {0}'; es='  Agregado (servicio): {0}' }

    'seed.none'        = @{ en='  No games found in the usual folders; add them by path or from the Programs view.'; es='  No encontre juegos en las carpetas tipicas; agregalos por ruta o desde la vista Programas.' }
    'seed.done'        = @{ en='  Detection done. Check the allow list (Xbox shows up as UWP/service).'; es='  Deteccion lista. Revisa la lista de permitidos (Xbox aparece como UWP/servicio).' }

    'rules.reapplied'  = @{ en='  Rules re-applied.'; es='  Reglas actualizadas.' }

    'exe.searching'    = @{ en='  Looking for .exe of: {0} ...'; es='  Buscando .exe de: {0} ...' }
    'exe.none'         = @{ en="  No .exe found; use 'Add by path' in the allow list."; es="  No encontre ningun .exe; usa 'Agregar por ruta' en la lista de permitidos." }
    'exe.prompt'       = @{ en="  which .exe? (number, 'all', or Enter to cancel)"; es="  cual .exe? (numero, 'all', o Enter para cancelar)" }

    'badge.active'       = @{ en='  GAME MODE ON  '; es='  MODO JUEGO ACTIVO  ' }
    'badge.inactive'     = @{ en='  OFF (internet open)  '; es='  DESACTIVADO (internet abierto)  ' }
    'badge.inconsistent' = @{ en='  NEEDS REPAIR  '; es='  NECESITA REPARAR  ' }
    'badge.unknown'      = @{ en='  UNKNOWN STATE  '; es='  ESTADO DESCONOCIDO  ' }

    'tiny.small'       = @{ en='  Window too small: {0}x{1} (min {2}x{3}).'; es='  Ventana muy chica: {0}x{1} (minimo {2}x{3}).' }
    'tiny.grow'        = @{ en='  Make the window bigger to see the interface.'; es='  Agranda la ventana para ver la interfaz.' }
    'tiny.quit'        = @{ en='  [q] quit'; es='  [q] salir' }

    'hdr.title'        = @{ en=' GAME MODE (firewall) '; es=' MODO JUEGO (firewall) ' }

    'action.activate'   = @{ en='Turn On'; es='Activar' }
    'action.deactivate' = @{ en='Turn Off'; es='Desactivar' }
    'action.seed'       = @{ en='Detect'; es='Detectar' }
    'action.installed'  = @{ en='Programs'; es='Programas' }
    'action.repair'     = @{ en='Repair'; es='Reparar' }
    'action.quit'       = @{ en='Quit'; es='Salir' }

    'list.title'       = @{ en='Allow list ({0})'; es='Permitidos ({0})' }
    'list.empty'       = @{ en=' (empty) Enter here = add; or use Detect / Programs'; es=' (vacia) Enter aqui = agregar; o usa Detectar / Programas' }
    'list.filter'      = @{ en=" filter: '{0}'   (Backspace edits, Esc clears)"; es=" filtro: '{0}'   (Backspace edita, Esc limpia)" }
    'list.noresults'   = @{ en=' (no matches - Backspace/Esc clears)'; es=' (sin coincidencias - Backspace/Esc limpia)' }

    'det.title'        = @{ en='Detail'; es='Detalle' }
    'det.name'         = @{ en=' Name   : {0}'; es=' Nombre : {0}' }
    'det.type'         = @{ en=' Type   : {0}'; es=' Tipo   : {0}' }
    'det.target'       = @{ en=' Target : {0}'; es=' Destino: {0}' }
    'det.state'        = @{ en=' State  : {0}'; es=' Estado : {0}' }
    'det.file_missing' = @{ en=' File   : MISSING (skipped when you turn on)'; es=' Archivo: NO EXISTE (se omite al activar)' }
    'det.file_ok'      = @{ en=' File   : OK'; es=' Archivo: OK' }
    'det.none'         = @{ en=' (nothing selected)'; es=' (no hay seleccion)' }
    'type.exe'         = @{ en='Exe (.exe)'; es='Exe (.exe)' }
    'type.pkg'         = @{ en='Package (UWP)'; es='Paquete (UWP)' }
    'type.svc'         = @{ en='Service (Windows)'; es='Servicio (Windows)' }
    'state.on'         = @{ en='on'; es='encendido' }
    'state.off'        = @{ en='off'; es='apagado' }

    'gs.title'         = @{ en='Global state'; es='Estado general' }
    'gs.rules'         = @{ en=' Rules   : {0} (group {1})'; es=' Reglas  : {0} (grupo {1})' }
    'gs.state_yes'     = @{ en='present (reversible)'; es='presente (reversible)' }
    'gs.state_no'      = @{ en='no'; es='no' }
    'gs.statejson'     = @{ en=' state.json : {0}'; es=' state.json : {0}' }
    'gs.fs_yes'        = @{ en='registered (at startup)'; es='registrado (al iniciar)' }
    'gs.fs_no'         = @{ en='not registered'; es='no registrado' }
    'gs.failsafe'      = @{ en=' Fail-safe  : {0}'; es=' Seguro de reinicio : {0}' }
    'gs.diag1'         = @{ en=' ! Diagnostic: profiles at Block={0}/3,'; es=' ! Diagnostico: perfiles en Block={0}/3,' }
    'gs.diag2'         = @{ en='   GameMode rules={0}, state.json={1}'; es='   reglas GameMode={0}, state.json={1}' }
    'gs.diag3'         = @{ en='   use More > Repair to fix it'; es='   usa Mas > Reparar para arreglarlo' }
    'gs.yes'           = @{ en='yes'; es='si' }
    'gs.no'            = @{ en='no'; es='no' }

    'keys.main'        = @{ en=' Tab: zone | {0} move | {1} buttons | Enter: action | Space: on/off | type: filter | Esc: clear/quit'; es=' Tab: zona | {0} mueve | {1} botones | Enter: accion | Espacio: on/off | escribe: filtra | Esc: limpia/sale' }

    'inst.header'      = @{ en=' INSTALLED PROGRAMS   {0}/{1}   {2}'; es=' PROGRAMAS INSTALADOS   {0}/{1}   {2}' }
    'inst.nofilter'    = @{ en='(no filter)'; es='(sin filtro)' }
    'inst.filter'      = @{ en="filter: '{0}'"; es="filtro: '{0}'" }
    'inst.noloc'       = @{ en='(no location)'; es='(sin ubicacion)' }
    'inst.empty'       = @{ en=' (no results for that filter - Esc clears it)'; es=' (sin resultados con ese filtro - Esc lo limpia)' }
    'inst.title'       = @{ en='Programs'; es='Programas' }
    'inst.filtering'   = @{ en=' filter: {0}_   (type; Enter/Esc ends, Backspace deletes)'; es=' filtro: {0}_   (escribe; Enter/Esc termina, Backspace borra)' }
    'keys.inst'        = @{ en=' [Enter] pick .exe   type: filter   [Esc] clear/back   (arrows/PgUp/PgDn move)'; es=' [Enter] elige .exe   escribe: filtra   [Esc] limpia/vuelve   (flechas/PgUp/PgDn mueven)' }

    'modal.hint'       = @{ en='[y] yes    [n] no'; es='[s] si    [n] no' }
    'menu.title'       = @{ en='Action'; es='Accion' }
    'menu.toggle_on'   = @{ en='Enable'; es='Encender' }
    'menu.toggle_off'  = @{ en='Disable'; es='Apagar' }
    'menu.add'         = @{ en='Add by path'; es='Agregar por ruta' }
    'menu.detail'      = @{ en='View detail'; es='Ver detalle' }
    'menu.remove'      = @{ en='Remove'; es='Quitar' }

    'line.back'        = @{ en='  (press any key to return to the interface)'; es='  (presiona cualquier tecla para volver a la interfaz)' }

    'msg.hello'        = @{ en='Tab switches between buttons and list. Enter opens actions for the selected game.'; es='Tab cambia entre botones y lista. Enter abre las acciones del juego seleccionado.' }
    'msg.reapplied'    = @{ en='Rules re-applied.'; es='Reglas actualizadas.' }
    'msg.refreshed'    = @{ en='State refreshed.'; es='Estado actualizado.' }
    'msg.menuclosed'   = @{ en='Menu closed.'; es='Menu cerrado.' }
    'msg.detail'       = @{ en='Detail of "{0}": {1}'; es='Detalle de "{0}": {1}' }
    'msg.toggle'       = @{ en='"{0}" {1}.'; es='"{0}" {1}.' }
    'msg.removed'      = @{ en='Removed: {0}'; es='Quitado: {0}' }
    'msg.wlupdated'    = @{ en='Allow list updated.'; es='Lista de permitidos actualizada.' }
    'msg.seeddone'     = @{ en='Detection done.'; es='Deteccion lista.' }
    'msg.emptyactivate'= @{ en='Allow list is empty or all off; add or enable games first (Detect / Programs).'; es='La lista de permitidos esta vacia o todo esta apagado; primero agrega o enciende juegos (Detectar / Programas).' }
    'msg.ready'        = @{ en='Done.'; es='Listo.' }
    'msg.alreadyinactive' = @{ en='It was already off. Nothing to restore.'; es='Ya estaba desactivado. Nada que restaurar.' }
    'msg.inetrestored' = @{ en='Internet restored.'; es='Internet restaurado.' }
    'msg.normalized'   = @{ en='Everything back to normal.'; es='Todo quedo normal.' }
    'msg.reading'      = @{ en='Reading installed programs...'; es='Leyendo los programas instalados...' }
    'msg.installedhint'= @{ en='Enter adds the selected program to the allow list.'; es='Enter agrega el programa seleccionado a la lista de permitidos.' }
    'msg.backmain'     = @{ en='Back to the main panel.'; es='De vuelta al panel principal.' }
    'msg.donerevisit'  = @{ en='Done; check the allow list when you go back ([Esc]).'; es='Listo; revisa la lista de permitidos al volver ([Esc]).' }
    'msg.langchanged'  = @{ en='Language: English'; es='Idioma: Espanol' }
    'msg.themechanged' = @{ en='Theme: {0}'; es='Tema: {0}' }

    'theme.neon'       = @{ en='Neon'; es='Neon' }
    'theme.sobrio'     = @{ en='Sober'; es='Sobrio' }

    'action.more'      = @{ en='More'; es='Mas' }

    'menu.system.title'= @{ en='More'; es='Mas' }
    'menu.repair'      = @{ en='Repair'; es='Reparar' }
    'menu.wizard'      = @{ en='Setup assistant'; es='Asistente' }
    'menu.theme'       = @{ en='Switch theme'; es='Cambiar tema' }
    'menu.reset'       = @{ en='Reset settings'; es='Reiniciar configuracion' }

    'wizard.title'     = @{ en='Setup assistant'; es='Asistente' }
    'wizard.header'    = @{ en='step {0}/{1}'; es='paso {0}/{1}' }
    'wizard.step.language' = @{ en='Language'; es='Idioma' }
    'wizard.lang.hint' = @{ en='Choose the language for LagCut.'; es='Elige el idioma de LagCut.' }
    'wizard.lang.en'   = @{ en='English'; es='English' }
    'wizard.lang.es'   = @{ en='Espanol (Spanish)'; es='Espanol' }
    'wizard.step.welcome'  = @{ en='Welcome'; es='Bienvenida' }
    'wizard.step.theme'    = @{ en='Choose a theme'; es='Elige un tema' }
    'wizard.step.profiles' = @{ en='Pick your profiles'; es='Elige tus perfiles' }
    'wizard.step.preview'  = @{ en='Apps to allow'; es='Apps a permitir' }
    'wizard.step.summary'  = @{ en='All set'; es='Listo' }

    'wizard.welcome1'  = @{ en='LagCut frees your bandwidth for gaming: it blocks'; es='LagCut libera tu ancho de banda para jugar: bloquea' }
    'wizard.welcome2'  = @{ en='background internet for everything except the apps'; es='el internet de fondo de todo, salvo las apps que tu' }
    'wizard.welcome3'  = @{ en='you allow. This assistant only reads your apps and'; es='permitas. Este asistente solo lee tus apps y guarda' }
    'wizard.welcome4'  = @{ en='saves your list. It never turns the firewall on.'; es='tu lista; NUNCA activa el firewall por si solo.' }

    'wizard.theme.neon'   = @{ en='vivid, saturated colors'; es='colores vivos y saturados' }
    'wizard.theme.sobrio' = @{ en='calm, softer colors'; es='colores mas tenues y suaves' }

    'wizard.noapps'    = @{ en='No apps detected for the chosen profiles.'; es='No detecte apps para los perfiles elegidos.' }
    'wizard.summary'   = @{ en='Added {0} program(s) to your allow list.'; es='Agregue {0} programa(s) a tu lista de permitidos.' }
    'wizard.finishhint'= @{ en='Press Enter to finish.'; es='Presiona Enter para terminar.' }
    'wizard.detecting' = @{ en='Detecting apps for the chosen profiles...'; es='Detectando apps de los perfiles elegidos...' }
    'wizard.previewhint'=@{ en='Space toggles an app; Enter or [g] saves the ticked ones.'; es='Espacio marca/desmarca una app; Enter o [g] guarda las marcadas.' }
    'wizard.savedmsg'  = @{ en='Saved {0} app(s) to the allow list.'; es='Guarde {0} app(s) en la lista de permitidos.' }
    'wizard.saved'     = @{ en='  Added {0} program(s) to the allow list.'; es='  Agregue {0} programa(s) a la lista de permitidos.' }
    'wizard.done'      = @{ en='Setup complete.'; es='Configuracion terminada.' }

    'wizard.keys.0'    = @{ en=' Up/Down: choose    Enter: continue    Esc: skip'; es=' Arriba/Abajo: elige    Enter: continuar    Esc: omitir' }
    'wizard.keys.1'    = @{ en=' Enter: continue    Esc: back'; es=' Enter: continuar    Esc: atras' }
    'wizard.keys.2'    = @{ en=' Up/Down: choose    Enter: continue    Esc: back'; es=' Arriba/Abajo: elige    Enter: continuar    Esc: atras' }
    'wizard.keys.3'    = @{ en=' Up/Down: move    Space: toggle    Enter: continue    Esc: back'; es=' Arriba/Abajo: mueve    Espacio: marca    Enter: continuar    Esc: atras' }
    'wizard.keys.4'    = @{ en=' Up/Down: move    Space: toggle    Enter/[g]: save    Esc: back'; es=' Arriba/Abajo: mueve    Espacio: marca    Enter/[g]: guarda    Esc: atras' }
    'wizard.keys.5'    = @{ en=' Enter: finish    Esc: back'; es=' Enter: terminar    Esc: atras' }

    'profile.games'    = @{ en='Games'; es='Juegos' }
    'profile.games.desc'   = @{ en='launchers and game clients'; es='launchers y clientes de juego' }
    'profile.browsers' = @{ en='Browsers'; es='Navegadores' }
    'profile.browsers.desc'= @{ en='Chrome, Edge, Firefox, etc.'; es='Chrome, Edge, Firefox, etc.' }
    'profile.dev'      = @{ en='Programming'; es='Programacion' }
    'profile.dev.desc'     = @{ en='editors, IDEs, terminals, tools'; es='editores, IDEs, terminales, herramientas' }
    'profile.design'   = @{ en='Design'; es='Diseno' }
    'profile.design.desc'  = @{ en='Photoshop, Figma, Blender, etc.'; es='Photoshop, Figma, Blender, etc.' }
    'profile.ai'       = @{ en='AI'; es='IA' }
    'profile.ai.desc'      = @{ en='AI apps and your default browser'; es='apps de IA y tu navegador predeterminado' }
    'profile.work'     = @{ en='Work/Comms'; es='Trabajo/Comunicacion' }
    'profile.work.desc'    = @{ en='Office, Teams, Slack, Zoom, etc.'; es='Office, Teams, Slack, Zoom, etc.' }

    'reset.confirm1'   = @{ en='Reset your settings? This clears your saved'; es='Reiniciar la configuracion? Esto borra tus' }
    'reset.confirm2'   = @{ en='preferences and reopens the assistant.'; es='preferencias y reabre el asistente.' }
    'reset.wl1'        = @{ en='Also EMPTY the allow list to start clean?'; es='Tambien VACIAR la lista de permitidos para empezar limpio?' }
    'reset.wl2'        = @{ en='[y] empty it    [n] keep your apps'; es='[s] la vacia    [n] conserva tus apps' }
    'reset.donewl'     = @{ en='Settings and allow list cleared.'; es='Configuracion y lista de permitidos reiniciadas.' }
    'reset.donecfg'    = @{ en='Settings reset (allow list kept).'; es='Configuracion reiniciada (lista de permitidos intacta).' }

    'modal.reapply1'   = @{ en='Game mode is ON. Re-apply the rules now'; es='El modo juego esta ACTIVO. Reaplicar las reglas ahora' }
    'modal.reapply2'   = @{ en='so your change takes effect?'; es='para que tu cambio surta efecto?' }
    'modal.remove'     = @{ en='Remove "{0}" from the allow list?'; es='Quitar "{0}" de la lista de permitidos?' }
    'modal.activate1'  = @{ en='{0} game(s) + essentials will be allowed'; es='Se permitiran {0} juego(s) + lo esencial' }
    'modal.activate2'  = @{ en='(DNS/DHCP/LAN/ICMP/NTP). Everything else'; es='(DNS/DHCP/LAN/ICMP/NTP). Todo lo demas' }
    'modal.activate3'  = @{ en='will have NO internet until you turn it off.'; es='quedara SIN internet hasta que lo desactives.' }
    'modal.activate4'  = @{ en='Turn game mode on now?'; es='Activar el modo juego ahora?' }
    'modal.repair1'    = @{ en='Repair: restore the internet and clear'; es='Reparar: restaurar el internet y limpiar' }
    'modal.repair2'    = @{ en='the GameMode rules?'; es='las reglas GameMode?' }
    'modal.quit1'      = @{ en='HEADS UP: GAME MODE is still ON; the block'; es='OJO: el MODO JUEGO sigue ACTIVO; el bloqueo' }
    'modal.quit2'      = @{ en='STAYS even if you close this window.'; es='CONTINUA aunque cierres esta ventana.' }
    'modal.quit3'      = @{ en='Turn it off now before exiting?'; es='Desactivarlo ahora antes de salir?' }

    'addline.header'   = @{ en='==================== ADD BY PATH ===================='; es='==================== AGREGAR POR RUTA ====================' }
    'addline.name'     = @{ en='  name'; es='  nombre' }
    'addline.path'     = @{ en='  path to the .exe'; es='  ruta al .exe' }
    'addline.cancel'   = @{ en='  Cancelled (empty name or path).'; es='  Cancelado (nombre o ruta vacios).' }
    'seedline.header'  = @{ en='==================== AUTO-DETECT GAMES ===================='; es='==================== AUTODETECTAR JUEGOS ====================' }

    'disp.dryactivate' = @{ en='== DRY-RUN: turn-on preview =='; es='== DRY-RUN: vista previa de ACTIVAR ==' }
    'disp.drydeactivate'=@{ en='== DRY-RUN: turn-off preview =='; es='== DRY-RUN: vista previa de DESACTIVAR ==' }
    'disp.offhdr'      = @{ en='== Turning GAME MODE off (restoring internet) =='; es='== Desactivando MODO JUEGO (restaurando internet) ==' }
    'disp.offalready'  = @{ en='  Already off. Nothing to restore.'; es='  Ya estaba desactivado. Nada que restaurar.' }
    'disp.offdone'     = @{ en='  Internet restored.'; es='  Internet restaurado.' }
    'disp.onhdr'       = @{ en='== Turning GAME MODE on =='; es='== Activando MODO JUEGO ==' }
    'disp.fshdr'       = @{ en='== Setting up the reboot fail-safe (without touching the firewall) =='; es='== Configurando el seguro de reinicio (sin tocar el firewall) ==' }
    'disp.fsok'        = @{ en='  OK: GameMode-FailSafe task registered.'; es='  OK: tarea GameMode-FailSafe registrada.' }
    'disp.fsfail'      = @{ en='  FAILED: could not set up the fail-safe (see the error above).'; es='  FALLO: no se pudo configurar el seguro de reinicio (revisa el error de arriba).' }

    'exit.err'         = @{ en='  INTERFACE ERROR: {0}'; es='  ERROR de interfaz: {0}' }
    'exit.errhint'     = @{ en='  If an action was interrupted, check the state when reopening (Repair) or run LagCut-Off.ps1.'; es='  Si una accion quedo a medias, revisa el estado al reabrir (Reparar) o usa LagCut-Off.ps1.' }
    'exit.stillon1'    = @{ en='  HEADS UP: you left GAME MODE ON. The block STAYS even if you close this window.'; es='  OJO: dejaste el MODO JUEGO ACTIVO. El bloqueo SIGUE aunque cierres esta ventana.' }
    'exit.stillon2'    = @{ en='  To restore the internet: reopen and use Turn Off, or run LagCut-Off.ps1.'; es='  Para restaurar el internet: vuelve a abrir y usa Desactivar, o corre LagCut-Off.ps1.' }
    'exit.bye'         = @{ en='  Exiting.'; es='  Saliendo.' }
}

function Resolve-Lang([string]$override, [string]$configLang) {
    # Priority: explicit -Lang flag > saved config > Windows culture > English.
    if ($override)   { return $override.ToLowerInvariant() }
    if ($configLang -and ($configLang -eq 'en' -or $configLang -eq 'es')) { return $configLang }
    try { if ((Get-Culture).TwoLetterISOLanguageName -eq 'es') { return 'es' } } catch {}
    return 'en'
}

function L([string]$key) {
    # Look up a localized string for the active language and optionally format
    # it with the extra args ({0},{1},...). Falls back to en, then to the key.
    $entry = $script:Msg[$key]
    if (-not $entry) { return $key }
    $s = $entry[$script:Lang]
    if ($null -eq $s) { $s = $entry['en'] }
    if ($args.Count -gt 0) { return ([string]::Format($s, $args)) }
    return $s
}

# =====================================================================
#  CONFIG (user preferences: onboarding, language, theme, chosen profiles)
#  Mirrors the whitelist storage pattern: tolerant read, -InputObject write.
#  This file NEVER touches the firewall; onboarding only reads apps and writes
#  whitelist.json / config.json.
# =====================================================================

function New-DefaultConfig {
    [pscustomobject]@{
        onboardedVersion = 0
        lang             = ''
        theme            = 'Neon'
        profiles         = @()
    }
}

function Load-Config {
    $cfg = New-DefaultConfig
    if (Test-Path $ConfigFile) {
        try {
            $raw = Get-Content $ConfigFile -Raw -ErrorAction Stop
            if ($raw -and $raw.Trim()) {
                $data = $raw | ConvertFrom-Json -ErrorAction Stop
                if ($data) {
                    if ($data.PSObject.Properties['onboardedVersion']) {
                        $iv = 0; [void][int]::TryParse("$($data.onboardedVersion)", [ref]$iv); $cfg.onboardedVersion = $iv
                    }
                    if ($data.PSObject.Properties['lang']  -and $data.lang)  { $cfg.lang  = "$($data.lang)" }
                    if ($data.PSObject.Properties['theme'] -and $data.theme) { $cfg.theme = "$($data.theme)" }
                    if ($data.PSObject.Properties['profiles'] -and $data.profiles) { $cfg.profiles = @($data.profiles | ForEach-Object { "$_" }) }
                }
            }
        } catch {
            # Corrupt config: back it up and fall back to defaults (never crash).
            $bak = $ConfigFile + '.bak'
            try { Copy-Item $ConfigFile $bak -Force } catch {}
        }
    }
    return $cfg
}

function Save-Config($cfg) {
    $dir = Split-Path -Parent $ConfigFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # PS 5.1: pass via -InputObject (piping a single object is fine, but keep the
    # same explicit form as Save-Whitelist for consistency).
    ConvertTo-Json -InputObject $cfg -Depth 5 | Set-Content -LiteralPath $ConfigFile -Encoding UTF8
}

function Remove-Config {
    if (Test-Path $ConfigFile) { Remove-Item $ConfigFile -Force -ErrorAction SilentlyContinue }
}

function Test-Onboarded {
    # First run = config.json missing or its onboardedVersion below the current one.
    param($cfg)
    if (-not $cfg) { $cfg = Load-Config }
    return ([int]$cfg.onboardedVersion -ge [int]$OnboardVersion)
}

$script:Config = Load-Config
$script:Lang   = Resolve-Lang $Lang $script:Config.lang
$script:Theme  = if ($script:Config.theme -eq 'Sobrio' -or $script:Config.theme -eq 'Neon') { $script:Config.theme } else { 'Neon' }

# ---- self-elevate (UAC) -------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin) -and -not $RenderTest) {
    Write-Host (L 'elev.need') -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $ScriptPath + '"'),'-Elevated')
    if ($AutoRestore) { $fwd += '-AutoRestore' }
    if ($DryRun)      { $fwd += '-DryRun' }
    if ($Off)         { $fwd += '-Off' }
    if ($On)          { $fwd += '-On' }
    if ($NoVt)        { $fwd += '-NoVt' }
    if ($RegisterFailSafe) { $fwd += '-RegisterFailSafe' }
    if ($Lang)        { $fwd += @('-Lang', $Lang) }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $fwd
    } catch {
        Write-Host (L 'elev.fail') -ForegroundColor Red
    }
    return
}

# =====================================================================
#  ALMACENAMIENTO (whitelist / state)
# =====================================================================

function Load-Whitelist {
    if (Test-Path $ListFile) {
        try {
            $raw = Get-Content $ListFile -Raw -ErrorAction Stop
            if (-not $raw -or -not $raw.Trim()) { return @() }
            # PS 5.1: ConvertFrom-Json emite el arreglo SIN enumerar, asi que
            # @($raw | ConvertFrom-Json) lo anida como UN elemento y colapsa toda
            # la whitelist. Asignar primero y luego @() si enumera correctamente.
            $data = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $data) { return @() }
            return @($data)
        } catch {
            # JSON corrupto: respaldar y avisar en vez de tragarse el error
            $bak = $ListFile + '.bak'
            try { Copy-Item $ListFile $bak -Force } catch {}
            Write-Host (L 'wl.corrupt' $bak) -ForegroundColor Red
            return @()
        }
    }
    return @()
}

function Save-Whitelist([object[]]$items) {
    $dir = Split-Path -Parent $ListFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $arr = @($items)
    if ($arr.Count -eq 0) {
        Set-Content -LiteralPath $ListFile -Value '[]' -Encoding UTF8
        return
    }
    # PS 5.1: usar -InputObject (NO pipe). Con pipe, ",$arr | ConvertTo-Json"
    # envuelve la salida en {value,Count} y al recargar se pierden los datos.
    ConvertTo-Json -InputObject $arr -Depth 5 | Set-Content -LiteralPath $ListFile -Encoding UTF8
}

function Save-State($profileMap) {
    # Guarda el DefaultOutboundAction previo por perfil para restaurar EXACTO.
    $obj = [pscustomobject]@{
        activatedAt = (Get-Date).ToString('s')
        profiles    = $profileMap
    }
    $obj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Load-State {
    if (Test-Path $StateFile) {
        try { return (Get-Content $StateFile -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Remove-State {
    if (Test-Path $StateFile) { Remove-Item $StateFile -Force -ErrorAction SilentlyContinue }
}

# =====================================================================
#  ESTADO DEL MODO
# =====================================================================

function Get-ProfileActions {
    # Devuelve un hashtable Perfil -> DefaultOutboundAction (string).
    $map = @{}
    foreach ($p in $Profiles) {
        try {
            $val = (Get-NetFirewallProfile -Profile $p -ErrorAction Stop).DefaultOutboundAction
            $map[$p] = "$val"
        } catch {
            $map[$p] = 'Unknown'
        }
    }
    return $map
}

function Get-GameModeState {
    $actions  = Get-ProfileActions
    $blocked  = @($Profiles | Where-Object { $actions[$_] -eq 'Block' }).Count
    $rules    = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)
    $ruleCnt  = $rules.Count
    $hasState = Test-Path $StateFile

    # Clasificacion: ACTIVE / INACTIVE / INCONSISTENT
    $status = 'INACTIVE'
    if ($blocked -eq 3 -and $ruleCnt -gt 0 -and $hasState) {
        $status = 'ACTIVE'
    } elseif ($blocked -eq 0 -and $ruleCnt -eq 0 -and -not $hasState) {
        $status = 'INACTIVE'
    } else {
        $status = 'INCONSISTENT'
    }

    [pscustomobject]@{
        Status         = $status
        BlockedCount   = $blocked
        Rules          = $ruleCnt
        HasState       = $hasState
        ProfileActions = $actions
    }
}

# =====================================================================
#  HELPERS DE FIREWALL (reglas esenciales, DoH, UWP)
# =====================================================================

function Get-DohDnsAddresses {
    # Si el usuario usa DNS cifrado (DoH), el Dnscache resuelve por 443 y el
    # puerto 53 no basta. Devolvemos las IPs del/los servidor(es) DNS para
    # permitir 443 SOLO hacia ellas (nunca 443 global -> seria un hueco QUIC).
    $addrs = New-Object System.Collections.Generic.List[string]
    try {
        $doh = Get-DnsClientDohServerAddress -ErrorAction Stop
        if ($doh) {
            foreach ($d in $doh) { if ($d.ServerAddress) { $addrs.Add("$($d.ServerAddress)") } }
        }
    } catch {
        # cmdlet no existe (Win10 viejo) o no hay DoH -> lista vacia
    }
    return @($addrs | Select-Object -Unique)
}

function New-CoreRules {
    param([switch]$DryRun)
    # Reglas esenciales para no romper conectividad basica durante el modo.
    $core = @(
        @{ n='GameMode Core - DNS UDP';  a=@{ Protocol='UDP'; RemotePort='53' } },
        @{ n='GameMode Core - DNS TCP';  a=@{ Protocol='TCP'; RemotePort='53' } },
        @{ n='GameMode Core - DHCP';     a=@{ Protocol='UDP'; RemotePort='67','68' } },
        @{ n='GameMode Core - DHCPv6';   a=@{ Protocol='UDP'; RemotePort='546','547' } },
        @{ n='GameMode Core - NTP';      a=@{ Protocol='UDP'; RemotePort='123' } },
        @{ n='GameMode Core - LAN';      a=@{ RemoteAddress='LocalSubnet' } },
        @{ n='GameMode Core - ICMPv4';   a=@{ Protocol='ICMPv4' } },
        @{ n='GameMode Core - ICMPv6';   a=@{ Protocol='ICMPv6' } }
    )
    foreach ($c in $core) {
        if ($DryRun) {
            $desc = ($c.a.GetEnumerator() | ForEach-Object { $_.Key + '=' + ($_.Value -join ',') }) -join ' '
            Write-Host ("   [dry] Allow OUT  " + $c.n + "  (" + $desc + ")") -ForegroundColor DarkGray
        } else {
            # splatting: el token debe ser @<variable> (no @($expr))
            $extra = $c.a
            New-NetFirewallRule -DisplayName $c.n -Group $Group -Direction Outbound -Action Allow @extra | Out-Null
        }
    }

    # DoH condicional: 443 SOLO hacia las IPs del servidor DNS configurado.
    $dohIps = Get-DohDnsAddresses
    if ($dohIps.Count -gt 0) {
        if ($DryRun) {
            Write-Host ("   [dry] Allow OUT  GameMode Core - DoH 443 -> " + ($dohIps -join ',')) -ForegroundColor DarkGray
        } else {
            New-NetFirewallRule -DisplayName 'GameMode Core - DoH TCP' -Group $Group -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -RemoteAddress $dohIps | Out-Null
            New-NetFirewallRule -DisplayName 'GameMode Core - DoH UDP' -Group $Group -Direction Outbound -Action Allow -Protocol UDP -RemotePort 443 -RemoteAddress $dohIps | Out-Null
        }
    }
}

function Get-AppxPackageSid([string]$familyName) {
    # El firewall permite apps UWP por SID de paquete (-Package). El SID se puede
    # resolver por el Moniker (= PackageFamilyName en minusculas) en el registro
    # de AppContainer Mappings. Devuelve el SID o $null si no lo halla.
    if (-not $familyName) { return $null }
    $target = $familyName.ToLowerInvariant()
    $bases = @(
        'HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings',
        'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    )
    foreach ($base in $bases) {
        if (-not (Test-Path $base)) { continue }
        $kids = @()
        try { $kids = @(Get-ChildItem $base -ErrorAction SilentlyContinue) } catch { $kids = @() }
        foreach ($kid in $kids) {
            $mon = $null
            try { $mon = (Get-ItemProperty $kid.PSPath -Name 'Moniker' -ErrorAction SilentlyContinue).Moniker } catch {}
            if ($mon -and $mon.ToLowerInvariant() -eq $target) {
                return (Split-Path $kid.Name -Leaf)
            }
        }
    }
    return $null
}

function New-AppRule {
    param($app, [switch]$DryRun)
    # Crea la regla Allow para una entrada de whitelist segun su tipo.
    $type = "$($app.Type)"
    if (-not $type) { $type = 'Exe' }
    $name = 'GameMode App - ' + $app.Name

    switch ($type) {
        'Package' {
            $sid = Get-AppxPackageSid $app.Package
            if (-not $sid) {
                Write-Host (L 'rule.uwpfail' $app.Package) -ForegroundColor DarkYellow
                return $false
            }
            if ($DryRun) {
                Write-Host ("   [dry] Allow OUT  " + $name + "  -Package " + $sid) -ForegroundColor DarkGray
            } else {
                New-NetFirewallRule -DisplayName $name -Group $Group -Direction Outbound -Action Allow -Package $sid | Out-Null
            }
            return $true
        }
        'Service' {
            if ($DryRun) {
                Write-Host ("   [dry] Allow OUT  " + $name + "  -Service " + $app.Service) -ForegroundColor DarkGray
            } else {
                New-NetFirewallRule -DisplayName $name -Group $Group -Direction Outbound -Action Allow -Service $app.Service | Out-Null
            }
            return $true
        }
        default {
            if (-not (Test-Path $app.Path)) {
                Write-Host (L 'rule.noexe' $app.Path) -ForegroundColor DarkYellow
                return $false
            }
            if ($DryRun) {
                Write-Host ("   [dry] Allow OUT  " + $name + "  -Program " + $app.Path) -ForegroundColor DarkGray
            } else {
                New-NetFirewallRule -DisplayName $name -Group $Group -Direction Outbound -Action Allow -Program $app.Path | Out-Null
            }
            return $true
        }
    }
}

# =====================================================================
#  FAIL-SAFE (tarea programada de reinicio)
# =====================================================================

function Test-FailSafeRegistered {
    [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

function Register-FailSafeTask {
    # AtStartup SYSTEM task that restores internet after a reboot while active.
    # Returns $true only if the task is actually present afterward. Two mechanisms:
    # the ScheduledTasks module first, then schtasks.exe as fallback -- the module
    # path can fail (sometimes silently) in some elevated/interactive contexts, so
    # we VERIFY after each attempt instead of trusting that it worked.
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '" -AutoRestore -Elevated'

    try {
        $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
        $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $princ -Settings $set -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host (L 'fs.m1fail' $_.Exception.Message) -ForegroundColor DarkYellow
    }
    if (Test-FailSafeRegistered) { return $true }

    # Fallback: schtasks.exe no depende del modulo ScheduledTasks.
    $sp = $ScriptPath
    if ($sp -match '\s') { $sp = '\"' + $sp + '\"' }
    $tr = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $sp + ' -AutoRestore -Elevated'
    try {
        & schtasks.exe /Create /TN $TaskName /TR $tr /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    } catch {
        Write-Host (L 'fs.m2fail' $_.Exception.Message) -ForegroundColor DarkYellow
    }
    return (Test-FailSafeRegistered)
}

function Unregister-FailSafeTask {
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        }
    } catch {}
}

# =====================================================================
#  ACTIVAR / DESACTIVAR
# =====================================================================

function Enable-GameMode {
    param([switch]$DryRun)

    $wl      = @(Load-Whitelist)
    $enabled = @($wl | Where-Object { $_.Enabled })
    if ($enabled.Count -eq 0) {
        Write-Host (L 'enable.emptywl') -ForegroundColor Red
        return
    }

    if ($DryRun) {
        Write-Host (L 'dry.header') -ForegroundColor Cyan
        Write-Host (L 'dry.block') -ForegroundColor DarkGray
        New-CoreRules -DryRun
        foreach ($app in $enabled) { New-AppRule -app $app -DryRun | Out-Null }
        Write-Host (L 'dry.end') -ForegroundColor Cyan
        return
    }

    # Anti-lockout: guardar como revertir ANTES de tocar el firewall.
    $snapshot = Get-ProfileActions
    try {
        Save-State $snapshot
    } catch {
        Write-Host (L 'enable.statefail' $_.Exception.Message) -ForegroundColor Red
        return
    }

    # Fail-safe primero: si el reboot ocurre a media activacion, ya restaura.
    $fsOk = Register-FailSafeTask

    # Reglas limpias del grupo (por si quedaron huerfanas) + esenciales + apps.
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-CoreRules
    $n = 0
    foreach ($app in $enabled) {
        if (New-AppRule -app $app) { $n++ }
    }

    # Bloquear el resto de la salida en los 3 perfiles.
    Set-NetFirewallProfile -Profile $Profiles -DefaultOutboundAction Block

    Write-Host ""
    Write-Host (L 'enable.done' $n) -ForegroundColor Green
    Write-Host (L 'enable.done2') -ForegroundColor Green
    Write-Host (L 'enable.note') -ForegroundColor DarkGray
    if (-not $fsOk) {
        Write-Host ""
        Write-Host (L 'enable.fswarn1') -ForegroundColor Yellow
        Write-Host (L 'enable.fswarn2') -ForegroundColor Yellow
    }
}

function Restore-FirewallFromState {
    # Restaura DefaultOutboundAction al snapshot guardado; si no hay snapshot,
    # cae a Allow (nunca dejar al usuario en Block por accidente).
    $st = Load-State
    foreach ($p in $Profiles) {
        $action = 'Allow'
        if ($st -and $st.profiles -and $st.profiles.$p) {
            $v = "$($st.profiles.$p)"
            if ($v -eq 'Block' -or $v -eq 'Allow' -or $v -eq 'NotConfigured') { $action = $v }
        }
        try { Set-NetFirewallProfile -Profile $p -DefaultOutboundAction $action } catch {}
    }
}

function Disable-GameMode {
    param([switch]$DryRun)

    if ($DryRun) {
        Write-Host (L 'dry.header') -ForegroundColor Cyan
        $st = Load-State
        foreach ($p in $Profiles) {
            $target = 'Allow'
            if ($st -and $st.profiles -and $st.profiles.$p) { $target = "$($st.profiles.$p)" }
            Write-Host (L 'dis.dryprofile' $p $target) -ForegroundColor DarkGray
        }
        Write-Host (L 'dis.dryrule') -ForegroundColor DarkGray
        Write-Host (L 'dis.drytask') -ForegroundColor DarkGray
        Write-Host (L 'dry.end') -ForegroundColor Cyan
        return
    }

    Restore-FirewallFromState
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Unregister-FailSafeTask
    Remove-State
    Write-Host ""
    Write-Host (L 'disable.done') -ForegroundColor Green
}

function Repair-GameMode {
    # Estado inconsistente -> dejar todo como "desactivado" limpio y seguro.
    Write-Host (L 'repair.working') -ForegroundColor Yellow
    Restore-FirewallFromState
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Unregister-FailSafeTask
    Remove-State
    Write-Host (L 'repair.done') -ForegroundColor Green
}

# =====================================================================
#  AUTO-RESTORE (invocado por la tarea fail-safe tras un reinicio)
# =====================================================================

if ($AutoRestore) {
    # Sin TUI: restaura, limpia y borra la propia tarea. Corre como SYSTEM.
    try {
        Restore-FirewallFromState
        Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-State
    } catch {}
    Unregister-FailSafeTask
    return
}

# =====================================================================
#  PROGRAMAS INSTALADOS + RESOLUCION DE .EXE
# =====================================================================

function Get-InstalledPrograms {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    $out  = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.DisplayName
            if (-not $name) { return }
            $name = $name.Trim()
            if (-not $name) { return }
            # filtrar basura: componentes del sistema y entradas de parches/updates
            if ($_.SystemComponent -eq 1) { return }
            if ($_.ReleaseType -and ($_.ReleaseType -match 'Update|Hotfix|Security')) { return }
            if ($_.ParentKeyName) { return }
            $norm = $name.ToLowerInvariant()
            if ($seen.ContainsKey($norm)) { return }
            $seen[$norm] = $true

            $loc = $_.InstallLocation
            if (-not $loc -and $_.DisplayIcon) {
                $ic = ($_.DisplayIcon -split ',')[0].Trim('"')
                if ($ic) { $loc = Split-Path -Parent $ic -ErrorAction SilentlyContinue }
            }
            $out.Add([pscustomobject]@{
                Name     = $name
                Location = $loc
                Icon     = $_.DisplayIcon
            })
        }
    }
    # PS 5.1 quirk (verified on 5.1.26100): @() straight over a List[object]
    # holding PSObjects throws ArgumentException; materialize with ToArray().
    return @($out.ToArray() | Sort-Object Name)
}

function Find-Exes([string]$location, [string]$icon) {
    # Devuelve candidatos .exe ordenados por heuristica: DisplayIcon primero,
    # luego exes en la raiz de InstallLocation; se relegan uninstall/setup/update.
    $result = New-Object System.Collections.Generic.List[string]
    $add = {
        param($p)
        if ($p -and (Test-Path $p) -and ($result -notcontains $p)) { $result.Add($p) }
    }

    if ($icon -and $icon -match '\.exe') {
        $p = ($icon -split ',')[0].Trim('"')
        if (Test-Path $p) { & $add ((Resolve-Path $p).Path) }
    }

    if ($location -and (Test-Path $location)) {
        $all = @(Get-ChildItem -Path $location -Filter *.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                 Select-Object -First 60)
        $rootDepth = ($location.TrimEnd('\') -split '\\').Count
        $ranked = $all | ForEach-Object {
            $isJunk  = ($_.Name -match '(?i)^unins|setup|update|crashpad|vcredist|helper|report')
            $depth   = ($_.FullName -split '\\').Count - $rootDepth
            [pscustomobject]@{ Path=$_.FullName; Junk=[int]$isJunk; Depth=$depth; Name=$_.Name }
        } | Sort-Object Junk, Depth, Name
        foreach ($r in $ranked | Select-Object -First 40) { & $add $r.Path }
    }
    # ToArray() instead of @($result): same List-wrapping quirk as above.
    return $result.ToArray()
}

# =====================================================================
#  WHITELIST OPS
# =====================================================================

function Add-ToWhitelist([string]$name,[string]$path) {
    $path = $path.Trim('"')
    if (-not (Test-Path $path)) { Write-Host (L 'add.noexist' $path) -ForegroundColor Red; return }
    if ($path -notmatch '\.exe$') { Write-Host (L 'add.notexe') -ForegroundColor Red; return }
    $full = (Resolve-Path $path).Path
    $wl = @(Load-Whitelist)
    if ($wl | Where-Object { $_.Path -and ($_.Path.ToLowerInvariant() -eq $full.ToLowerInvariant()) }) {
        Write-Host (L 'add.already') -ForegroundColor Yellow; return
    }
    $wl += [pscustomobject]@{ Name = $name; Path = $full; Enabled = $true; Type = 'Exe' }
    Save-Whitelist $wl
    Write-Host (L 'add.added' $name) -ForegroundColor Green
}

function Add-PackageToWhitelist([string]$name,[string]$familyName) {
    $wl = @(Load-Whitelist)
    if ($wl | Where-Object { $_.Package -and ($_.Package.ToLowerInvariant() -eq $familyName.ToLowerInvariant()) }) {
        return
    }
    $wl += [pscustomobject]@{ Name = $name; Package = $familyName; Enabled = $true; Type = 'Package' }
    Save-Whitelist $wl
    Write-Host (L 'add.addeduwp' $name) -ForegroundColor Green
}

function Add-ServiceToWhitelist([string]$name,[string]$service) {
    $wl = @(Load-Whitelist)
    if ($wl | Where-Object { $_.Service -and ($_.Service.ToLowerInvariant() -eq $service.ToLowerInvariant()) }) {
        return
    }
    $wl += [pscustomobject]@{ Name = $name; Service = $service; Enabled = $true; Type = 'Service' }
    Save-Whitelist $wl
    Write-Host (L 'add.addedsvc' $name) -ForegroundColor Green
}

function Get-RiotInstallPaths {
    # RiotClientInstalls.json trae las rutas reales de instalacion de Riot.
    $paths = New-Object System.Collections.Generic.List[string]
    $f = Join-Path $env:ProgramData 'Riot Games\RiotClientInstalls.json'
    if (Test-Path $f) {
        try {
            $j = Get-Content $f -Raw | ConvertFrom-Json
            foreach ($prop in $j.PSObject.Properties) {
                if ($prop.Value -is [string] -and $prop.Value -match '\.exe$') { $paths.Add($prop.Value) }
            }
        } catch {}
    }
    return @($paths | Select-Object -Unique)
}

function Seed-KnownGames {
    # Catalogo extensible: primera ruta que exista se agrega (idempotente).
    $cands = @(
        @{ n='LoL - Cliente';   g=@('C:\Riot Games\League of Legends\LeagueClient.exe') },
        @{ n='LoL - Juego';     g=@('C:\Riot Games\League of Legends\Game\League of Legends.exe') },
        @{ n='Riot Client';     g=@((Join-Path $env:LOCALAPPDATA 'Riot Games\Riot Client\RiotClientServices.exe'),'C:\Riot Games\Riot Client\RiotClientServices.exe') },
        @{ n='Vanguard (vgc)';  g=@('C:\Program Files\Riot Vanguard\vgc.exe') },
        @{ n='Vanguard (tray)'; g=@('C:\Program Files\Riot Vanguard\vgtray.exe') }
    )
    $added = 0
    foreach ($c in $cands) {
        foreach ($p in $c.g) {
            if (Test-Path $p) { Add-ToWhitelist $c.n $p; $added++; break }
        }
    }

    # Optional: non-game apps you always want to keep online while gaming
    # (e.g. a remote-access client). Add exe paths here to auto-seed them.
    $essentials = @()
    foreach ($c in $essentials) {
        foreach ($p in $c.g) {
            if (Test-Path $p) { Add-ToWhitelist $c.n $p; $added++; break }
        }
    }

    # Fallback: rutas reales de Riot desde RiotClientInstalls.json
    foreach ($rp in Get-RiotInstallPaths) {
        if (Test-Path $rp) {
            $nm = 'Riot - ' + (Split-Path $rp -Leaf)
            Add-ToWhitelist $nm $rp; $added++
        }
    }

    # Fallback: procesos vivos de Riot/LoL (si el juego esta abierto)
    foreach ($pn in @('LeagueClient','League of Legends','RiotClientServices','vgc','vgtray')) {
        try {
            Get-Process -Name $pn -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Path -and (Test-Path $_.Path)) { Add-ToWhitelist $pn $_.Path; $added++ }
            }
        } catch {}
    }

    # Xbox / Store: apps UWP -> por PAQUETE (no por .exe; el alias es reparse point).
    $xboxPkgs = @('Microsoft.GamingApp','Microsoft.XboxApp','Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider','Microsoft.GamingServices','Microsoft.Xbox.TCUI')
    foreach ($pkg in $xboxPkgs) {
        try {
            Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue | ForEach-Object {
                Add-PackageToWhitelist ('Xbox: ' + $_.Name) $_.PackageFamilyName; $added++
            }
        } catch {}
    }
    # Servicio GamingServices (soporte de juegos de la Store)
    try {
        if (Get-Service -Name 'GamingServices' -ErrorAction SilentlyContinue) {
            Add-ServiceToWhitelist 'Xbox GamingServices' 'GamingServices'; $added++
        }
    } catch {}

    if ($added -eq 0) {
        Write-Host (L 'seed.none') -ForegroundColor Yellow
    } else {
        Write-Host (L 'seed.done') -ForegroundColor Green
    }
}

# =====================================================================
#  ONBOARDING CATALOG + PROFILE-BASED APP RESOLUTION
#  Stable profile keys map to localized names via L 'profile.<key>'. Each
#  profile lists combinable matchers; Resolve-ProfileApps runs them read-only
#  and returns DETECTED apps as data. It NEVER writes the whitelist or touches
#  the firewall -- the wizard's preview step does the writing, only for ticked
#  apps, through the same idempotent Add-*ToWhitelist helpers.
# =====================================================================

$script:OnboardProfileOrder = @('Games','Browsers','Dev','Design','AI','Work')

$script:OnboardCatalog = @{
    'Games' = @{
        ExeNames = @('steam.exe','EpicGamesLauncher.exe','Battle.net.exe','Agent.exe','LeagueClient.exe','RiotClientServices.exe','VALORANT-Win64-Shipping.exe','vgc.exe','GalaxyClient.exe','Origin.exe','EADesktop.exe','UbisoftConnect.exe')
        Paths = @(
            'C:\Riot Games\League of Legends\LeagueClient.exe',
            '%LOCALAPPDATA%\Riot Games\Riot Client\RiotClientServices.exe',
            'C:\Riot Games\Riot Client\RiotClientServices.exe',
            'C:\Program Files\Riot Vanguard\vgc.exe',
            '%ProgramFiles(x86)%\Steam\steam.exe',
            '%ProgramFiles(x86)%\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe',
            '%ProgramFiles(x86)%\Battle.net\Battle.net.exe',
            '%ProgramFiles(x86)%\GOG Galaxy\GalaxyClient.exe',
            '%ProgramFiles%\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe',
            '%ProgramFiles(x86)%\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe'
        )
        Packages = @('Microsoft.GamingApp','Microsoft.XboxGamingOverlay','Microsoft.GamingServices')
        Services = @('GamingServices')
        DisplayNameRegex = @('Steam','Epic Games','Battle\.net','Riot','GOG Galaxy','Ubisoft','EA app|EA Desktop|Origin')
        Riot = $true
    }
    'Browsers' = @{
        ExeNames = @('chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','opera_gx.exe','vivaldi.exe')
        Paths = @(
            '%ProgramFiles%\Google\Chrome\Application\chrome.exe',
            '%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe',
            '%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe',
            '%ProgramFiles%\Mozilla Firefox\firefox.exe',
            '%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe',
            '%ProgramFiles%\Vivaldi\Application\vivaldi.exe'
        )
        DisplayNameRegex = @('Google Chrome','Microsoft Edge','Mozilla Firefox','Brave','Opera','Vivaldi')
    }
    'Dev' = @{
        ExeNames = @('Code.exe','devenv.exe','idea64.exe','pycharm64.exe','rider64.exe','webstorm64.exe','clion64.exe','git.exe','node.exe','pwsh.exe','Docker Desktop.exe','sublime_text.exe')
        Paths = @(
            '%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe',
            '%ProgramFiles%\Microsoft VS Code\Code.exe',
            '%ProgramFiles%\Git\cmd\git.exe',
            '%ProgramFiles%\Git\bin\git.exe',
            '%ProgramFiles%\nodejs\node.exe',
            '%ProgramFiles%\Docker\Docker\Docker Desktop.exe',
            '%ProgramFiles%\PowerShell\7\pwsh.exe',
            '%ProgramFiles%\Sublime Text\sublime_text.exe'
        )
        Packages = @('Microsoft.WindowsTerminal')
        DisplayNameRegex = @('Visual Studio','IntelliJ','PyCharm','JetBrains Rider','WebStorm','CLion','Sublime Text','Docker Desktop','Node\.js','Git')
    }
    'Design' = @{
        ExeNames = @('Photoshop.exe','Illustrator.exe','AfterFX.exe','Figma.exe','Blender.exe','krita.exe','Affinity Photo.exe','Affinity Designer.exe','resolve.exe')
        Paths = @(
            '%LOCALAPPDATA%\Figma\Figma.exe',
            '%ProgramFiles%\Blender Foundation\*\blender.exe',
            '%ProgramFiles%\Krita*\bin\krita.exe',
            '%ProgramFiles%\Blackmagic Design\DaVinci Resolve\Resolve.exe'
        )
        DisplayNameRegex = @('Photoshop','Illustrator','After Effects','Adobe','Figma','Blender','Krita','Affinity','DaVinci Resolve')
    }
    'AI' = @{
        ExeNames = @('Claude.exe','ChatGPT.exe','ollama app.exe','ollama.exe','LM Studio.exe','jan.exe','Cursor.exe')
        Paths = @(
            '%LOCALAPPDATA%\AnthropicClaude\claude.exe',
            '%LOCALAPPDATA%\Programs\cursor\Cursor.exe',
            '%LOCALAPPDATA%\Programs\Ollama\ollama app.exe',
            '%LOCALAPPDATA%\Programs\lm-studio\LM Studio.exe',
            '%LOCALAPPDATA%\Programs\Jan\jan.exe'
        )
        DisplayNameRegex = @('Claude','ChatGPT','Ollama','LM Studio','Jan','Cursor')
        DefaultBrowser = $true
    }
    'Work' = @{
        ExeNames = @('WINWORD.EXE','EXCEL.EXE','OUTLOOK.EXE','POWERPNT.EXE','Teams.exe','Slack.exe','Discord.exe','Zoom.exe')
        Paths = @(
            '%LOCALAPPDATA%\Microsoft\Teams\current\Teams.exe',
            '%LOCALAPPDATA%\slack\slack.exe',
            '%APPDATA%\Zoom\bin\Zoom.exe'
        )
        Packages = @('MSTeams')
        DisplayNameRegex = @('Microsoft Office','Microsoft 365','Microsoft Teams','Slack','Discord','Zoom')
    }
}

function Find-ExePath([string]$exeName) {
    # Resolve an exe basename to a full path without a broad disk scan:
    # the App Paths registry first (authoritative for launchers/browsers/Office),
    # then a running process with that image name.
    $bases = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'
    )
    foreach ($b in $bases) {
        $k = $b + $exeName
        if (Test-Path $k) {
            try {
                $def = (Get-ItemProperty $k -ErrorAction SilentlyContinue).'(default)'
                if ($def) { $def = "$def".Trim('"'); if ($def -and (Test-Path $def)) { return (Resolve-Path $def).Path } }
            } catch {}
        }
    }
    try {
        $pn = [System.IO.Path]::GetFileNameWithoutExtension($exeName)
        $proc = Get-Process -Name $pn -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
        if ($proc -and $proc.Path -and (Test-Path $proc.Path)) { return $proc.Path }
    } catch {}
    return $null
}

function Get-ExeFriendlyName([string]$exeName, [string]$path) {
    # Prefer the file's own description; fall back to the base name.
    try {
        if ($path -and (Test-Path $path)) {
            $vi = (Get-Item $path -ErrorAction SilentlyContinue).VersionInfo
            if ($vi) {
                if ($vi.FileDescription -and $vi.FileDescription.Trim()) { return $vi.FileDescription.Trim() }
                if ($vi.ProductName -and $vi.ProductName.Trim()) { return $vi.ProductName.Trim() }
            }
        }
    } catch {}
    return [System.IO.Path]::GetFileNameWithoutExtension($exeName)
}

function Get-DefaultBrowserPath {
    # Resolve the user's default https handler to an .exe (for the AI profile,
    # which keeps the browser online alongside the AI apps).
    try {
        $uc = 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice'
        $progId = (Get-ItemProperty $uc -ErrorAction SilentlyContinue).ProgId
        if ($progId) {
            $cmdKey = "HKLM:\SOFTWARE\Classes\$progId\shell\open\command"
            if (-not (Test-Path $cmdKey)) { $cmdKey = "HKCU:\SOFTWARE\Classes\$progId\shell\open\command" }
            if (Test-Path $cmdKey) {
                $cmd = (Get-ItemProperty $cmdKey -ErrorAction SilentlyContinue).'(default)'
                if ($cmd) {
                    $m = [regex]::Match("$cmd", '"([^"]+\.exe)"')
                    if (-not $m.Success) { $m = [regex]::Match("$cmd", '([A-Za-z]:\\[^\s"]+\.exe)') }
                    if ($m.Success) {
                        $p = $m.Groups[1].Value
                        if (Test-Path $p) { return (Resolve-Path $p).Path }
                    }
                }
            }
        }
    } catch {}
    return $null
}

function Expand-CatalogPaths([string]$path) {
    # Expand %ENV% and, for wildcard entries, every filesystem match.
    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    if ($expanded -match '[\*\?]') {
        try { return @(Resolve-Path $expanded -ErrorAction SilentlyContinue | ForEach-Object { $_.Path }) } catch { return @() }
    }
    if (Test-Path $expanded) { return @((Resolve-Path $expanded).Path) }
    return @()
}

function Resolve-ProfileApps([string[]]$selected) {
    # Read-only detection across the chosen profiles. Returns view-model objects
    # carrying everything Add-*ToWhitelist needs (Type + Path/Package/Service),
    # de-duplicated by target, each pre-ticked (Enabled) for the preview step.
    $result = New-Object System.Collections.Generic.List[object]
    $seen   = @{}
    $installed = $null

    $add = {
        param([string]$name, [string]$type, [string]$target, [string]$profile)
        if (-not $target) { return }
        $key = $type.ToLowerInvariant() + '|' + $target.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return }
        # also collapse same app reached via different exes (e.g. steam.exe vs gameoverlayui.exe,
        # or a versioned msedge.exe subfolder): dedup by friendly name too, keeping the first
        # (earlier detection layers = curated ExeNames/Paths, so the better target wins).
        $nameKey = $type.ToLowerInvariant() + '#' + $name.ToLowerInvariant()
        if ($seen.ContainsKey($nameKey)) { return }
        $seen[$key] = $true
        $seen[$nameKey] = $true
        $o = [pscustomobject]@{
            Name    = $name
            Type    = $type
            Path    = ''
            Package = ''
            Service = ''
            Profile = $profile
            Enabled = $true
        }
        switch ($type) {
            'Package' { $o.Package = $target }
            'Service' { $o.Service = $target }
            default   { $o.Path = $target }
        }
        $result.Add($o)
    }

    foreach ($pk in @($selected)) {
        $prof = $script:OnboardCatalog[$pk]
        if (-not $prof) { continue }

        if ($prof.Paths) {
            foreach ($path in $prof.Paths) {
                foreach ($full in (Expand-CatalogPaths $path)) {
                    & $add (Get-ExeFriendlyName ([System.IO.Path]::GetFileName($full)) $full) 'Exe' $full $pk
                }
            }
        }

        if ($prof.ExeNames) {
            foreach ($exe in $prof.ExeNames) {
                $p = Find-ExePath $exe
                if ($p) { & $add (Get-ExeFriendlyName $exe $p) 'Exe' $p $pk }
            }
        }

        if ($prof.Packages) {
            foreach ($pkg in $prof.Packages) {
                try {
                    Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue | ForEach-Object {
                        & $add ("$($_.Name)") 'Package' "$($_.PackageFamilyName)" $pk
                    }
                } catch {}
            }
        }

        if ($prof.Services) {
            foreach ($svc in $prof.Services) {
                try {
                    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                    if ($s) { & $add ("$($s.DisplayName)") 'Service' "$($s.Name)" $pk }
                } catch {}
            }
        }

        if ($prof.DisplayNameRegex) {
            if ($null -eq $installed) { $installed = @(Get-InstalledPrograms) }
            foreach ($rx in $prof.DisplayNameRegex) {
                foreach ($prog in @($installed | Where-Object { $_.Name -match $rx })) {
                    $exes = @(Find-Exes $prog.Location $prog.Icon)
                    # Prefer the first non-junk exe (uninstallers/crash handlers/updaters
                    # slip into the icon slot); fall back to the first if all look junky.
                    $pick = $exes | Where-Object { [System.IO.Path]::GetFileName($_) -notmatch '(?i)^unins|setup|update|crash|report|helper|log-uploader' } | Select-Object -First 1
                    if (-not $pick -and $exes.Count -gt 0) { $pick = $exes[0] }
                    if ($pick) { & $add ("$($prog.Name)") 'Exe' $pick $pk }
                }
            }
        }

        if ($prof.Riot) {
            foreach ($rp in (Get-RiotInstallPaths)) {
                if (Test-Path $rp) { & $add ('Riot - ' + (Split-Path $rp -Leaf)) 'Exe' ((Resolve-Path $rp).Path) $pk }
            }
        }

        if ($prof.DefaultBrowser) {
            $db = Get-DefaultBrowserPath
            if ($db) { & $add (Get-ExeFriendlyName ([System.IO.Path]::GetFileName($db)) $db) 'Exe' $db $pk }
        }
    }

    return $result.ToArray()
}

# =====================================================================
#  RE-APLICAR REGLAS (accion compartida; antes vivia dentro de Offer-Reapply)
# =====================================================================

function Update-GameModeRules {
    # Recreate the GameMode rule group from the current whitelist WITHOUT
    # touching DefaultOutboundAction (no OFF/ON cycle). Same body the old
    # Offer-Reapply ran on "yes"; the TUI asks via a drawn modal instead.
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-CoreRules
    $wl = @(Load-Whitelist | Where-Object { $_.Enabled })
    foreach ($app in $wl) { New-AppRule -app $app | Out-Null }
    Write-Host (L 'rules.reapplied') -ForegroundColor Green
}

function Select-ExeForProgram($prog) {
    Write-Host (L 'exe.searching' $prog.Name) -ForegroundColor DarkGray
    $exes = @(Find-Exes $prog.Location $prog.Icon)
    if ($exes.Count -eq 0) {
        Write-Host (L 'exe.none') -ForegroundColor Yellow
        return
    }
    $j = 1
    foreach ($e in $exes) { Write-Host ("   {0,2}. {1}" -f $j, $e); $j++ }
    Write-Host ""
    $es = (Read-Host (L 'exe.prompt')).Trim()
    if ($es -eq 'all') {
        foreach ($e in $exes) { Add-ToWhitelist $prog.Name $e }
    } elseif ($es -match '^\d+$') {
        $k = [int]$es - 1
        if ($k -ge 0 -and $k -lt $exes.Count) { Add-ToWhitelist $prog.Name $exes[$k] }
    }
}

# =====================================================================
#  TUI ENGINE  (VT via P/Invoke, ASCII fallback, buffered single-write frames)
# =====================================================================

$script:MinW = 70
$script:MinH = 15
$script:Vt   = $false

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

function Test-TrueColor {
    # 24-bit color is available under Windows Terminal or a terminal that
    # advertises truecolor. Only meaningful when VT sequences are already on.
    if (-not $script:Vt) { return $false }
    if ($env:COLORTERM -eq 'truecolor' -or $env:COLORTERM -eq '24bit') { return $true }
    if ($env:WT_SESSION) { return $true }
    return $false
}

function Get-SixteenColorPalette([string]$theme, [char]$e) {
    # 16-color VT set, now theme-aware so switching is visible even on a console
    # without truecolor (conhost): Neon uses the bright set (9x fg / 10x bg),
    # Sobrio uses the standard/muted set (3x fg / 4x bg). Same keys in both.
    if ($theme -eq 'Sobrio') {
        return @{
            Reset  = "$e[0m";  Bold  = "$e[1m";  Dim   = "$e[90m"
            Cyan   = "$e[36m"; Green = "$e[32m"; Yellow= "$e[33m"
            Red    = "$e[31m"; White = "$e[37m"; Inv   = "$e[7m"
            Border = "$e[34m"
            SelItem  = "$e[46;30m"
            SelDimBg = "$e[100;37m"
            BtnFocus = "$e[47;30m"
            BtnDim   = "$e[90m"
            TagExe = "$e[36m"; TagUwp = "$e[35m"; TagSvc = "$e[33m"
            On     = "$e[32m"
            SelDanger= "$e[41;37m"
            BgGreen  = "$e[42;30m"
            BgGray   = "$e[100;37m"
            BgYellow = "$e[43;30m"
        }
    }
    @{
        Reset  = "$e[0m";  Bold  = "$e[1m";  Dim   = "$e[90m"
        Cyan   = "$e[96m"; Green = "$e[92m"; Yellow= "$e[93m"
        Red    = "$e[91m"; White = "$e[97m"; Inv   = "$e[7m"
        Border = "$e[94m"
        SelItem  = "$e[1;106;30m"
        SelDimBg = "$e[100;97m"
        BtnFocus = "$e[1;107;30m"
        BtnDim   = "$e[90m"
        TagExe = "$e[96m"; TagUwp = "$e[95m"; TagSvc = "$e[93m"
        On     = "$e[92m"
        SelDanger= "$e[1;101;30m"
        BgGreen  = "$e[1;102;30m"
        BgGray   = "$e[100;97m"
        BgYellow = "$e[1;103;30m"
    }
}

function Get-TrueColorPalette([string]$theme, [char]$e) {
    # 24-bit palette. fg/bg builders emit SGR from RGB; selection/badge keys
    # combine a bg with a contrasting bold fg so text stays legible on the bar.
    $fg  = { param($r,$g,$b) $e + '[38;2;' + $r + ';' + $g + ';' + $b + 'm' }
    $bg  = { param($r,$g,$b) $e + '[48;2;' + $r + ';' + $g + ';' + $b + 'm' }
    $bfg = { param($r,$g,$b) $e + '[1;38;2;' + $r + ';' + $g + ';' + $b + 'm' }

    if ($theme -eq 'Sobrio') {
        $cyan=@(125,175,190); $green=@(120,170,130); $amber=@(200,170,110)
        $red=@(200,130,130);  $white=@(220,223,228); $dim=@(130,135,145)
        $border=@(110,120,150)
        $selBg=@(70,80,110);   $selFg=@(240,242,248)
        $btnBg=@(210,213,220); $btnFg=@(20,22,28)
        $uwp=@(180,150,200)
        $okBg=@(70,120,90);    $okFg=@(235,245,238)
        $warnBg=@(150,120,60); $warnFg=@(25,20,10)
        $dangBg=@(150,70,70);  $dangFg=@(245,235,235)
        $grayBg=@(80,85,95);   $grayFg=@(225,228,233)
    } else {
        $cyan=@(34,211,238);   $green=@(52,211,153);  $amber=@(251,191,36)
        $red=@(248,113,113);   $white=@(244,246,250); $dim=@(120,125,140)
        $border=@(99,102,241)
        $selBg=@(34,211,238);  $selFg=@(10,12,20)
        $btnBg=@(244,246,250); $btnFg=@(10,12,20)
        $uwp=@(196,132,252)
        $okBg=@(52,211,153);   $okFg=@(6,20,14)
        $warnBg=@(251,191,36); $warnFg=@(30,22,4)
        $dangBg=@(248,113,113);$dangFg=@(30,8,8)
        $grayBg=@(75,85,99);   $grayFg=@(226,232,240)
    }

    @{
        Reset  = "$e[0m"; Bold = "$e[1m"; Inv = "$e[7m"
        Dim    = (& $fg  $dim[0]   $dim[1]   $dim[2])
        Cyan   = (& $fg  $cyan[0]  $cyan[1]  $cyan[2])
        Green  = (& $fg  $green[0] $green[1] $green[2])
        Yellow = (& $fg  $amber[0] $amber[1] $amber[2])
        Red    = (& $fg  $red[0]   $red[1]   $red[2])
        White  = (& $fg  $white[0] $white[1] $white[2])
        Border = (& $fg  $border[0] $border[1] $border[2])
        SelItem  = (& $bg $selBg[0] $selBg[1] $selBg[2]) + (& $bfg $selFg[0] $selFg[1] $selFg[2])
        SelDimBg = (& $bg $grayBg[0] $grayBg[1] $grayBg[2]) + (& $fg $grayFg[0] $grayFg[1] $grayFg[2])
        BtnFocus = (& $bg $btnBg[0] $btnBg[1] $btnBg[2]) + (& $bfg $btnFg[0] $btnFg[1] $btnFg[2])
        BtnDim   = (& $fg $dim[0] $dim[1] $dim[2])
        TagExe = (& $fg $cyan[0] $cyan[1] $cyan[2])
        TagUwp = (& $fg $uwp[0]  $uwp[1]  $uwp[2])
        TagSvc = (& $fg $amber[0] $amber[1] $amber[2])
        On     = (& $fg $green[0] $green[1] $green[2])
        SelDanger= (& $bg $dangBg[0] $dangBg[1] $dangBg[2]) + (& $bfg $dangFg[0] $dangFg[1] $dangFg[2])
        BgGreen  = (& $bg $okBg[0] $okBg[1] $okBg[2]) + (& $bfg $okFg[0] $okFg[1] $okFg[2])
        BgGray   = (& $bg $grayBg[0] $grayBg[1] $grayBg[2]) + (& $fg $grayFg[0] $grayFg[1] $grayFg[2])
        BgYellow = (& $bg $warnBg[0] $warnBg[1] $warnBg[2]) + (& $bfg $warnFg[0] $warnFg[1] $warnFg[2])
    }
}

function Initialize-Style {
    # Three render tiers: 24-bit truecolor, the 16-color VT set, or a no-color
    # ASCII fallback (a conhost that rejects VT also garbles Unicode box glyphs,
    # so color and box style degrade together). Theme (Neon/Sobrio) picks the
    # palette. Color codes always wrap AROUND text and never count toward the
    # visible width, so Render-Segments/Fit column math is unaffected.
    $e = [char]27

    if (-not $script:Vt) {
        $script:P = @{
            Reset=''; Bold=''; Dim=''; Cyan=''; Green=''; Yellow=''; Red=''; White=''; Inv=''
            Border=''; SelItem=''; SelDimBg=''; BtnFocus=''; BtnDim=''
            TagExe=''; TagUwp=''; TagSvc=''; On=''; SelDanger=''
            BgGreen=''; BgGray=''; BgYellow=''
        }
        $script:B = @{ TL='+'; TR='+'; BL='+'; BR='+'; H='-'; V='|'; LT='+'; RT='+' }
        $script:ArrowUp = '^'; $script:ArrowDn = 'v'; $script:ArrowLt = '<'; $script:ArrowRt = '>'
        return
    }

    $theme = $script:Theme
    if ($theme -ne 'Neon' -and $theme -ne 'Sobrio') { $theme = 'Neon' }

    if (Test-TrueColor) { $script:P = Get-TrueColorPalette $theme $e }
    else                { $script:P = Get-SixteenColorPalette $theme $e }

    $script:B = @{
        TL=[string][char]0x250C; TR=[string][char]0x2510; BL=[string][char]0x2514; BR=[string][char]0x2518
        H =[string][char]0x2500; V =[string][char]0x2502; LT=[string][char]0x251C; RT=[string][char]0x2524
    }
    $script:ArrowUp = [string][char]0x2191
    $script:ArrowDn = [string][char]0x2193
    $script:ArrowLt = [string][char]0x2190
    $script:ArrowRt = [string][char]0x2192
}

function Render-Segments($segs, [int]$w) {
    # Compose colored segments into a string of EXACT visible width w. Each
    # segment's plain text is measured/truncated; color codes wrap around it
    # (never counted), so per-tag/per-mark coloring keeps column alignment.
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

function Fit([string]$s, [int]$w) {
    # Truncate with ellipsis and right-pad to an exact width (plain text only;
    # color codes wrap AROUND the padded text so visible width stays stable).
    if ($null -eq $s) { $s = '' }
    if ($w -lt 1) { return '' }
    if ($s.Length -gt $w) {
        if ($w -ge 4) { $s = $s.Substring(0, $w - 3) + '...' }
        else          { $s = $s.Substring(0, $w) }
    }
    return $s.PadRight($w)
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
    # Border chars stay in border color; content must arrive padded to w-2.
    $b = $script:B
    $p = $script:P
    $body = $content
    if ($color) { $body = $color + $content + $p.Reset }
    return $p.Border + $b.V + $p.Reset + $body + $p.Border + $b.V + $p.Reset
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
    # 'lang' shows the ACTIVE language code (press to switch); the rest are
    # localized words. Labels are resolved at render time so a language toggle
    # re-labels the whole action bar on the next frame.
    if ($id -eq 'lang') { return $script:Lang.ToUpperInvariant() }
    return (L ('action.' + $id))
}

function Get-TagColor([string]$tag) {
    $p = $script:P
    switch ($tag) {
        'uwp' { return $p.TagUwp }
        'svc' { return $p.TagSvc }
        default { return $p.TagExe }
    }
}

function Read-WhitelistItems {
    # View models for the list pane, built on top of the real loader so the TUI
    # always mirrors whitelist.json (order preserved -> Sel maps to file index).
    $items = @(Load-Whitelist)
    $out = New-Object System.Collections.Generic.List[object]
    $i = 0
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
            Idx     = $i                 # position in whitelist.json (survives filtering)
            Name    = "$($it.Name)"
            Type    = $type
            Tag     = $tag
            Target  = $target
            Enabled = [bool]$it.Enabled
            Missing = $missing
        })
        $i++
    }
    # ToArray(): @() straight over a List[object] of PSObjects throws on PS 5.1.
    return $out.ToArray()
}

function Get-TuiGlobalState {
    # Get-GameModeState plus fail-safe task presence. Read-only queries only.
    $s = Get-GameModeState
    $failSafe = $false
    try { $failSafe = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) } catch {}
    [pscustomobject]@{
        Status         = $s.Status
        BlockedCount   = $s.BlockedCount
        ProfileActions = $s.ProfileActions
        Rules          = $s.Rules
        HasState       = $s.HasState
        FailSafe       = $failSafe
    }
}

# =====================================================================
#  TUI FRAMES  (builders return a list of full-width lines; one write per frame)
# =====================================================================

function Build-TinyFrame([int]$W, [int]$H) {
    $p  = $script:P
    $uw = [Math]::Max(10, $W - 1)
    $totalRows = [Math]::Max(4, $H - 1)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((Fit '' $uw))
    $lines.Add(($p.Yellow + (Fit (L 'tiny.small' $W $H $script:MinW $script:MinH) $uw) + $p.Reset))
    $lines.Add((Fit (L 'tiny.grow') $uw))
    $lines.Add(($p.Dim + (Fit (L 'tiny.quit') $uw) + $p.Reset))
    while ($lines.Count -lt $totalRows) { $lines.Add((Fit '' $uw)) }
    return $lines
}

function Build-ActionBar($ctx, [int]$uw) {
    # Horizontal button row (zone 'actions'). Focused button uses BtnFocus,
    # the rest BtnDim; when the list zone is focused every button is dim so it
    # is always clear which zone owns input. Padded to exact width uw.
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

function Get-VisibleItems($ctx) {
    # The whitelist rows currently shown: all of them, or the WlFilter matches.
    $all = @($ctx.Items)
    if ($ctx.WlFilter) { return @($all | Where-Object { $_.Name -match [regex]::Escape($ctx.WlFilter) }) }
    return $all
}

function Get-SelectedIdx($ctx) {
    # whitelist.json index of the selected (possibly filtered) row, or -1 if none.
    $vis = @(Get-VisibleItems $ctx)
    if ($vis.Count -eq 0 -or $ctx.Sel -lt 0 -or $ctx.Sel -ge $vis.Count) { return -1 }
    return [int]$vis[$ctx.Sel].Idx
}

function Build-MainFrame($ctx, [int]$W, [int]$H) {
    $p  = $script:P
    $uw = $W - 1                     # avoid last-column wrap on legacy conhost
    $totalRows = $H - 1              # never write the last console row (no scroll)
    if ($W -lt $script:MinW -or $H -lt $script:MinH) { return (Build-TinyFrame $W $H) }
    $lines = New-Object System.Collections.Generic.List[string]
    $panelRows = $totalRows - 4      # header + action bar + message + key bar

    $lw = [Math]::Min(42, [int]([Math]::Floor($uw * 0.42)))
    if ($lw -lt 24) { $lw = 24 }
    $rw = $uw - $lw

    # ---- header --------------------------------------------------------------
    $badge = Get-StatusBadge $ctx.Global.Status
    $title = L 'hdr.title'
    $btext = $badge.Text
    if (($title.Length + $btext.Length) -gt $uw) {
        $btext = $btext.Substring(0, [Math]::Max(0, $uw - $title.Length))
    }
    $mid = [Math]::Max(0, $uw - $title.Length - $btext.Length)
    $lines.Add($p.Bold + $p.Cyan + $title + $p.Reset + $badge.Color + $btext + $p.Reset + (' ' * $mid))

    # ---- action bar ----------------------------------------------------------
    $lines.Add((Build-ActionBar $ctx $uw))

    # ---- left pane rows (whitelist) ------------------------------------------
    $items    = @(Get-VisibleItems $ctx)
    $listZone = ($ctx.Zone -eq 'list')
    $visible  = $panelRows - 2
    if ($visible -lt 1) { $visible = 1 }
    if ($ctx.Sel -lt $ctx.Scroll) { $ctx.Scroll = $ctx.Sel }
    if ($ctx.Sel -ge ($ctx.Scroll + $visible)) { $ctx.Scroll = $ctx.Sel - $visible + 1 }
    if ($ctx.Scroll -lt 0) { $ctx.Scroll = 0 }

    # each left row is pre-rendered to EXACTLY (lw-2) visible chars
    $leftPre = New-Object System.Collections.Generic.List[string]
    if ($items.Count -eq 0) {
        $emsg = L 'list.empty'
        if ($ctx.WlFilter) { $emsg = L 'list.noresults' }
        $leftPre.Add($p.Dim + (Fit $emsg ($lw - 2)) + $p.Reset)
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
                # solid highlight bar: vivid cyan when the list owns focus,
                # muted gray when focus is on the action bar
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
                    @{ Text = $cur;              Color = '' },
                    @{ Text = $mark + ' ';       Color = $markColor },
                    @{ Text = $it.Tag + ' ';     Color = (Get-TagColor $it.Tag) },
                    @{ Text = "$($it.Name)";     Color = $nameColor }
                )
                $leftPre.Add((Render-Segments $segs ($lw - 2)))
            }
        }
    }
    $ltitle = L 'list.title' $items.Count
    if ($listZone) { $ltitle += ' *' }
    if ($ctx.Scroll -gt 0) { $ltitle += ' ' + $script:ArrowUp }
    if (($ctx.Scroll + $visible) -lt $items.Count) { $ltitle += ' ' + $script:ArrowDn }

    # ---- right pane rows (selected detail + global state) --------------------
    $rightInner = New-Object System.Collections.Generic.List[object]
    $sel = $null
    if ($items.Count -gt 0 -and $ctx.Sel -lt $items.Count) { $sel = $items[$ctx.Sel] }
    if ($null -ne $sel) {
        $typeLabel = L 'type.exe'
        if ($sel.Type -eq 'Package') { $typeLabel = L 'type.pkg' }
        if ($sel.Type -eq 'Service') { $typeLabel = L 'type.svc' }
        $enLabel = L 'state.off'
        $enColor = $p.Dim
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
    foreach ($pr in $Profiles) {
        $v = 'Unknown'
        if ($g.ProfileActions) { $v = $g.ProfileActions[$pr] }
        $c = ''
        if ($v -eq 'Block') { $c = $p.Red }
        elseif ($v -eq 'Allow') { $c = $p.Green }
        else { $c = $p.Dim }
        $rightInner.Add(@{ Text = (' {0,-8}: {1}' -f $pr, $v); Color = $c })
    }
    $rightInner.Add(@{ Text = (L 'gs.rules' $g.Rules $Group); Color = '' })
    $stLabel = L 'gs.state_no'
    if ($g.HasState) { $stLabel = L 'gs.state_yes' }
    $fsLabel = L 'gs.fs_no'
    if ($g.FailSafe) { $fsLabel = L 'gs.fs_yes' }
    $rightInner.Add(@{ Text = (L 'gs.statejson' $stLabel); Color = '' })
    $rightInner.Add(@{ Text = (L 'gs.failsafe' $fsLabel); Color = '' })
    if ($g.Status -eq 'INCONSISTENT') {
        $hs = L 'gs.no'
        if ($g.HasState) { $hs = L 'gs.yes' }
        $rightInner.Add(@{ Text = (L 'gs.diag1' $g.BlockedCount); Color = $p.Yellow })
        $rightInner.Add(@{ Text = (L 'gs.diag2' $g.Rules $hs); Color = $p.Yellow })
        $rightInner.Add(@{ Text = (L 'gs.diag3'); Color = $p.Yellow })
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
    $msgLine = ' ' + $ctx.Msg
    if ($ctx.WlFilter) { $msgLine = L 'list.filter' $ctx.WlFilter }
    $lines.Add(($p.Yellow + (Fit $msgLine $uw) + $p.Reset))
    $a = $script:ArrowUp + $script:ArrowDn
    $lr = $script:ArrowLt + $script:ArrowRt
    $keys = L 'keys.main' $a $lr
    $lines.Add(($p.Inv + (Fit $keys $uw) + $p.Reset))
    return $lines
}

function Get-InstalledView($ctx) {
    $all = @($ctx.Programs)
    if ($ctx.Filter) { return @($all | Where-Object { $_.Name -match [regex]::Escape($ctx.Filter) }) }
    return $all
}

function Build-InstalledFrame($ctx, [int]$W, [int]$H) {
    $p  = $script:P
    $uw = $W - 1
    $totalRows = $H - 1
    if ($W -lt $script:MinW -or $H -lt $script:MinH) { return (Build-TinyFrame $W $H) }
    $lines = New-Object System.Collections.Generic.List[string]
    $panelRows = $totalRows - 3

    $all   = @($ctx.Programs)
    $view  = @(Get-InstalledView $ctx)
    $total = $view.Count

    $flabel = L 'inst.nofilter'
    if ($ctx.Filter) { $flabel = L 'inst.filter' $ctx.Filter }
    $lines.Add(($p.Bold + $p.Cyan + (Fit (L 'inst.header' $total $all.Count $flabel) $uw) + $p.Reset))

    $visible = $panelRows - 2
    if ($visible -lt 1) { $visible = 1 }
    if ($ctx.ISel -ge $total) { $ctx.ISel = [Math]::Max(0, $total - 1) }
    if ($ctx.ISel -lt $ctx.IScroll) { $ctx.IScroll = $ctx.ISel }
    if ($ctx.ISel -ge ($ctx.IScroll + $visible)) { $ctx.IScroll = $ctx.ISel - $visible + 1 }
    if ($ctx.IScroll -lt 0) { $ctx.IScroll = 0 }

    $inner = New-Object System.Collections.Generic.List[object]
    if ($total -eq 0) {
        $inner.Add(@{ Text = (L 'inst.empty'); Color = $p.Dim })
    } else {
        $nameW = [Math]::Min(44, [int]([Math]::Floor(($uw - 2) * 0.5)))
        for ($i = $ctx.IScroll; $i -lt [Math]::Min($ctx.IScroll + $visible, $total); $i++) {
            $prog = $view[$i]
            $cur = '  '
            if ($i -eq $ctx.ISel) { $cur = '> ' }
            $loc = "$($prog.Location)"
            if (-not $loc) { $loc = L 'inst.noloc' }
            $text  = $cur + (Fit "$($prog.Name)" $nameW) + '  ' + $loc
            $color = ''
            if ($i -eq $ctx.ISel) { $color = $p.SelItem }
            $inner.Add(@{ Text = $text; Color = $color })
        }
    }
    $btitle = L 'inst.title'
    if ($ctx.IScroll -gt 0) { $btitle += ' ' + $script:ArrowUp }
    if (($ctx.IScroll + $visible) -lt $total) { $btitle += ' ' + $script:ArrowDn }

    for ($r = 0; $r -lt $panelRows; $r++) {
        if ($r -eq 0) { $lines.Add(($p.Border + (New-BoxTop $btitle $uw) + $p.Reset)) }
        elseif ($r -eq ($panelRows - 1)) { $lines.Add(($p.Border + (New-BoxBottom $uw) + $p.Reset)) }
        else {
            $li = $r - 1
            $content = Fit '' ($uw - 2)
            $color = ''
            if ($li -lt $inner.Count) {
                $content = Fit $inner[$li].Text ($uw - 2)
                $color   = $inner[$li].Color
            }
            $lines.Add((New-BoxRow $content $uw $color))
        }
    }

    $lines.Add(($p.Yellow + (Fit (' ' + $ctx.Msg) $uw) + $p.Reset))
    $lines.Add(($p.Inv + (Fit (L 'keys.inst') $uw) + $p.Reset))
    return $lines
}

function Build-WizardRow([bool]$sel, [string]$cursor, [string]$mark, [string]$markColor, [string]$text, [string]$textColor, [int]$w) {
    # One list row rendered to EXACTLY w visible chars. Selected rows draw a
    # solid highlight bar; others color the mark and text separately.
    $p = $script:P
    if ($sel) {
        return $p.SelItem + (Fit ($cursor + $mark + $text) $w) + $p.Reset
    }
    $segs = @(
        @{ Text = $cursor; Color = '' },
        @{ Text = $mark;   Color = $markColor },
        @{ Text = $text;   Color = $textColor }
    )
    return (Render-Segments $segs $w)
}

function Build-WizardFrame($ctx, [int]$W, [int]$H) {
    # Onboarding wizard. Steps 0..5: language, welcome, theme, profiles
    # (multi-select), preview (per-app checkboxes + save), summary. Same
    # full-width line model as the other frames so the shared overlays and
    # RenderTest apply unchanged.
    $p  = $script:P
    $uw = $W - 1
    $totalRows = $H - 1
    if ($W -lt $script:MinW -or $H -lt $script:MinH) { return (Build-TinyFrame $W $H) }
    $wz = $ctx.Wizard
    $lines = New-Object System.Collections.Generic.List[string]
    $panelRows = $totalRows - 3
    $step = [int]$wz.Step
    $w2 = $uw - 2

    $hdr = L 'wizard.header' ($step + 1) 6
    $lines.Add(($p.Bold + $p.Cyan + (Fit ((L 'wizard.title') + '   ' + $hdr) $uw) + $p.Reset))

    $inner = New-Object System.Collections.Generic.List[string]
    $boxTitle = ''

    switch ($step) {
        0 {
            $boxTitle = L 'wizard.step.language'
            $langs = @('en','es')
            for ($i = 0; $i -lt $langs.Count; $i++) {
                $lc = $langs[$i]
                $cur = '  '; if ($i -eq $wz.LangSel) { $cur = '> ' }
                $isCur = ($script:Lang -eq $lc)
                $mark = '[ ] '; if ($isCur) { $mark = '[*] ' }
                $mc = $p.Dim; if ($isCur) { $mc = $p.Green }
                $inner.Add((Build-WizardRow ($i -eq $wz.LangSel) $cur $mark $mc (L ('wizard.lang.' + $lc)) '' $w2))
            }
        }
        1 {
            $boxTitle = L 'wizard.step.welcome'
            foreach ($k in @('wizard.welcome1','wizard.welcome2','wizard.welcome3','wizard.welcome4')) {
                $inner.Add((Fit ('  ' + (L $k)) $w2))
            }
        }
        2 {
            $boxTitle = L 'wizard.step.theme'
            $themes = @('Neon','Sobrio')
            for ($i = 0; $i -lt $themes.Count; $i++) {
                $tk = $themes[$i]
                $cur = '  '; if ($i -eq $wz.ThemeSel) { $cur = '> ' }
                $isCur = ($script:Theme -eq $tk)
                $mark = '[ ] '; if ($isCur) { $mark = '[*] ' }
                $mc = $p.Dim; if ($isCur) { $mc = $p.Green }
                $txt = (L ('theme.' + $tk.ToLowerInvariant())) + ' - ' + (L ('wizard.theme.' + $tk.ToLowerInvariant()))
                $inner.Add((Build-WizardRow ($i -eq $wz.ThemeSel) $cur $mark $mc $txt '' $w2))
            }
        }
        3 {
            $boxTitle = L 'wizard.step.profiles'
            for ($i = 0; $i -lt $script:OnboardProfileOrder.Count; $i++) {
                $pk = $script:OnboardProfileOrder[$i]
                $cur = '  '; if ($i -eq $wz.ProfSel) { $cur = '> ' }
                $on = [bool]$wz.Profiles[$pk]
                $mark = '[ ] '; if ($on) { $mark = '[x] ' }
                $mc = $p.Dim; if ($on) { $mc = $p.On }
                $txt = (L ('profile.' + $pk.ToLowerInvariant())) + ' - ' + (L ('profile.' + $pk.ToLowerInvariant() + '.desc'))
                $inner.Add((Build-WizardRow ($i -eq $wz.ProfSel) $cur $mark $mc $txt '' $w2))
            }
        }
        4 {
            $apps = @($wz.Apps)
            $onCount = @($apps | Where-Object { $_.Enabled }).Count
            $boxTitle = (L 'wizard.step.preview') + ' (' + $onCount + '/' + $apps.Count + ')'
            if ($apps.Count -eq 0) {
                $inner.Add((Build-WizardRow $false '  ' '' $p.Dim (L 'wizard.noapps') $p.Dim $w2))
            } else {
                for ($i = 0; $i -lt $apps.Count; $i++) {
                    $ap = $apps[$i]
                    $cur = '  '; if ($i -eq $wz.AppSel) { $cur = '> ' }
                    $mark = '[ ] '; if ($ap.Enabled) { $mark = '[x] ' }
                    $mc = $p.Dim; if ($ap.Enabled) { $mc = $p.On }
                    $tag = 'exe'
                    if ($ap.Type -eq 'Package') { $tag = 'uwp' } elseif ($ap.Type -eq 'Service') { $tag = 'svc' }
                    $inner.Add((Build-WizardRow ($i -eq $wz.AppSel) $cur $mark $mc ($tag + ' ' + $ap.Name) '' $w2))
                }
            }
        }
        default {
            $boxTitle = L 'wizard.step.summary'
            $inner.Add((Fit ('  ' + (L 'wizard.summary' $wz.Added)) $w2))
            $inner.Add((Fit '' $w2))
            $inner.Add((Fit ('  ' + (L 'wizard.finishhint')) $w2))
        }
    }

    $visible = $panelRows - 2
    if ($visible -lt 1) { $visible = 1 }
    $scroll = 0
    if ($step -eq 4) {
        $sel = [int]$wz.AppSel
        if ($sel -lt $wz.AppScroll) { $wz.AppScroll = $sel }
        if ($sel -ge ($wz.AppScroll + $visible)) { $wz.AppScroll = $sel - $visible + 1 }
        if ($wz.AppScroll -lt 0) { $wz.AppScroll = 0 }
        $scroll = $wz.AppScroll
        if ($scroll -gt 0) { $boxTitle += ' ' + $script:ArrowUp }
        if (($scroll + $visible) -lt $inner.Count) { $boxTitle += ' ' + $script:ArrowDn }
    }

    for ($r = 0; $r -lt $panelRows; $r++) {
        if ($r -eq 0) { $lines.Add(($p.Border + (New-BoxTop $boxTitle $uw) + $p.Reset)) }
        elseif ($r -eq ($panelRows - 1)) { $lines.Add(($p.Border + (New-BoxBottom $uw) + $p.Reset)) }
        else {
            $li = ($r - 1) + $scroll
            $content = Fit '' $w2
            if ($li -lt $inner.Count) { $content = $inner[$li] }
            $lines.Add((New-BoxRow $content $uw ''))
        }
    }

    $lines.Add(($p.Yellow + (Fit (' ' + $ctx.Msg) $uw) + $p.Reset))
    $lines.Add(($p.Inv + (Fit (L ('wizard.keys.' + $step)) $uw) + $p.Reset))
    return $lines
}

function Add-ModalOverlay($lines, $modal, [int]$uw, [int]$totalRows) {
    # Draw a centered s/n box over already-built frame lines. Whole lines get
    # replaced (padded to full width), so the underlying row is fully erased.
    $p = $script:P
    $b = $script:B
    $text = @($modal.Lines)
    $hint = L 'modal.hint'
    $mw = $hint.Length
    foreach ($t in $text) { if ($t.Length -gt $mw) { $mw = $t.Length } }
    $mw += 6
    if ($mw -gt ($uw - 2)) { $mw = $uw - 2 }
    if ($mw -lt 24) { $mw = 24 }
    $inner = $mw - 2
    $padStr = ' ' * [Math]::Max(0, [int](($uw - $mw) / 2))

    $rows = New-Object System.Collections.Generic.List[string]
    $rows.Add($b.TL + ($b.H * $inner) + $b.TR)
    foreach ($t in $text) { $rows.Add($b.V + (Fit ('  ' + $t) $inner) + $b.V) }
    $rows.Add($b.V + (Fit '' $inner) + $b.V)
    $rows.Add($b.V + (Fit ('  ' + $hint) $inner) + $b.V)
    $rows.Add($b.BL + ($b.H * $inner) + $b.BR)

    $top = [Math]::Max(1, [int](($totalRows - $rows.Count) / 2))
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $li = $top + $i
        if ($li -lt ($lines.Count - 1)) {
            $lines[$li] = $p.Yellow + (Fit ($padStr + $rows[$i]) $uw) + $p.Reset
        }
    }
}

function Add-MenuOverlay($lines, $menu, [int]$uw, [int]$totalRows) {
    # Small selectable popup (context menu) drawn over the frame. The selected
    # row is a solid inverse bar (red when it is the destructive 'Quitar').
    $p = $script:P
    $b = $script:B
    $items = @($menu.Items)
    $title = L 'menu.title'
    if ($menu.Title) { $title = $menu.Title }
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
        $rows.Add(@{ Plain = $rowPlain; Color = $rowColor; Whole = $true })
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

function Write-TuiFrame($lines) {
    $frame = ($lines -join "`r`n")
    if ($script:Vt) { [Console]::Write(([char]27) + '[H' + $frame) }
    else { [Console]::SetCursorPosition(0, 0); [Console]::Write($frame) }
}

# =====================================================================
#  TUI ACTIONS  (thin view layer: every real change goes through the same
#  functions the classic menu called; risky ones run in classic line mode)
# =====================================================================

function Invoke-LineMode([scriptblock]$body) {
    # Suspend the TUI: hand back a classic console so legacy Write-Host /
    # Read-Host flows behave exactly as before, then return to the frame loop.
    try { [Console]::TreatControlCAsInput = $false } catch {}
    try { [Console]::CursorVisible = $true } catch {}
    Clear-Host
    & $body
    Write-Host ''
    Write-Host (L 'line.back') -ForegroundColor DarkGray
    [Console]::ReadKey($true) | Out-Null
    try { [Console]::CursorVisible = $false } catch {}
    try { [Console]::TreatControlCAsInput = $true } catch {}
    Clear-Host
}

function New-TuiContext {
    @{
        View       = 'main'
        Zone       = 'list'          # 'actions' (button bar) or 'list' (whitelist)
        Items      = @(Read-WhitelistItems)
        Global     = Get-TuiGlobalState
        Sel        = 0
        Scroll     = 0
        ActionSel  = 0
        Actions    = @(
            @{ Id = 'activate' },
            @{ Id = 'deactivate' },
            @{ Id = 'seed' },
            @{ Id = 'installed' },
            @{ Id = 'more' },
            @{ Id = 'lang' },
            @{ Id = 'quit' }
        )
        Wizard     = $null           # onboarding wizard sub-state (see Start-Wizard)
        Menu       = $null           # context menu popup: @{ Items; Sel; Title }
        Msg        = (L 'msg.hello')
        Modal      = $null
        Running    = $true
        ExitDisable= $false
        Programs   = @()
        ISel       = 0
        IScroll    = 0
        Filter     = ''              # installed-programs view filter
        FilterMode = $false
        WlFilter   = ''              # whitelist (main list) filter
        WlFilterMode = $false
    }
}

function Invoke-TuiRefresh($ctx, [string]$msg) {
    $ctx.Items  = @(Read-WhitelistItems)
    $ctx.Global = Get-TuiGlobalState
    if ($PSBoundParameters.ContainsKey('msg') -and $null -ne $msg) { $ctx.Msg = $msg }
    $count = @(Get-VisibleItems $ctx).Count   # clamp to the filtered view, not the full list
    if ($ctx.Sel -ge $count -and $count -gt 0) { $ctx.Sel = $count - 1 }
    if ($ctx.Sel -lt 0) { $ctx.Sel = 0 }
}

function Open-Modal($ctx, [string[]]$text, [scriptblock]$onYes, [scriptblock]$onNo) {
    $ctx.Modal = @{ Lines = @($text); OnYes = $onYes; OnNo = $onNo }
}

function Invoke-ModalKey($ctx, $k) {
    $ch = ("$($k.KeyChar)").ToLowerInvariant()
    if ($ch -eq 's' -or $ch -eq 'y') {
        $m = $ctx.Modal
        $ctx.Modal = $null
        if ($m.OnYes) { & $m.OnYes }
    } elseif ($ch -eq 'n' -or $k.Key -eq 'Escape') {
        $m = $ctx.Modal
        $ctx.Modal = $null
        if ($m.OnNo) { & $m.OnNo }
    }
}

function Request-ReapplyModal($ctx) {
    # TUI counterpart of the old Offer-Reapply: same ACTIVE guard, same action.
    $s = Get-GameModeState
    if ($s.Status -ne 'ACTIVE') { return }
    Open-Modal $ctx @((L 'modal.reapply1'), (L 'modal.reapply2')) ({
        Invoke-LineMode { Update-GameModeRules }
        Invoke-TuiRefresh $ctx (L 'msg.reapplied')
    }.GetNewClosure())
}

function Invoke-WhitelistMutation($ctx, [scriptblock]$body, [string]$doneMsg) {
    # Run a whitelist-editing flow in line mode; offer rule reapply only if the
    # entry count actually changed and the mode is ACTIVE.
    $before = @(Load-Whitelist).Count
    Invoke-LineMode $body
    Invoke-TuiRefresh $ctx $doneMsg
    $after = @(Load-Whitelist).Count
    if ($after -ne $before) { Request-ReapplyModal $ctx }
}

function Invoke-ToggleSelected($ctx) {
    $idx = Get-SelectedIdx $ctx
    $wl = @(Load-Whitelist)
    if ($idx -lt 0 -or $idx -ge $wl.Count) { return }
    $it = $wl[$idx]
    $it.Enabled = -not $it.Enabled
    Save-Whitelist $wl
    $state = L 'state.off'
    if ($it.Enabled) { $state = L 'state.on' }
    Invoke-TuiRefresh $ctx (L 'msg.toggle' $it.Name $state)
    Request-ReapplyModal $ctx
}

function Invoke-RemoveSelected($ctx) {
    $idx = Get-SelectedIdx $ctx
    $wl = @(Load-Whitelist)
    if ($idx -lt 0 -or $idx -ge $wl.Count) { return }
    $victim = $wl[$idx]
    Open-Modal $ctx @((L 'modal.remove' $victim.Name)) ({
        $cur = @(Load-Whitelist)
        $new = New-Object System.Collections.Generic.List[object]
        for ($k = 0; $k -lt $cur.Count; $k++) { if ($k -ne $idx) { $new.Add($cur[$k]) } }
        Save-Whitelist $new.ToArray()
        Invoke-TuiRefresh $ctx (L 'msg.removed' $victim.Name)
        Request-ReapplyModal $ctx
    }.GetNewClosure())
}

function Invoke-AddEntryAction($ctx) {
    Invoke-WhitelistMutation $ctx {
        Write-Host (L 'addline.header') -ForegroundColor Cyan
        $n = (Read-Host (L 'addline.name')).Trim()
        $p2 = (Read-Host (L 'addline.path')).Trim().Trim('"')
        if ($n -and $p2) { Add-ToWhitelist $n $p2 }
        else { Write-Host (L 'addline.cancel') -ForegroundColor DarkGray }
    } (L 'msg.wlupdated')
}

function Invoke-SeedAction($ctx) {
    Invoke-WhitelistMutation $ctx {
        Write-Host (L 'seedline.header') -ForegroundColor Cyan
        Seed-KnownGames
    } (L 'msg.seeddone')
}

function Invoke-ActivateRequest($ctx) {
    $enabled = @(Load-Whitelist | Where-Object { $_.Enabled })
    if ($enabled.Count -eq 0) {
        $ctx.Msg = L 'msg.emptyactivate'
        return
    }
    Open-Modal $ctx @(
        (L 'modal.activate1' $enabled.Count),
        (L 'modal.activate2'),
        (L 'modal.activate3'),
        (L 'modal.activate4')
    ) ({
        Invoke-LineMode { Enable-GameMode }
        Invoke-TuiRefresh $ctx (L 'msg.ready')
    }.GetNewClosure())
}

function Invoke-DeactivateRequest($ctx) {
    $s = Get-GameModeState
    if ($s.Status -eq 'INACTIVE') {
        $ctx.Msg = L 'msg.alreadyinactive'
        return
    }
    Invoke-LineMode { Disable-GameMode }
    Invoke-TuiRefresh $ctx (L 'msg.inetrestored')
}

function Invoke-RepairRequest($ctx) {
    Open-Modal $ctx @((L 'modal.repair1'), (L 'modal.repair2')) ({
        Invoke-LineMode { Repair-GameMode }
        Invoke-TuiRefresh $ctx (L 'msg.normalized')
    }.GetNewClosure())
}

function Invoke-OpenInstalled($ctx) {
    # Registry scan takes a moment: paint an interim frame so the UI does not
    # look frozen while Get-InstalledPrograms runs.
    $ctx.Msg = L 'msg.reading'
    try { Write-TuiFrame (Build-MainFrame $ctx ([Console]::WindowWidth) ([Console]::WindowHeight)) } catch {}
    $ctx.Programs   = @(Get-InstalledPrograms)
    $ctx.ISel       = 0
    $ctx.IScroll    = 0
    $ctx.Filter     = ''
    $ctx.FilterMode = $false
    $ctx.View       = 'installed'
    $ctx.Msg        = L 'msg.installedhint'
}

function Toggle-Language($ctx) {
    if ($script:Lang -eq 'es') { $script:Lang = 'en' } else { $script:Lang = 'es' }
    $script:Config.lang = $script:Lang
    try { Save-Config $script:Config } catch {}
    $ctx.Msg = L 'msg.langchanged'
}

function Set-Theme($ctx, [string]$theme) {
    # Switch palette immediately (re-run Initialize-Style) and persist the choice.
    if ($theme -ne 'Neon' -and $theme -ne 'Sobrio') { return }
    $script:Theme = $theme
    $script:Config.theme = $theme
    try { Save-Config $script:Config } catch {}
    Initialize-Style
    if ($ctx) { $ctx.Msg = L 'msg.themechanged' (L ('theme.' + $theme.ToLowerInvariant())) }
}

function Toggle-Theme($ctx) {
    if ($script:Theme -eq 'Neon') { Set-Theme $ctx 'Sobrio' } else { Set-Theme $ctx 'Neon' }
}

function Invoke-QuitRequest($ctx) {
    $s = Get-GameModeState
    if ($s.Status -eq 'ACTIVE') {
        Open-Modal $ctx @(
            (L 'modal.quit1'),
            (L 'modal.quit2'),
            (L 'modal.quit3')
        ) ({
            $ctx.ExitDisable = $true
            $ctx.Running = $false
        }.GetNewClosure()) ({
            $ctx.Running = $false
        }.GetNewClosure())
    } else {
        $ctx.Running = $false
    }
}

function Start-Wizard($ctx) {
    # Prepare wizard state. Pre-tick profiles from a prior run, else default to
    # Games (this is a gaming firewall). Never touches the firewall.
    $profs = @{}
    foreach ($k in $script:OnboardProfileOrder) { $profs[$k] = $false }
    $saved = @($script:Config.profiles)
    if ($saved.Count -gt 0) {
        foreach ($k in $saved) { if ($profs.ContainsKey("$k")) { $profs["$k"] = $true } }
    } else {
        $profs['Games'] = $true
    }
    $themeSel = 0; if ($script:Theme -eq 'Sobrio') { $themeSel = 1 }
    $langSel = 0; if ($script:Lang -eq 'es') { $langSel = 1 }
    $ctx.Wizard = @{
        Step = 0; Profiles = $profs; ProfSel = 0; LangSel = $langSel
        Apps = @(); AppSel = 0; AppScroll = 0; Added = 0; ThemeSel = $themeSel
    }
    $ctx.Menu  = $null
    $ctx.View  = 'wizard'
    $ctx.Msg   = L 'wizard.lang.hint'
}

function Complete-Wizard($ctx) {
    # Persist choices and return to the main view. Marks onboarding done so the
    # wizard does not reappear on the next launch.
    $sel = @($script:OnboardProfileOrder | Where-Object { $ctx.Wizard.Profiles[$_] })
    $script:Config.onboardedVersion = $OnboardVersion
    $script:Config.lang     = $script:Lang
    $script:Config.theme    = $script:Theme
    $script:Config.profiles = $sel
    try { Save-Config $script:Config } catch {}
    $ctx.Wizard = $null
    $ctx.View   = 'main'
    Invoke-TuiRefresh $ctx (L 'wizard.done')
}

function Enter-WizardPreview($ctx) {
    # Transition into the preview step: resolve apps for the ticked profiles.
    # Paint an interim frame first (detection can take a moment).
    $ctx.Msg = L 'wizard.detecting'
    try { Write-TuiFrame (Build-WizardFrame $ctx ([Console]::WindowWidth) ([Console]::WindowHeight)) } catch {}
    $sel = @($script:OnboardProfileOrder | Where-Object { $ctx.Wizard.Profiles[$_] })
    $ctx.Wizard.Apps      = @(Resolve-ProfileApps $sel)
    $ctx.Wizard.AppSel    = 0
    $ctx.Wizard.AppScroll = 0
    $ctx.Wizard.Step      = 4
    $ctx.Msg = L 'wizard.previewhint'
}

function Save-WizardSelection($ctx) {
    # Add only the ticked apps to the whitelist (Enabled), via the idempotent
    # adders. Runs in line mode so their console output does not corrupt frames.
    $ticked = @($ctx.Wizard.Apps | Where-Object { $_.Enabled })
    Invoke-LineMode ({
        foreach ($app in $ticked) {
            switch ($app.Type) {
                'Package' { Add-PackageToWhitelist $app.Name $app.Package }
                'Service' { Add-ServiceToWhitelist $app.Name $app.Service }
                default   { Add-ToWhitelist $app.Name $app.Path }
            }
        }
        Write-Host ''
        Write-Host (L 'wizard.saved' $ticked.Count) -ForegroundColor Green
    }.GetNewClosure())
    $ctx.Wizard.Added = $ticked.Count
    $ctx.Wizard.Step  = 5
    Invoke-TuiRefresh $ctx (L 'wizard.savedmsg' $ticked.Count)
}

function Request-ResetConfig($ctx) {
    # Double confirmation: reset config, then optionally empty the whitelist,
    # then relaunch the wizard. No firewall action.
    Open-Modal $ctx @((L 'reset.confirm1'), (L 'reset.confirm2')) ({
        Remove-Config
        $script:Config = New-DefaultConfig
        Open-Modal $ctx @((L 'reset.wl1'), (L 'reset.wl2')) ({
            Save-Whitelist @()
            Invoke-TuiRefresh $ctx (L 'reset.donewl')
            Start-Wizard $ctx
        }.GetNewClosure()) ({
            Invoke-TuiRefresh $ctx (L 'reset.donecfg')
            Start-Wizard $ctx
        }.GetNewClosure())
    }.GetNewClosure())
}

function Open-SystemMenu($ctx) {
    # The 'More' popup: actions that do not fit the top button bar.
    $mi = New-Object System.Collections.Generic.List[object]
    $mi.Add(@{ Id = 'repair';   Label = (L 'menu.repair') })
    $mi.Add(@{ Id = 'wizard';   Label = (L 'menu.wizard') })
    $mi.Add(@{ Id = 'theme';    Label = (L 'menu.theme') })
    $mi.Add(@{ Id = 'resetcfg'; Label = (L 'menu.reset') })
    $ctx.Menu = @{ Items = $mi.ToArray(); Sel = 0; Title = (L 'menu.system.title') }
}

function Apply-WizardLang($ctx) {
    # Apply the language picked at step 0 live so the rest of the wizard shows
    # in it immediately. Texts use L (uncached), so the next frame re-labels.
    $lc = @('en','es')[$ctx.Wizard.LangSel]
    $script:Lang = $lc
    $ctx.Msg = L 'wizard.lang.hint'
}

function Invoke-WizardKey($ctx, $k) {
    $wz = $ctx.Wizard
    $step = [int]$wz.Step
    switch ($step) {
        0 {
            switch ($k.Key) {
                'UpArrow'    { if ($wz.LangSel -gt 0) { $wz.LangSel-- }; Apply-WizardLang $ctx; return }
                'DownArrow'  { if ($wz.LangSel -lt 1) { $wz.LangSel++ }; Apply-WizardLang $ctx; return }
                'Spacebar'   { Apply-WizardLang $ctx; return }
                'Enter'      { Apply-WizardLang $ctx; $wz.Step = 1; return }
                'RightArrow' { Apply-WizardLang $ctx; $wz.Step = 1; return }
                'Escape'     { Complete-Wizard $ctx; return }
            }
            if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { Complete-Wizard $ctx }
            return
        }
        1 {
            if ($k.Key -eq 'Enter' -or $k.Key -eq 'RightArrow' -or $k.Key -eq 'Spacebar') { $wz.Step = 2; return }
            if ($k.Key -eq 'LeftArrow' -or $k.Key -eq 'Escape') { $wz.Step = 0; return }
            return
        }
        2 {
            switch ($k.Key) {
                'UpArrow'    { if ($wz.ThemeSel -gt 0) { $wz.ThemeSel-- }; Set-Theme $ctx (@('Neon','Sobrio')[$wz.ThemeSel]); return }
                'DownArrow'  { if ($wz.ThemeSel -lt 1) { $wz.ThemeSel++ }; Set-Theme $ctx (@('Neon','Sobrio')[$wz.ThemeSel]); return }
                'Spacebar'   { Set-Theme $ctx (@('Neon','Sobrio')[$wz.ThemeSel]); return }
                'Enter'      { $wz.Step = 3; return }
                'RightArrow' { $wz.Step = 3; return }
                'LeftArrow'  { $wz.Step = 1; return }
                'Escape'     { $wz.Step = 1; return }
            }
            return
        }
        3 {
            $n = $script:OnboardProfileOrder.Count
            switch ($k.Key) {
                'UpArrow'    { if ($wz.ProfSel -gt 0) { $wz.ProfSel-- }; return }
                'DownArrow'  { if ($wz.ProfSel -lt ($n - 1)) { $wz.ProfSel++ }; return }
                'Home'       { $wz.ProfSel = 0; return }
                'End'        { $wz.ProfSel = $n - 1; return }
                'Spacebar'   { $pk = $script:OnboardProfileOrder[$wz.ProfSel]; $wz.Profiles[$pk] = -not $wz.Profiles[$pk]; return }
                'Enter'      { Enter-WizardPreview $ctx; return }
                'RightArrow' { Enter-WizardPreview $ctx; return }
                'LeftArrow'  { $wz.Step = 2; return }
                'Escape'     { $wz.Step = 2; return }
            }
            return
        }
        4 {
            $n = @($wz.Apps).Count
            switch ($k.Key) {
                'UpArrow'    { if ($wz.AppSel -gt 0) { $wz.AppSel-- }; return }
                'DownArrow'  { if ($wz.AppSel -lt ($n - 1)) { $wz.AppSel++ }; return }
                'PageUp'     { $wz.AppSel = [Math]::Max(0, $wz.AppSel - 10); return }
                'PageDown'   { if ($n -gt 0) { $wz.AppSel = [Math]::Min($n - 1, $wz.AppSel + 10) }; return }
                'Home'       { $wz.AppSel = 0; return }
                'End'        { if ($n -gt 0) { $wz.AppSel = $n - 1 }; return }
                'Spacebar'   { if ($n -gt 0) { $wz.Apps[$wz.AppSel].Enabled = -not $wz.Apps[$wz.AppSel].Enabled }; return }
                'Enter'      { Save-WizardSelection $ctx; return }
                'LeftArrow'  { $wz.Step = 3; return }
                'Escape'     { $wz.Step = 3; return }
            }
            if (("$($k.KeyChar)").ToLowerInvariant() -eq 'g') { Save-WizardSelection $ctx }
            return
        }
        default {
            if ($k.Key -eq 'Enter' -or $k.Key -eq 'Spacebar') { Complete-Wizard $ctx; return }
            if ($k.Key -eq 'LeftArrow') { $wz.Step = 4; return }
            if ($k.Key -eq 'Escape') { Complete-Wizard $ctx; return }
            return
        }
    }
}

function Invoke-ActionButton($ctx) {
    switch ($ctx.Actions[$ctx.ActionSel].Id) {
        'activate'   { Invoke-ActivateRequest $ctx }
        'deactivate' { Invoke-DeactivateRequest $ctx }
        'seed'       { Invoke-SeedAction $ctx }
        'installed'  { Invoke-OpenInstalled $ctx }
        'more'       { Open-SystemMenu $ctx }
        'lang'       { Toggle-Language $ctx }
        'quit'       { Invoke-QuitRequest $ctx }
    }
}

function Open-ContextMenu($ctx) {
    # Per-item actions (Enter on the list). With 0 items only 'Agregar por ruta'
    # is offered so add-by-path is always reachable without stray shortcuts.
    $vis = @(Get-VisibleItems $ctx)
    $count = $vis.Count
    $mi = New-Object System.Collections.Generic.List[object]
    if ($count -gt 0 -and $ctx.Sel -lt $count) {
        $it = $vis[$ctx.Sel]
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

function Invoke-MenuKey($ctx, $k) {
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
            switch ($id) {
                'toggle' { Invoke-ToggleSelected $ctx }
                'add'    { Invoke-AddEntryAction $ctx }
                'remove' { Invoke-RemoveSelected $ctx }
                'detail' {
                    $vis = @(Get-VisibleItems $ctx)
                    if ($vis.Count -gt 0 -and $ctx.Sel -lt $vis.Count) {
                        $it = $vis[$ctx.Sel]
                        $ctx.Msg = L 'msg.detail' $it.Name $it.Target
                    }
                }
                'repair'   { Invoke-RepairRequest $ctx }
                'wizard'   { Start-Wizard $ctx }
                'theme'    { Toggle-Theme $ctx }
                'resetcfg' { Request-ResetConfig $ctx }
            }
            return
        }
    }
    if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { $ctx.Menu = $null }
}

function Invoke-MainKey($ctx, $k) {
    # Two focus zones. Tab toggles; the list can also reach the bar by pressing
    # Up on the first item, and the bar reaches the list with Down. Everything
    # is reachable with Tab/arrows/Enter/Esc; Space stays as a list shortcut.
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
            'Enter'      { Invoke-ActionButton $ctx; return }
            'Spacebar'   { Invoke-ActionButton $ctx; return }
            'F5'         { Invoke-TuiRefresh $ctx (L 'msg.refreshed'); return }
            'Escape'     { Invoke-QuitRequest $ctx; return }
        }
        if (("$($k.KeyChar)").ToLowerInvariant() -eq 'q') { Invoke-QuitRequest $ctx }
        return
    }

    # list zone
    $count = @(Get-VisibleItems $ctx).Count
    switch ($k.Key) {
        'UpArrow'   { if ($ctx.Sel -gt 0) { $ctx.Sel-- } else { $ctx.Zone = 'actions' }; return }
        'DownArrow' { if ($ctx.Sel -lt ($count - 1)) { $ctx.Sel++ }; return }
        'PageUp'    { $ctx.Sel = [Math]::Max(0, $ctx.Sel - 10); return }
        'PageDown'  { if ($count -gt 0) { $ctx.Sel = [Math]::Min($count - 1, $ctx.Sel + 10) }; return }
        'Home'      { $ctx.Sel = 0; return }
        'End'       { if ($count -gt 0) { $ctx.Sel = $count - 1 }; return }
        'Spacebar'  { Invoke-ToggleSelected $ctx; return }
        'Enter'     { Open-ContextMenu $ctx; return }
        'Delete'    { Invoke-RemoveSelected $ctx; return }
        'F5'        { Invoke-TuiRefresh $ctx (L 'msg.refreshed'); return }
        'Backspace' {
            if ($ctx.WlFilter.Length -gt 0) { $ctx.WlFilter = $ctx.WlFilter.Substring(0, $ctx.WlFilter.Length - 1); $ctx.Sel = 0; $ctx.Scroll = 0 }
            return
        }
        'Escape'    {
            if ($ctx.WlFilter) { $ctx.WlFilter = ''; $ctx.Sel = 0; $ctx.Scroll = 0 }
            else { Invoke-QuitRequest $ctx }
            return
        }
    }
    # type-to-filter: any printable char extends the filter (no '/' needed). Space is the
    # on/off shortcut (handled above), so it never enters the filter.
    $ch = $k.KeyChar
    if ($ch -and ([int]$ch) -ge 32) {
        if (-not $ctx.WlFilter -and ("$ch").ToLowerInvariant() -eq 'q') { Invoke-QuitRequest $ctx; return }
        $ctx.WlFilter += $ch; $ctx.Sel = 0; $ctx.Scroll = 0
    }
}

function Invoke-InstalledKey($ctx, $k) {
    $view  = @(Get-InstalledView $ctx)
    $count = $view.Count
    switch ($k.Key) {
        'UpArrow'   { if ($ctx.ISel -gt 0) { $ctx.ISel-- }; return }
        'DownArrow' { if ($ctx.ISel -lt ($count - 1)) { $ctx.ISel++ }; return }
        'PageUp'    { $ctx.ISel = [Math]::Max(0, $ctx.ISel - 15); return }
        'PageDown'  { if ($count -gt 0) { $ctx.ISel = [Math]::Min($count - 1, $ctx.ISel + 15) }; return }
        'Home'      { $ctx.ISel = 0; return }
        'End'       { if ($count -gt 0) { $ctx.ISel = $count - 1 }; return }
        'Enter'     {
            if ($count -gt 0 -and $ctx.ISel -lt $count) {
                $prog = $view[$ctx.ISel]
                Invoke-WhitelistMutation $ctx ({ Select-ExeForProgram $prog }.GetNewClosure()) (L 'msg.donerevisit')
            }
            return
        }
        'Backspace' {
            if ($ctx.Filter.Length -gt 0) { $ctx.Filter = $ctx.Filter.Substring(0, $ctx.Filter.Length - 1); $ctx.ISel = 0; $ctx.IScroll = 0 }
            return
        }
        'Escape'    {
            if ($ctx.Filter) { $ctx.Filter = ''; $ctx.ISel = 0; $ctx.IScroll = 0 }
            else { $ctx.View = 'main'; Invoke-TuiRefresh $ctx (L 'msg.backmain') }
            return
        }
    }
    # type-to-filter: any printable char extends the filter (no '/' needed).
    $ch = $k.KeyChar
    if ($ch -and ([int]$ch) -ge 32) { $ctx.Filter += $ch; $ctx.ISel = 0; $ctx.IScroll = 0 }
}

function Invoke-TuiLoop($ctx) {
    $lastW = -1
    $lastH = -1
    while ($ctx.Running) {
        $W = [Console]::WindowWidth
        $H = [Console]::WindowHeight
        if ($W -ne $lastW -or $H -ne $lastH) {
            # resize: full clear once, then buffered frames again
            Clear-Host
            $lastW = $W
            $lastH = $H
        }

        $lines = $null
        if ($ctx.View -eq 'wizard') { $lines = Build-WizardFrame $ctx $W $H }
        elseif ($ctx.View -eq 'installed') { $lines = Build-InstalledFrame $ctx $W $H }
        else { $lines = Build-MainFrame $ctx $W $H }
        if ($ctx.Menu)  { Add-MenuOverlay  $lines $ctx.Menu  ($W - 1) ($H - 1) }
        if ($ctx.Modal) { Add-ModalOverlay $lines $ctx.Modal ($W - 1) ($H - 1) }
        Write-TuiFrame $lines

        # poll: wake on key OR on window resize (ReadKey alone would block)
        $resized = $false
        while (-not [Console]::KeyAvailable) {
            Start-Sleep -Milliseconds 80
            if ([Console]::WindowWidth -ne $lastW -or [Console]::WindowHeight -ne $lastH) { $resized = $true; break }
        }
        if ($resized) { continue }

        $k = [Console]::ReadKey($true)
        if ($ctx.Modal) { Invoke-ModalKey $ctx $k }
        elseif ($ctx.Menu) { Invoke-MenuKey $ctx $k }
        elseif ($ctx.View -eq 'wizard') { Invoke-WizardKey $ctx $k }
        elseif ($ctx.View -eq 'installed') { Invoke-InstalledKey $ctx $k }
        else { Invoke-MainKey $ctx $k }

        $count = @($ctx.Items).Count
        if ($ctx.Sel -ge $count -and $count -gt 0) { $ctx.Sel = $count - 1 }
        if ($ctx.Sel -lt 0) { $ctx.Sel = 0 }
    }
}

# =====================================================================
#  DISPATCH CLI + ENTRADA INTERACTIVA
# =====================================================================

if ($RenderTest) {
    # Headless render self-check: build frames at fixed sizes with the real
    # (read-only) data, dump one, and verify no line overflows its width
    # (a wrapped line would break the whole layout). Exits 0 on success.
    $script:Vt = $false
    Initialize-Style
    $ctx = New-TuiContext
    ((Build-MainFrame $ctx 100 30) -join "`r`n") | Write-Output

    $ok = $true
    $ctx.Programs = @(
        [pscustomobject]@{ Name = 'Mock Program A'; Location = 'C:\Mock\A'; Icon = $null },
        [pscustomobject]@{ Name = 'Mock Program B with a very long display name to force render truncation paths'; Location = $null; Icon = $null }
    )
    $menu = @{ Items = @(
        @{ Id = 'toggle'; Label = (L 'menu.toggle_off') },
        @{ Id = 'add';    Label = (L 'menu.add') },
        @{ Id = 'detail'; Label = (L 'menu.detail') },
        @{ Id = 'remove'; Label = (L 'menu.remove') }
    ); Sel = 3 }
    foreach ($size in @(@(100,30), @(70,15), @(120,40))) {
        foreach ($viewName in @('main','installed')) {
            foreach ($zone in @('list','actions')) {
                $ctx.View = $viewName
                $ctx.Zone = $zone
                $ctx.Scroll = 0
                $ctx.IScroll = 0
                $f = $null
                if ($viewName -eq 'installed') { $f = Build-InstalledFrame $ctx $size[0] $size[1] }
                else { $f = Build-MainFrame $ctx $size[0] $size[1] }
                # overlay both popups to exercise their width math too
                Add-MenuOverlay  $f $menu ($size[0] - 1) ($size[1] - 1)
                Add-ModalOverlay $f @{ Lines = @('Test modal: yes/no?') } ($size[0] - 1) ($size[1] - 1)
                foreach ($ln in $f) {
                    if ($ln.Length -gt ($size[0] - 1)) {
                        Write-Output ('RENDERTEST-FAIL: overflow ' + $viewName + '/' + $zone + ' at ' + $size[0] + 'x' + $size[1] + ' len=' + $ln.Length)
                        $ok = $false
                    }
                }
            }
        }
    }

    # ---- wizard sweep: every step at every size, with mock apps in preview ---
    $ctx.Wizard = @{
        Step = 0; LangSel = 1; ProfSel = 1; AppSel = 1; AppScroll = 0; Added = 3; ThemeSel = 1
        Profiles = @{}
        Apps = @(
            [pscustomobject]@{ Name = 'Mock App One'; Type = 'Exe'; Path = 'C:\Mock\one.exe'; Package = ''; Service = ''; Profile = 'Games'; Enabled = $true },
            [pscustomobject]@{ Name = 'Mock App Two with a very long name to force truncation in the preview list'; Type = 'Package'; Path = ''; Package = 'Mock.Pkg_x'; Service = ''; Profile = 'Games'; Enabled = $false },
            [pscustomobject]@{ Name = 'Mock Service'; Type = 'Service'; Path = ''; Package = ''; Service = 'MockSvc'; Profile = 'Work'; Enabled = $true }
        )
    }
    foreach ($pk in $script:OnboardProfileOrder) { $ctx.Wizard.Profiles[$pk] = $false }
    $ctx.Wizard.Profiles['Games'] = $true
    $ctx.View = 'wizard'
    foreach ($size in @(@(100,30), @(70,15), @(120,40))) {
        for ($ws = 0; $ws -le 5; $ws++) {
            $ctx.Wizard.Step = $ws
            $ctx.Wizard.AppScroll = 0
            $f = Build-WizardFrame $ctx $size[0] $size[1]
            # per-step sentinel: the header always carries 'step N/6' in either language
            $sent = ($ws + 1).ToString() + '/6'
            if (($f -join "`n") -notmatch [regex]::Escape($sent)) {
                Write-Output ('RENDERTEST-FAIL: wizard sentinel step' + $ws + ' at ' + $size[0] + 'x' + $size[1])
                $ok = $false
            }
            # overlay both popups to exercise their width math on the wizard too
            Add-MenuOverlay  $f $menu ($size[0] - 1) ($size[1] - 1)
            Add-ModalOverlay $f @{ Lines = @('Reset config: yes/no?') } ($size[0] - 1) ($size[1] - 1)
            foreach ($ln in $f) {
                if ($ln.Length -gt ($size[0] - 1)) {
                    Write-Output ('RENDERTEST-FAIL: overflow wizard/step' + $ws + ' at ' + $size[0] + 'x' + $size[1] + ' len=' + $ln.Length)
                    $ok = $false
                }
            }
        }
    }
    $ctx.Wizard = $null

    $ctx.View = 'main'
    $ctx.Zone = 'list'
    $tiny = ((Build-MainFrame $ctx 40 10) -join "`n")
    # language-agnostic: the tiny frame always carries the [q] quit hint
    if ($tiny -notmatch '\[q\]') { Write-Output 'RENDERTEST-FAIL: tiny branch'; $ok = $false }
    if ($ok) { Write-Output 'RENDERTEST-OK'; exit 0 }
    exit 1
}

if ($DryRun) {
    Write-Host (L 'disp.dryactivate') -ForegroundColor Cyan
    Enable-GameMode -DryRun
    Write-Host ""
    Write-Host (L 'disp.drydeactivate') -ForegroundColor Cyan
    Disable-GameMode -DryRun
    return
}

if ($Off) {
    Write-Host (L 'disp.offhdr') -ForegroundColor Cyan
    $s = Get-GameModeState
    if ($s.Status -eq 'INACTIVE') { Write-Host (L 'disp.offalready') -ForegroundColor Gray }
    else { Disable-GameMode; Write-Host (L 'disp.offdone') -ForegroundColor Green }
    return
}

if ($On) {
    Write-Host (L 'disp.onhdr') -ForegroundColor Cyan
    Enable-GameMode
    return
}

if ($RegisterFailSafe) {
    Write-Host (L 'disp.fshdr') -ForegroundColor Cyan
    if (Register-FailSafeTask) { Write-Host (L 'disp.fsok') -ForegroundColor Green }
    else { Write-Host (L 'disp.fsfail') -ForegroundColor Red }
    return
}

# ---- TUI interactiva ---------------------------------------------------------
$origEncoding = $null
$origCtrlC    = $null
$tuiError     = $null
$tuiCtx = New-TuiContext
try {
    if (-not $NoVt) { $script:Vt = Enable-VtProcessing }
    Initialize-Style
    try {
        $origEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    } catch {}
    try {
        $origCtrlC = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
    } catch {}
    try { [Console]::CursorVisible = $false } catch {}
    Clear-Host
    # First run (or a bumped onboarding version): open the wizard before the
    # main view. This only reads apps and writes config/whitelist; never the firewall.
    if (-not (Test-Onboarded $script:Config)) { Start-Wizard $tuiCtx }
    Invoke-TuiLoop $tuiCtx
}
catch {
    # keep the error: the finally below clears the screen and would hide it
    $tuiError = $_
}
finally {
    # leave the console exactly as we found it
    try { if ($script:Vt) { [Console]::Write(([char]27) + '[0m') } } catch {}
    try { [Console]::CursorVisible = $true } catch {}
    try { if ($null -ne $origCtrlC) { [Console]::TreatControlCAsInput = $origCtrlC } } catch {}
    try { if ($null -ne $origEncoding) { [Console]::OutputEncoding = $origEncoding } } catch {}
    try { Clear-Host } catch {}
}

if ($null -ne $tuiError) {
    Write-Host ""
    Write-Host (L 'exit.err' $tuiError.Exception.Message) -ForegroundColor Red
    Write-Host (L 'exit.errhint') -ForegroundColor Yellow
}

# Confirmed on the exit modal: restore the internet in plain console so the
# result stays visible after the TUI is gone.
if ($tuiCtx.ExitDisable) { Disable-GameMode }

# Warn on exit if the block is still active (system rules, not process-bound).
$final = Get-GameModeState
if ($final.Status -eq 'ACTIVE') {
    Write-Host ""
    Write-Host (L 'exit.stillon1') -ForegroundColor Yellow
    Write-Host (L 'exit.stillon2') -ForegroundColor Yellow
}
Write-Host (L 'exit.bye') -ForegroundColor Gray
