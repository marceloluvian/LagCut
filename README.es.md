[English](README.md) | **Español**

# LagCut

**Bloquea toda conexión de salida excepto las apps que tú elijas — para que tu juego se lleve el ancho de banda, no el ruido de fondo.**

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![Windows PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![Requiere administrador](https://img.shields.io/badge/requiere-Administrador-critical)

LagCut es una herramienta chica de consola para Windows que funciona como un interruptor de firewall. Cuando está encendido, solo los programas de tu **lista de permitidos** (más lo esencial que Windows necesita para seguir en la red) pueden salir a internet. Todo lo demás —los navegadores que dejaste abiertos, las actualizaciones de Windows y de la Store, la sincronización de la nube, los launchers, la telemetría— se queda callado hasta que lo vuelves a apagar.

De eso se trata: esas apps de fondo compiten por tu conexión y meten jitter y picos de lag justo cuando estás en plena partida. LagCut las saca del camino con una sola tecla y deja todo tal como estaba cuando terminas.

> LagCut no baja tu ping por sí solo — eso es la ruta hacia el servidor. Lo que hace es liberar tu ancho de banda local para que nada en tu casa le pelee la conexión a tu juego.

## Cómo funciona

Cuando presionas **Activar**, LagCut pone la acción de salida del firewall en **Block** en los tres perfiles (Domain, Private, Public) y agrega reglas **Allow** explícitas para:

- cada app que hayas encendido en tu lista de permitidos, y
- lo esencial: DNS, DHCP, tráfico de LAN, ICMP (ping) y NTP (reloj). Si usas DNS cifrado (DoH), se permite solo hacia tu servidor DNS configurado, no hacia todo internet.

Una regla Allow explícita le gana al Block por defecto, así que solo tus apps y lo esencial pasan. Todas las reglas viven bajo un único grupo `GameMode`, lo que significa que **Desactivar** las quita de forma limpia y restaura exactamente el estado de salida que tenías antes.

## Funciones

| Función | Qué hace |
|---|---|
| **Activar / Desactivar de un clic** | Enciende o apaga todo el bloqueo desde la barra de botones de arriba. |
| **Lista de permitidos** | Agrega apps Exe, apps UWP (de la Store) y servicios de Windows. Enciende o apaga cada entrada, agrega una por ruta, o escribe para filtrar la lista. |
| **Asistente de primer inicio** | Te guía por el idioma, el tema de color y los perfiles; luego detecta tus apps instaladas y las precarga con casillas para que revises antes de guardar nada. |
| **Perfiles** | Grupos de selección múltiple —Juegos, Navegadores, Programación, Diseño, IA, Trabajo/Comunicación— que ya saben dónde viven las apps típicas y las encuentran por ti. |
| **Interfaz bilingüe** | Inglés / Español, cambiable en cualquier momento desde la barra de botones. |
| **Temas de color** | Neon (vivo) o Sobrio (más tranquilo). |
| **Menú "Más"** | Reparar, Asistente, Cambiar tema, Reiniciar configuración. |
| **Seguro de reinicio** | Registra una tarea de inicio para que, si Windows se reinicia con el bloqueo encendido, tu internet se restaure solo. |

## Vista previa de la interfaz

<!-- (agrega aquí una captura real, por ejemplo docs/screenshot.png) -->

```
 MODO JUEGO (firewall)                              MODO JUEGO ACTIVO
 [ Activar ] [ Desactivar ] [ Detectar ] [ Programas ] [ Mas ] [ ES ] [ Salir ]
 +- Permitidos (5) * ----------++- Detalle ---------------------+
 | > [x] exe  League of Legends|| Nombre : League of Legends    |
 |   [x] exe  Riot Client      || Tipo   : Exe (.exe)           |
 |   [x] uwp  Xbox             || Destino: C:\Riot Games\...    |
 |   [ ] exe  Steam            || Estado : encendido            |
 |   [x] svc  GamingServices   || Archivo: OK                   |
 |                             |+- Estado general --------------+
 |                             || Domain : Block                |
 |                             || Private: Block                |
 |                             || Public : Block                |
 |                             || Reglas : 14 (grupo GameMode)  |
 +-----------------------------++-------------------------------+
 Tab: zona   arriba/abajo mueve   Enter: accion   Espacio: on/off   Esc: salir
```

## Instalación

1. Descarga o clona esta carpeta en cualquier parte de tu PC.
2. Ejecuta `install.ps1`. Crea un acceso directo **LagCut** en tu Escritorio que abre la herramienta como administrador (se necesita administrador para tocar el firewall).
3. Doble clic en **LagCut** para abrirla. La primera vez, el asistente te ayuda a configurarla.

También puedes correr la herramienta directamente:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\LagCut.ps1
```

Se eleva sola con el aviso estándar de Windows (UAC) cuando necesita permisos de administrador.

## Uso rápido

Muévete con las flechas y acciona con Enter.

- **Tab** — cambia entre la barra de botones y la lista de permitidos.
- **Izquierda / Derecha** — te mueves entre los botones; **Enter** o **Espacio** dispara el que esté seleccionado.
- **Arriba / Abajo** — te mueves por la lista de permitidos.
- **Espacio** — enciende/apaga la app seleccionada.
- **Enter** (sobre una entrada de la lista) — abre sus acciones: Encender/Apagar, Agregar por ruta, Ver detalle, Quitar.
- **Escribe** — empieza a filtrar la lista; **Esc** limpia el filtro, o sale.
- **Más** — Reparar, Asistente, Cambiar tema, Reiniciar configuración.

Activar y Desactivar son los dos primeros botones. Detectar busca en las carpetas típicas de juegos; Programas te deja elegir de todo lo instalado.

## Perfiles y temas

El asistente (y el menú **Más**) te dejan elegir entre seis perfiles: **Juegos, Navegadores, Programación, Diseño, IA, Trabajo/Comunicación**. Cada uno detecta las apps que de verdad tienes instaladas y las muestra con casillas — no se agrega nada hasta que confirmas.

Vienen dos temas: **Neon**, de colores vivos y saturados, y **Sobrio**, para un aspecto más tranquilo. Cámbialo cuando quieras desde **Más → Cambiar tema**.

## Seguridad y cómo recuperar tu internet

LagCut está hecho para ser reversible y difícil de dejarte atorado:

- El **asistente nunca activa el firewall** — solo lee tus apps y guarda tu lista.
- **Desactivar** restaura el estado de salida anterior para todos los programas y quita todas las reglas `GameMode`.
- Un **seguro de reinicio** restaura el internet automáticamente si la PC se reinicia con el bloqueo encendido.
- `LagCut-Off.ps1` es un "botón de pánico" de un solo uso que lo apaga todo.

Si tu conexión quedó cortada y algo salió mal, cualquiera de estas te regresa en línea:

1. Vuelve a abrir LagCut y presiona **Desactivar**.
2. Corre `powershell -NoProfile -ExecutionPolicy Bypass -File .\LagCut.ps1 -Off`.
3. Corre `LagCut-Off.ps1`.
4. Reinicia la PC — el seguro de reinicio restaura el internet al arrancar.

> Mientras el bloqueo está encendido, Windows puede mostrar un aviso de "Sin internet". Es normal: lo que se bloquea es el chequeo de conectividad, pero tus apps permitidas sí tienen conexión real.

## Requisitos

- Windows 10 u 11
- Windows PowerShell 5.1
- Permisos de administrador (necesarios para cambiar el firewall)

---

Hecho por Juan Marcelo Luvián ([@marceloluvian](https://github.com/marceloluvian)). Si LagCut te devuelve un par de partidas limpias, cumplió su trabajo.
