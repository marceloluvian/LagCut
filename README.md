<p align="center">
  <img src="assets/banner.svg" alt="LagCut — block everything except your games" width="100%">
</p>

# LagCut 🎮

**Does your ping spike mid-match for no reason?** Your game shouldn't have to fight Windows Update, cloud sync, and a dozen background apps for bandwidth. LagCut cuts all of it off — everything except your games — with one keystroke. It won't lower your ISP's ping, but it clears the *local* congestion that turns into jitter at the worst possible moment.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

## Overview

When you're mid-match, everything else on the PC is still talking to the internet: browsers, Windows and Store updates, cloud sync, telemetry, and idle launchers all compete for your upstream bandwidth. On a busy connection that shows up as jitter and latency spikes right when it hurts.

LagCut flips a single switch. It blocks **all** outbound internet traffic and then re-allows only a whitelist you control (your games) plus the handful of protocols a machine needs to stay on the network. Turn it off and your connection returns to exactly the state it was in before.

It does **not** lower your ISP's ping — that's the route to the server, and nothing local can change it. What it does is remove *local* contention so background transfers stop stealing bandwidth from the game.

The whole thing runs from a keyboard-driven terminal interface, or fully from the command line if you'd rather script it.

## Features

- **Whitelist-based outbound blocking** — only the apps you authorize can reach the internet while the mode is on.
- **Three whitelist types** — executables (`.exe`), Microsoft Store apps (UWP, matched by package), and Windows services.
- **Auto-detection** — finds common games in their usual locations (Riot Client, League of Legends, Riot Vanguard) and Xbox / Store apps, so you start with a sensible list.
- **Exact-state restore** — the previous firewall configuration is snapshotted before activation and restored byte-for-byte on deactivation.
- **Reboot fail-safe** — a startup task restores your internet automatically if Windows reboots while the mode is active.
- **Panic button** — a standalone script restores everything without depending on the main tool.
- **Dry run** — preview every rule and profile change before anything touches the firewall.
- **Two-pane terminal interface** — colored VT/ANSI output with an automatic ASCII fallback for consoles that don't support it.
- **Self-elevating** — prompts for administrator rights via UAC when it needs them.

## How it works

LagCut sets `DefaultOutboundAction = Block` on all three Windows Firewall profiles (Domain, Private, Public), then creates outbound `Allow` rules — all under a single rule group named **GameMode** — for each whitelisted app plus the essentials:

- DNS (UDP/TCP 53) and DNS-over-HTTPS (443, restricted to your configured resolver IPs only)
- DHCP and DHCPv6
- NTP (time sync)
- Local subnet / LAN traffic
- ICMPv4 and ICMPv6 (ping)

In the Windows Filtering Platform an explicit `Allow` rule wins over the default `Block`, so the net result is: your games and the essentials get out, everything else is silently dropped. Because every rule lives under the **GameMode** group, deactivation is a clean sweep — the group is removed and the default outbound action is restored from the saved snapshot.

## Interface

```text
 GAME MODE (firewall)                          MODE ACTIVE
 [ On ]  Off   Detect   Programs   Repair   Quit
+- Whitelist (6) * -------------+- Details ----------------------------+
| > [x] exe  League of Legends  || Name   : League of Legends          |
|   [x] exe  Riot Client        || Type   : Exe (.exe)                 |
|   [x] exe  VALORANT           || Target : C:\Riot Games\...\Game.exe |
|   [ ] exe  vgc (Vanguard)     || State  : enabled                    |
|   [x] uwp  Xbox               || File   : OK                         |
|   [x] svc  GamingServices     |+- Global state ----------------------+
|                               || Domain  : Block                     |
|                               || Private : Block                     |
|                               || Public  : Block                     |
|                               || Rules   : 14 (group GameMode)       |
|                               || State   : present (reversible)      |
|                               || FailSafe: registered (AtStartup)    |
+-------------------------------+--------------------------------------+
 Tab: switch zone | up/down: move | left/right: buttons | Enter: action | Space: on/off | Esc: quit
```

The left pane is the whitelist; `[x]` / `[ ]` marks whether each entry is armed, and the `exe` / `uwp` / `svc` tag shows its type. The right pane shows the selected item's details on top and the live firewall state below (per-profile action, active rule count, snapshot presence, fail-safe status). The action bar sits at the top; the key hints run along the bottom.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1, or PowerShell 7
- Administrator privileges — the tool self-elevates through UAC (it has to modify the firewall)

## Installation

No installer or dependencies. Clone or download the repository, then run `install.ps1` once to drop a Desktop shortcut that launches the tool as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

You can also run `LagCut.ps1` directly from a PowerShell prompt — it will request elevation on its own.

Want to see the interface first without touching anything? Run the read-only preview (no admin required):

```powershell
powershell -ExecutionPolicy Bypass -File .\LagCut-Preview.ps1
```

## Usage

Launch `LagCut.ps1` (or the Desktop shortcut) to open the interface. Build your whitelist with **Detect** (auto-discovery), **Programs** (pick from installed software), or add an executable by its path, then arm the entries you want and hit **On**.

### Command-line flags

For scripting or quick toggles, skip the interface entirely:

| Flag | Action |
|---|---|
| `-On` | Activate game mode and exit |
| `-Off` | Deactivate, restore internet, and exit |
| `-DryRun` | Preview the rules and profile changes without applying anything |
| `-RegisterFailSafe` | Register the reboot fail-safe task without touching the firewall |
| `-NoVt` | Force plain ASCII mode (no color, no VT box drawing) |
| `-RenderTest` | Render diagnostic — draws one frame and exits (no admin required) |

```powershell
# Preview what activation would do
powershell -ExecutionPolicy Bypass -File .\LagCut.ps1 -DryRun

# Turn it on, then off
powershell -ExecutionPolicy Bypass -File .\LagCut.ps1 -On
powershell -ExecutionPolicy Bypass -File .\LagCut.ps1 -Off
```

### Keys

| Key | Action |
|---|---|
| `Tab` | Switch focus between the action bar and the list |
| `←` `→` | Move along the action bar (On / Off / Detect / Programs / Repair / Quit) |
| `↑` `↓` | Move through the whitelist |
| `Enter` | Run the focused button, or open the selected item's menu (toggle, add by path, view details, remove) |
| `Space` | Toggle the selected item on/off |
| `Esc` | Close the menu / go back |
| `q` | Quit |

## Safety & reversibility

This is the part that matters most, so it's built to fail safe:

- **Snapshot before change.** The current `DefaultOutboundAction` of every profile is written to `state.json` *before* the firewall is touched. Deactivation restores those exact values — if a profile was `Allow`, it goes back to `Allow`; if it was `NotConfigured`, it goes back to `NotConfigured`.
- **Reboot fail-safe.** On activation, a scheduled task (`GameMode-FailSafe`, running as SYSTEM at startup) is registered. If Windows reboots while the mode is active, that task restores your internet and cleans up on its own — you never get stranded with the firewall locked down.
- **Panic button.** `LagCut-Off.ps1` restores everything independently of the main tool: it puts the outbound action back, removes the **GameMode** rule group, deletes the fail-safe task, and clears the snapshot. Use it if anything ever looks wrong.
- **Anti-lockout ordering.** Activation aborts before changing the firewall if it can't write the snapshot first, so there's always a known-good state to roll back to.

If the tool ever detects a partial or inconsistent state (say, rules present but the snapshot missing), the **Repair** action normalizes everything back to a clean, internet-open baseline.

## Notes & FAQ

**The network icon says "No internet" while the mode is active.** That's expected. Windows checks connectivity with a background probe (NCSI) that LagCut blocks along with everything else non-whitelisted. Your game still has full network access — only the connectivity check is being dropped. It clears the moment you deactivate.

**The borders or arrows look garbled.** Some legacy consoles don't handle VT/ANSI sequences. Run with `-NoVt` to force plain ASCII, or use a modern terminal.

**Where are my whitelist and saved state stored?** In `whitelist.json` and `state.json` next to the script. Both are per-machine and are excluded from version control via `.gitignore`.

**Does this reduce my ping?** No — latency to the game server is set by the network path to it. LagCut removes *local* bandwidth contention, which reduces jitter and spikes caused by background traffic saturating your connection.

## Repository layout

| File | Purpose |
|---|---|
| `LagCut.ps1` | Main tool — the terminal interface and firewall logic |
| `LagCut-Off.ps1` | Emergency restorer (panic button) |
| `install.ps1` | Creates the "run as administrator" Desktop shortcut |
| `LagCut-Preview.ps1` | Read-only preview of the interface — no admin, no firewall changes |
| `README.md` | This file |
| `LICENSE` | MIT license |
| `.gitignore` | Excludes local data (`whitelist.json`, `state.json`) |

## License

Released under the MIT License. Copyright © 2026 Juan Marcelo Luvián.

See [LICENSE](LICENSE) for the full text.
