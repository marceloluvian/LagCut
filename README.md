**English** | [Español](README.es.md)

# LagCut

**Block every outbound connection except the apps you choose — so your game gets the bandwidth, not the background noise.**

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![Windows PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![Admin required](https://img.shields.io/badge/requires-Administrator-critical)

LagCut is a small Windows console tool that works like a firewall switch. When it's on, only the programs in your **allow list** (plus the essentials Windows needs to stay on the network) can reach the internet. Everything else — browsers you left open, Windows and Store updates, cloud sync, launchers, telemetry — goes quiet until you turn it back off.

That's the whole point: those background apps compete for your connection and add jitter and lag spikes right when you're in a match. LagCut cuts them out of the picture with one keystroke, and puts everything back exactly as it was when you're done.

> LagCut doesn't lower your ping by itself — that's your route to the server. What it does is free up your local bandwidth so nothing at home is fighting your game for it.

## How it works

When you press **Turn On**, LagCut sets the firewall's default outbound action to **Block** on all three profiles (Domain, Private, Public) and adds explicit **Allow** rules for:

- every app you enabled in your allow list, and
- the essentials: DNS, DHCP, LAN traffic, ICMP (ping) and NTP (clock). If you use encrypted DNS (DoH), it's allowed only to your configured DNS server, not the whole internet.

An explicit Allow wins over the default Block, so only your apps and the essentials get through. Every rule lives under a single `GameMode` group, which means **Turn Off** removes them cleanly and restores the exact outbound state you had before.

## Features

| Feature | What it does |
|---|---|
| **One-click Turn On / Turn Off** | Flip the whole block on or off from the top button bar. |
| **Allow list** | Add Exe, UWP (Store) apps and Windows services. Enable or disable each entry, add one by path, or type to filter the list. |
| **First-run assistant** | Walks you through language, color theme and profiles, then detects your installed apps and pre-loads them with checkboxes so you review before anything is saved. |
| **Profiles** | Multi-select buckets — Games, Browsers, Programming, Design, AI, Work/Comms — that know where the usual apps live and find them for you. |
| **Bilingual UI** | English / Spanish, switchable at any time from the button bar. |
| **Color themes** | Neon (vivid) or Sober (calmer). |
| **"More" menu** | Repair, Assistant, Switch theme, Reset settings. |
| **Reboot fail-safe** | Registers a startup task so that if Windows reboots while the block is on, your internet is restored on its own. |

## Interface preview

<!-- (add a real screenshot here, e.g. docs/screenshot.png) -->

```
 GAME MODE (firewall)                                    GAME MODE ON
 [ Turn On ] [ Turn Off ] [ Detect ] [ Programs ] [ More ] [ EN ] [ Quit ]
 +- Allow list (5) * ----------++- Detail ----------------------+
 | > [x] exe  League of Legends|| Name   : League of Legends    |
 |   [x] exe  Riot Client      || Type   : Exe (.exe)           |
 |   [x] uwp  Xbox             || Target : C:\Riot Games\...    |
 |   [ ] exe  Steam            || State  : on                   |
 |   [x] svc  GamingServices   || File   : OK                   |
 |                             |+- Global state ----------------+
 |                             || Domain : Block                |
 |                             || Private: Block                |
 |                             || Public : Block                |
 |                             || Rules  : 14 (group GameMode)  |
 +-----------------------------++-------------------------------+
 Tab: zone   up/down move   Enter: action   Space: on/off   Esc: quit
```

## Installation

1. Download or clone this folder anywhere on your PC.
2. Run `install.ps1`. It creates a **LagCut** shortcut on your Desktop that launches the tool as administrator (admin is required to change the firewall).
3. Double-click **LagCut** to open it. The first time, the assistant helps you set it up.

You can also run the tool directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\LagCut.ps1
```

It self-elevates through the standard Windows (UAC) prompt when it needs admin rights.

## Quick use

Navigate with the arrow keys and act with Enter.

- **Tab** — move between the button bar and the allow list.
- **Left / Right** — move across the buttons; **Enter** or **Space** triggers the selected one.
- **Up / Down** — move through the allow list.
- **Space** — enable/disable the selected app.
- **Enter** (on a list item) — open its actions: Enable/Disable, Add by path, View detail, Remove.
- **Type** — start filtering the list; **Esc** clears the filter, or quits.
- **More** — Repair, Assistant, Switch theme, Reset settings.

Turn On and Turn Off are the first two buttons. Detect scans the usual game folders; Programs lets you pick from everything installed.

## Profiles and themes

The assistant (and the **More** menu) let you pick from six profiles: **Games, Browsers, Programming, Design, AI, Work/Comms**. Each one detects the apps you actually have installed and shows them with checkboxes — nothing is added until you confirm.

Two themes ship in the box: **Neon** for vivid, saturated colors and **Sober** for a calmer look. Switch anytime from **More → Switch theme**.

## Safety and how to get your internet back

LagCut is built to be reversible and hard to get stuck in:

- The setup **assistant never turns the firewall on** — it only reads your apps and saves your list.
- **Turn Off** restores your previous outbound state for every program and removes all `GameMode` rules.
- A **reboot fail-safe** restores the internet automatically if the PC reboots while the block is on.
- `LagCut-Off.ps1` is a one-shot "panic button" that turns everything off.

If your connection is cut and something went sideways, any of these gets you back online:

1. Reopen LagCut and press **Turn Off**.
2. Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\LagCut.ps1 -Off`.
3. Run `LagCut-Off.ps1`.
4. Restart the PC — the fail-safe restores the internet on startup.

> While the block is on, Windows may show a "No internet" indicator. That's normal: the connectivity check itself is blocked, but your allowed apps still have a real connection.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1
- Administrator rights (needed to change the firewall)

---

Made by Juan Marcelo Luvián ([@marceloluvian](https://github.com/marceloluvian)). If LagCut buys back a few clean matches, it did its job.
