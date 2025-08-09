## Classic Dota 6.84 One‑Click Installer (Windows)

This repo provides a one‑click PowerShell installer for the community Dota 2 Classic 6.84 (Source 1) build.

### Features
- Uses a bundled `Dota_6.84.zip.torrent` if present (auto‑downloads portable aria2c)
- Falls back to Mega.nz (if MEGAcmd is installed) or Google Drive
- Extracts game to `C:\Games\Dota_6.84` (configurable)
- Creates `dota/cfg/autoexec.cfg` with common defaults
- Adds Windows Firewall rules, optional hosts block for `www.dota2.com`
- Installs prerequisites (DirectX June 2010, VC++ x86/x64)
- Creates a Desktop launcher and opens the queue page

See `Install/README.md` for usage.

### License
Code in this repository is licensed under the MIT License (see `LICENSE`). Game assets and binaries are not included; downloads are user‑initiated from community mirrors.


