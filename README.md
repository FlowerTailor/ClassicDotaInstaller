## Dota 2 Classic 6.84 One-Click Installer (Windows)

This folder contains a PowerShell script that installs and configures the community Dota 2 Classic 6.84 client on Windows. 
PRESS THE GREEN "CODE" BUTTON AND SELECT "DOWNLOAD ZIP" to obtain the installer. 

### What it does
- Installs from a local archive you provide (ZIP/7z)
- Extracts to `C:\Games\Dota_6.84` by default (customizable)
- Creates common settings in `dota/cfg/autoexec.cfg`
- Adds Windows Firewall allow rules for the game
- Optionally blocks `www.dota2.com` in `hosts` to reduce lag
- Optionally installs prerequisites (DirectX June 2010, VC++ x86/x64)
-  opens the queue/sign-in pages

### Requirements
- Windows 10/11
- Run as Administrator (the script will auto-elevate)
- Steam must be running before launching the game
- You need an archive of the original game data 

### HOW TO USE (Recommended: GUI)
- Double‑click `Install/Install-Dota684-GUI.bat` and follow the wizard.  Thats it! select your archive and if you want, customize your download folder. 
- The script should install all the prerequisites and add the firewall exceptions and configuration autoamtically. 
- Not possible to offer integrated downloading of the patches yet. 


- Or run the GUI directly via PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
cd <path-to-repo>\Install
powershell -ExecutionPolicy Bypass -File .\Install-Dota684-GUI.ps1
```

### Command‑line (alternative)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
cd <path-to-repo>\Install
powershell -ExecutionPolicy Bypass -File .\Install-Dota684.ps1 -OpenQueue -BlockDota2Site -InstallPrereqs
```

Options:
- `-InstallDir "D:\Games\Dota_6.84"` set a custom installation directory
- `-BlockDota2Site` toggles a hosts entry `0.0.0.0 www.dota2.com`
- `-InstallPrereqs` installs DirectX June 2010 + VC++ 2015-2019 x86/x64 silently
- `-OpenQueue` opens the Sign-in and Queue pages after install
 

Place the archive next to the script with one of these names:
- `Dota_6.84.zip` (preferred)
- `Dota_2_6.84_Source_1_(1504).7z`

ZIPs are extracted using Windows' `Expand-Archive`. 7z requires 7-Zip on PATH.

### Where to get the archive
- Google Drive: https://drive.google.com/file/d/13wnnUYpUeYP7PJQ1dSZpS8W-CTCjati6/view
- Mega: https://mega.nz/file/UPgSgAxS#Snc3ITt7mtm-qfW38Ye0j9eBU_Es20G8TC9N_Q8f5Sw
- MediaFire: https://www.mediafire.com/file/37a334itg8iv6zz/Dota_2_6.84_Source_1_%281504%29.7z/file


### Launching and playing
- Double-click the Desktop shortcut `Launch Dota 6.84.bat` (ensure Steam is open)
- If there is no desktop shortcut just go to the selected install folder of the game and double-click the dota.exe
- Sign in and queue: `https://dota2classic.com/Auth/signin?redirectUrl=/&authProvider=Steam` then `https://dota2classic.com/queue`
- Alternatively use the Discord queue channels after linking your account

### Autoexec defaults
Created at `dota/cfg/autoexec.cfg` if missing:

```
dota_minimap_hero_size 1300
dota_force_right_click_attack 1
dota_player_auto_repeat_right_mouse 1
dota_camera_disable_zoom 1
bind "a" "mc_attack; +sixense_left_click; -sixense_left_click"
```

### Troubleshooting
- Steam error: Ensure Steam is running; restart if needed
- DirectX/VC++ errors: run with `-InstallPrereqs`
- Unable to connect: firewall may block; rule is created automatically, but check your antivirus/firewall too
- Server connect: use the console `connect <ip>:<port>` if clicking link fails
- Low FPS/Lag: consider `-BlockDota2Site` to add `0.0.0.0 www.dota2.com` to hosts; remove the line to revert
- Overlays: disable Discord/GeForce Experience/RivaTuner overlays

Linux/Mac users: see `https://dota2classic.com/Download` for Proton/Wine instructions.

Let me know if there are any features you desire for version 2! 


