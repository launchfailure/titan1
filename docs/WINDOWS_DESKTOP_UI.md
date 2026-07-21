# Windows Desktop Workbench

Titan's Windows workbench is a native PySide6 application. It runs directly on
Windows, receives Explorer drag-and-drop events, and supplies the taskbar icon
and desktop integration. Primary analysis is delegated to Titan running inside
Debian through WSL.

This arrangement gives the interface native Windows behavior while keeping the
analysis environment in Debian. WSL is a genuine Linux environment, but it is
not a security boundary for executing hostile samples. Titan performs static
analysis and does not require recovered payloads to be run.

## Components

| Component | Runs in | Purpose |
|---|---|---|
| `titan-ui` / `Titan-Windows.cmd` | Windows | Native PySide6 desktop workbench |
| `debian_bridge` | Debian under WSL | Runs Titan analysis and returns the report |
| `titan-tui` / `titan-workbench-ui` | Current terminal | Optional Textual terminal workbench |
| `titan-workbench` | Current terminal | Dependency-free completed-report explorer |

The native and terminal workbenches are separate interfaces. `titan-ui` is not
an alias for `titan-tui`.

## Prerequisites

- Windows 10 or Windows 11;
- Python 3.10 or newer installed on Windows;
- WSL with a distribution named `Debian`;
- the Titan repository stored on a Windows drive that Debian can access under
  `/mnt`, such as `C:\path\to\titan1` and `/mnt/c/path/to/titan1`.

Check the installed WSL distributions from PowerShell:

```powershell
wsl --list --verbose
```

If the Debian distribution uses another name, see
[Choose another Debian distribution](#choose-another-debian-distribution).

## One-time setup

The launcher and bridge intentionally use two different virtual environments.
Keep their names exactly as shown.

### 1. Prepare the Debian analysis environment

Open Debian, change to the repository through its `/mnt` path, and create the
`.venv` environment:

```bash
cd /mnt/c/path/to/titan1
sudo apt update
sudo apt install -y python3-venv
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

Replace the example repository path with the location of your clone. The
Windows bridge invokes `.venv/bin/python` directly, so activating this
environment is not required when the desktop application runs.

### 2. Prepare the native Windows environment

Open PowerShell in the same repository and create `.venv-windows`:

```powershell
cd C:\path\to\titan1
py -m venv .venv-windows
.\.venv-windows\Scripts\python.exe -m pip install --upgrade pip
.\.venv-windows\Scripts\python.exe -m pip install -e ".[desktop-ui]"
```

This installs Titan, PySide6, and the native desktop assets into the Windows
environment. The environments are machine-local and are not committed to the
repository.

## Launch

From PowerShell or File Explorer, run:

```powershell
.\Titan-Windows.cmd
```

The launcher uses `.venv-windows\Scripts\pythonw.exe`, so it opens the
workbench without a separate console window. For debugging, keep a console and
launch the module directly:

```powershell
.\.venv-windows\Scripts\python.exe -m titan_decoder.desktop_ui.app
```

After activating `.venv-windows`, `titan-ui` launches the same native module.

## How analysis crosses into Debian

```text
Explorer drop or file picker
        -> native PySide6 workbench on Windows
        -> wsl.exe -d Debian
        -> .venv/bin/python -m titan_decoder.desktop_ui.debian_bridge
        -> deterministic Titan report
        -> native workbench results
```

The bridge translates ordinary drive paths such as
`C:\Evidence\sample.bin` to `/mnt/c/Evidence/sample.bin`. Pasted text and byte
input are transferred as encoded data instead of being written to a temporary
file.

The **Analyze** actions use the Debian bridge. A manually selected decoder in
the right-hand Decoder Workbench runs in the native process against the data
already loaded into the UI.

## Drag and drop

Drop a local file or folder from Windows File Explorer onto the large **DROP
FILES HERE** area. The native application receives the Explorer event and
starts analysis. Clicking the drop area opens Titan's dark file picker, and
pressing `A` opens the text-input action.

If a file can be selected in the picker but cannot be dropped, confirm that:

1. the native `Titan-Windows.cmd`/`titan-ui` application is running, rather
   than `titan-tui` inside Windows Terminal;
2. File Explorer and Titan run at the same privilege level—Windows blocks
   drag-and-drop from a non-elevated process into an elevated process;
3. the source is a local file or folder with a path visible to Debian under
   `/mnt`.

Terminal emulators cannot provide the same native Explorer event to a Textual
application. `titan-tui` accepts a path when the terminal turns a drop into
bracketed pasted text, but that behavior depends on the terminal.

## Workbench controls

- **PROFILE** cycles the analysis profile.
- **NETWORK** starts in offline mode. Enabling it displays a warning because
  network-capable analyzers or plugins may send hashes, indicators, URLs,
  domains, or other sample-derived data to external services. Titan does not
  automatically upload the evidence file, but plugin behavior is controlled by
  the plugin. Enable online mode only when investigation policy permits it.
- **AGGRESSIVE** enables deeper and lower-confidence decoding attempts. It may
  find more candidates and also produce more noise.
- **Recent samples** retains archived sample records independently of whether
  an item is hidden from **Latest Analysis Results**.

## Choose another Debian distribution

The default WSL distribution name is `Debian`. Override it before launching:

```powershell
$env:TITAN_WSL_DISTRIBUTION = "Debian-Testing"
.\Titan-Windows.cmd
```

Use the exact name reported by `wsl --list --verbose`. Set the variable in the
user environment if the choice should persist across PowerShell sessions.

For frontend development only, the Debian bridge can be bypassed so analysis
runs in the Windows process:

```powershell
$env:TITAN_DESKTOP_BACKEND = "local"
.\Titan-Windows.cmd
```

The supported Windows deployment uses the default `debian` backend. The local
override is useful for UI tests and troubleshooting, not as additional sample
isolation.

## Troubleshooting

### The launcher says the Windows environment is not installed

Create `.venv-windows` and install `.[desktop-ui]` using the Windows setup
commands above. The launcher requires
`.venv-windows\Scripts\pythonw.exe` in the repository.

### The Debian analysis backend failed

Verify all three layers:

```powershell
wsl --list --verbose
wsl -d Debian -- bash -lc "cd /mnt/c/path/to/titan1 && .venv/bin/python -c 'import titan_decoder; print(titan_decoder.__version__)'"
```

Adjust the repository path and distribution name. If the second command fails,
recreate the Debian `.venv` and reinstall Titan from inside Debian.

### A moved clone no longer analyzes

Both environments use editable installs, and the bridge locates Debian from the
native source tree. Reinstall Titan in `.venv-windows` and `.venv` after moving
the repository.

### The desktop shortcut has the wrong icon

Point the shortcut at `Titan-Windows.cmd` and choose
`titan_decoder\desktop_ui\assets\titan-metallic.ico` as its icon. Windows may
cache old shortcut artwork; recreating the shortcut or restarting Explorer
refreshes that cache.

## Safety boundary

Treat unknown input as untrusted even when Titan reports no findings. A static
result is evidence, not permission to execute the sample. WSL shares resources
and filesystem access with its Windows host and must not be described as a VM
detonation boundary. Use Titan's assurance controls and an approved isolated VM
workflow when a conclusive verdict requires dynamic execution.
