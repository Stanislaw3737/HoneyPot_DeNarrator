# DeNarrator

DeNarrator is a terminal-focused honeypot / obfuscation layer that can wrap a shell session and present fake, discouraging system information to anyone doing basic reconnaissance.

There are three main implementations in this folder:

- **PowerShell** (`DeNarrator.ps1`) – Windows PowerShell session wrapper.
- **Python** (`denarrator.py`) – cross-platform interactive honeypot shell.
- **Bash / Linux** (`denarrator.sh`) – Linux-oriented honeypot shell with Linux-style fake outputs.

All variants share the same basic ideas:

- Generate **fake, evolving system logs** in `logs/fake_system.log`.
- Return **plausible but deceptive information** for common recon commands.
- Maintain a **key-based bypass** using `key.txt` so the real owner can safely control activation.

---

## Files

- `DeNarrator.ps1` – PowerShell implementation.
- `denarrator.py` – Python implementation.
- `denarrator.sh` – Bash/Linux implementation.
- `logs/` – directory where fake log history is written.
  - `fake_system.log` – evolving fake system log generated in the background (shared across implementations).
- `key.txt` – secret key file automatically created on first activation, used to securely enable/disable honeypot behavior.

---

## 1. PowerShell version (`DeNarrator.ps1`)

### Requirements

- Windows with PowerShell (tested with Windows PowerShell 5.x).
- Permission to run scripts:
  - You may need to use `-ExecutionPolicy Bypass` or adjust your execution policy.

### Installation and activation

1. Place the `DeNarrator` folder somewhere under your user profile (or anywhere you like).
2. Ensure `DeNarrator.ps1` is present inside the `DeNarrator` folder.
3. Open a PowerShell session.
4. From the directory that contains the `DeNarrator` folder, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\DeNarrator\DeNarrator.ps1 -Activate
```

This starts DeNarrator **in that PowerShell process**.

You should see:

> [DeNarrator] Honeypot active in this session.

### Wrapped commands (fake outputs)

When active, the PowerShell script defines wrapper functions in the current session for:

- `systeminfo`
- `hostname`
- `whoami`
- `ipconfig`
- `Get-ComputerInfo`
- `Get-EventLog`

These wrappers:

- Return **fake but consistent identity details**, such as hostname, domain, username, OS, IP, MAC, BIOS/UUID.
- Construct output in a format that resembles normal command output, so the deception looks natural.

Example commands to test:

```powershell
systeminfo
hostname
whoami
ipconfig
Get-ComputerInfo
Get-EventLog -LogName System -Newest 10
```

### Background fake log generator (PowerShell)

On activation, DeNarrator starts a background PowerShell job that:

- Writes to `logs/fake_system.log`.
- Appends believable events at random intervals, e.g. backup jobs, disk warnings, failed logins, firewall rejections.

View the fake logs directly:

```powershell
Get-Content .\DeNarrator\logs\fake_system.log -Tail 20
```

### Key-based bypass (PowerShell)

On first run, a key is generated and saved to `key.txt` in the same folder as `DeNarrator.ps1`.

Read your key:

```powershell
Get-Content .\DeNarrator\key.txt
```

To use key-based control, **dot-source** the script so its functions are loaded into your existing session:

```powershell
cd .\DeNarrator
. .\DeNarrator.ps1    # note the leading dot and space
```

Assume your key is `YOUR_KEY_HERE`.

Enable (or re-enable) DeNarrator in the current session:

```powershell
Use-DeNarratorKey -Key 'YOUR_KEY_HERE'
```

Disable DeNarrator and restore real behavior:

```powershell
Use-DeNarratorKey -Key 'YOUR_KEY_HERE' -Disable
```

Disabling will:

- Stop and remove the background job.
- Remove the fake wrappers.
- Return commands like `systeminfo`, `hostname`, `whoami`, etc. to their original behavior for that session.

### PowerShell-specific limitations

- Affects **only the PowerShell session** where it is loaded/activated.
- Does **not** intercept commands in CMD, WSL, or other shells.
- Does **not** change the underlying system configuration; it only changes what selected commands return.
- If PowerShell is restarted, DeNarrator must be explicitly reactivated in each new session.

---

## 2. Python version (`denarrator.py`)

The Python version is a cross-platform honeypot shell that uses the same fake identity and log file but implements its own REPL.

### Requirements

- Python 3.8+ installed.
- Ability to run `python` or `python3` from your shell.

### Basic usage (interactive shell)

From inside the `DeNarrator` folder:

```bash
python denarrator.py --shell
# or just
python denarrator.py
```

This will:

- Ensure `key.txt` exists (generating it if needed).
- Start the background log generator thread.
- Drop you into an interactive shell:

```text
[DeNarrator] Python honeypot shell. Type 'help' for commands, 'exit' to quit.
denarrator>
```

Available commands inside the Python shell:

- `systeminfo` – fake Windows-style system info.
- `hostname` – fake hostname.
- `whoami` – fake domain\user.
- `ipconfig` – fake network info.
- `logs` – tail of `logs/fake_system.log`.
- `real <command>` – run a real OS command in a subshell.
- `help` – show help text.
- `exit` / `quit` – leave the shell.

Example session:

```text
denarrator> systeminfo
denarrator> hostname
denarrator> whoami
denarrator> ipconfig
denarrator> logs
```

### Background activation/deactivation with key (Python)

The Python script also supports a key-based activate/deactivate mode similar to the PowerShell core.

1. Read your key (shared with other implementations):

```bash
cat key.txt
```

2. Activate background honeypot logic (logs only, no REPL):

```bash
python denarrator.py --activate --key YOUR_KEY_HERE
```

3. Deactivate and stop background logs:

```bash
python denarrator.py --deactivate --key YOUR_KEY_HERE
```

Notes:

- In this version, the interactive shell is where the fake command behavior is implemented.
- `--activate` / `--deactivate` focus on controlling logging and internal state.

---

## 3. Bash / Linux version (`denarrator.sh`)

The Bash version is tailored for Linux (or WSL) and returns Linux-style fake outputs.

### Requirements

- A Linux system (or WSL) with:
  - `bash`
  - standard user-space tools (`tail`, `head`, `date`, etc.).

### Make it executable

From inside the `DeNarrator` folder:

```bash
chmod +x denarrator.sh
```

### Start the wrapped Linux shell

```bash
./denarrator.sh --shell
# or simply
./denarrator.sh
```

You will see:

```text
[DeNarrator] Linux honeypot shell. Type 'help' for commands, 'exit' to quit.
denarrator>
```

Available commands inside the Bash shell:

- `uname [-a|-r|-n|-m]` – fake kernel/system info.
- `hostname` – fake hostname.
- `whoami` – fake user account.
- `ip a` / `ip addr` / `ip address` – fake `ip` output with loopback and one `eth0` interface.
- `cat /etc/os-release` – fake distro info (Ubuntu 20.04 LTS-style).
- `uptime` – fake uptime and load averages.
- `free -h` – fake memory usage.
- `logs` – tail of `logs/fake_system.log`.
- `real <command>` – run a real command in a subshell.
- `exit` / `quit` – leave the shell.

Example session:

```text
denarrator> uname -a
denarrator> hostname
denarrator> whoami
denarrator> ip a
denarrator> cat /etc/os-release
denarrator> uptime
denarrator> free -h
denarrator> logs
```

### Background activation/deactivation with key (Bash)

The Bash script also honors `key.txt` and can run just the background logger.

1. Read your key:

```bash
cat key.txt
```

2. Activate background fake logs only:

```bash
./denarrator.sh --activate --key YOUR_KEY_HERE
```

3. Deactivate background fake logs:

```bash
./denarrator.sh --deactivate --key YOUR_KEY_HERE
```

The interactive shell (`--shell` or no args) will automatically ensure `key.txt` exists and will share the same `logs/fake_system.log` file as the other implementations.

---

## Design notes and limitations (all versions)

- Each implementation affects **only the shell process** it wraps; none of them hook the OS globally.
- They do **not** change real system configuration; they only change what certain commands return.
- All implementations share `logs/fake_system.log` and `key.txt`, so you can mix and match them as long as you understand that state is shared.
- Restarting a shell or terminal requires re-activation for that new process.

---

## Ideas for future enhancements

- Hook additional commands (e.g. process and service listings) in each shell.
- Add multiple fake profiles (e.g. "abandoned server", "overloaded backup node", "misconfigured lab box").
- Integrate a (carefully sandboxed) AI component to:
  - Generate richer, context-aware log narratives.
  - Adjust fake responses based on observed command patterns.
- Package each implementation as a module/package for easier loading (e.g. PowerShell module, Python package, Bash helper script).

---

## Safety and ethics

DeNarrator is designed for experimentation, deception-resistant honeypots, and obfuscation in controlled environments. Before using it on systems you do not fully control, or in production environments, ensure that you:

- Comply with local laws, organizational policies, and any relevant platform terms of service.
- Clearly separate honeypot data from real operational monitoring so you do not confuse defenders or incident responders.
