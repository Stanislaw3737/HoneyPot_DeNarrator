import argparse
import os
import sys
import threading
import time
import uuid
import random
from datetime import datetime, timedelta


class DeNarratorState:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.logs_path = os.path.join(base_dir, "logs")
        self.key_path = os.path.join(base_dir, "key.txt")
        self.active = False
        self.key = None
        self.log_thread = None
        self.stop_event = threading.Event()

        # Fake identity
        self.fake_hostname = "lab-gateway-01"
        self.fake_user = "svc_backup"
        self.fake_domain = "LAB-SEGMENT"
        self.fake_os = "Microsoft Windows Server 2016 Datacenter"
        self.fake_ip = "10.13.37.42"
        self.fake_mac = "00-15-5D-AB-CD-EF"
        self.fake_uuid = "EC2F3A12-0F9E-4C8F-9B3D-11AA22BB33CC"
        self.install_date = datetime.now() - timedelta(days=120)
        self.boot_time = datetime.now() - timedelta(hours=19)

    # --- key handling ---
    def load_or_create_key(self) -> str:
        if not os.path.exists(self.key_path):
            key = uuid.uuid4().hex
            with open(self.key_path, "w", encoding="ascii") as f:
                f.write(key)
        with open(self.key_path, "r", encoding="ascii") as f:
            return f.read().strip()

    # --- log generation ---
    def _log_worker(self) -> None:
        os.makedirs(self.logs_path, exist_ok=True)
        log_file = os.path.join(self.logs_path, "fake_system.log")
        if not os.path.exists(log_file):
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n=== DeNarrator fake system log started: {datetime.utcnow().isoformat()}Z ===\n")

        events = [
            "INFO  BackupService   Completed incremental backup to NAS-01",
            "WARN  DiskMonitor     High latency detected on volume E:",
            "INFO  AuthService     Successful kerberos ticket renewal for svc_backup",
            "WARN  FW              Rejected inbound connection from 203.0.113.45:445",
            "INFO  PatchAgent      Update cycle postponed; maintenance window not reached",
            "WARN  RAID            Rebuild in progress on slot 3",
            "INFO  JobRunner       Archive job 4921 completed with 0 errors",
            "WARN  AuthService     3 failed logon attempts for disabled user temp_admin",
        ]

        while not self.stop_event.is_set():
            line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {random.choice(events)}"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # sleep 20–60 seconds, but wake up promptly if stop_event is set
            for _ in range(60):
                if self.stop_event.wait(timeout=random.uniform(0.3, 1.2)):
                    return

    def start_logs(self) -> None:
        if self.log_thread and self.log_thread.is_alive():
            return
        self.stop_event.clear()
        self.log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.log_thread.start()

    def stop_logs(self) -> None:
        self.stop_event.set()
        if self.log_thread and self.log_thread.is_alive():
            self.log_thread.join(timeout=5)

    # --- fake outputs ---
    def fake_systeminfo(self) -> str:
        return "\n".join([
            f"Host Name:                 {self.fake_hostname}",
            f"OS Name:                   {self.fake_os}",
            "OS Version:                10.0.14393 N/A Build 14393",
            "System Manufacturer:       Generic Virtual Machine",
            "System Model:              Sandbox-Node",
            "System Type:               x64-based PC",
            "BIOS Version:              Hypervisor BIOS 1.0",
            f"Original Install Date:     {self.install_date.strftime('%d-%m-%Y, %H:%M:%S')}",
            f"System Boot Time:          {self.boot_time.strftime('%d-%m-%Y, %H:%M:%S')}",
            f"Domain:                    {self.fake_domain}",
            "Hotfix(s):                 42 Hotfix(s) Installed.",
            "Network Card(s):          1 NIC(s) installed.",
            f"                             {self.fake_ip}  {self.fake_mac}",
        ])

    def fake_hostname_output(self) -> str:
        return self.fake_hostname

    def fake_whoami(self) -> str:
        return f"{self.fake_domain.lower()}\\{self.fake_user}"

    def fake_ipconfig(self) -> str:
        return """Windows IP Configuration

Ethernet adapter CorpNet:

   Connection-specific DNS Suffix  . : corp.lab
   IPv4 Address. . . . . . . . . . . : {ip}
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.13.37.1
""".format(ip=self.fake_ip)

    def fake_logs_tail(self, n: int = 50) -> str:
        log_file = os.path.join(self.logs_path, "fake_system.log")
        if not os.path.exists(log_file):
            return "(no events)"
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return "".join(lines[-n:]) if lines else "(no events)"


def interactive_shell(state: DeNarratorState) -> None:
    """Simple REPL that masks a few system info commands.

    This is not a full shell replacement. It just demonstrates
    deceptive outputs for specific commands while the background
    logger runs.
    """

    print("[DeNarrator] Python honeypot shell. Type 'help' for commands, 'exit' to quit.")
    state.start_logs()

    while True:
        try:
            cmd = input("denarrator> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()  # newline
            break

        if not cmd:
            continue

        if cmd.lower() in {"exit", "quit"}:
            break

        if cmd.lower() == "help":
            print("Available commands:")
            print("  systeminfo       - show fake system information")
            print("  hostname         - show fake hostname")
            print("  whoami           - show fake user")
            print("  ipconfig         - show fake network info")
            print("  logs             - show tail of fake logs")
            print("  real <command>   - run a real OS command (use with care)")
            print("  exit / quit      - leave this shell")
            continue

        if cmd.lower() == "systeminfo":
            print(state.fake_systeminfo())
            continue

        if cmd.lower() == "hostname":
            print(state.fake_hostname_output())
            continue

        if cmd.lower() == "whoami":
            print(state.fake_whoami())
            continue

        if cmd.lower() == "ipconfig":
            print(state.fake_ipconfig())
            continue

        if cmd.lower() == "logs":
            print(state.fake_logs_tail(40))
            continue

        if cmd.lower().startswith("real "):
            real_cmd = cmd[5:].strip()
            if not real_cmd:
                print("Usage: real <command>")
                continue
            os.system(real_cmd)
            continue

        # Unknown command: for now just show a discouraging message
        print("Command not recognized or not supported in this environment.")

    state.stop_logs()
    print("[DeNarrator] Shell terminated.")


def use_key(state: DeNarratorState, key: str, disable: bool) -> None:
    real_key = state.key or state.load_or_create_key()
    state.key = real_key

    if key != real_key:
        print("[DeNarrator] Invalid key.")
        return

    if disable:
        if state.active:
            state.stop_logs()
            state.active = False
            print("[DeNarrator] Honeypot deactivated.")
        else:
            print("[DeNarrator] Honeypot already inactive.")
    else:
        if not state.active:
            state.start_logs()
            state.active = True
            print("[DeNarrator] Honeypot activated (background logs running). Use the interactive shell to interact.")
        else:
            print("[DeNarrator] Honeypot already active.")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="DeNarrator Python honeypot")
    parser.add_argument("--activate", action="store_true", help="activate background honeypot")
    parser.add_argument("--deactivate", action="store_true", help="deactivate background honeypot")
    parser.add_argument("--key", type=str, help="bypass key for secure activate/deactivate")
    parser.add_argument("--shell", action="store_true", help="start the interactive DeNarrator shell")

    args = parser.parse_args(argv)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    state = DeNarratorState(base_dir)

    if args.activate or args.deactivate:
        if not args.key:
            print("[DeNarrator] --key is required for activate/deactivate operations.")
            sys.exit(1)
        use_key(state, args.key, disable=args.deactivate)
        return

    # Default behavior: start interactive shell (this will also start logs)
    if args.shell or (not args.activate and not args.deactivate):
        # Ensure key exists even if not used explicitly, for parity with PowerShell version
        state.key = state.load_or_create_key()
        interactive_shell(state)


if __name__ == "__main__":
    main()
