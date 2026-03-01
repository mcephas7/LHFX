#!/usr/bin/env python3

# LHFX – Linux–Hadoop Forensics Extractor
# Copyright (c) 2026 Cephas Charles Mpungu
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# https://www.gnu.org/licenses/gpl-3.0.html

"""
LHFX Linux-Hadoop Forensics Extractor (GUI) — evidence kickstart for Linux-Hadoop NameNodes
Version: 3.6.3

Design goals:
- Investigator-first UX: wizard-like flow, clear guidance, copy/paste commands, non-technical friendly.
- Works on mounted images (manual mount or auto-mount via loop device), read-only.
- Broad Linux + Hadoop + ecosystem artefact discovery (generic signatures + container storage).
- Robust error handling: PermissionError/EIO safe traversal; never crash on unreadable dirs.
- Strong logging: console + log file + run summary + warnings + suggested remediation.
- Hashing: choose algorithm OR proceed without hashing (with caution message).

Forensic note:
- This tool does not silently auto-install dependencies. It detects missing commands and provides copy/paste install guidance.
  An optional, investigator-initiated “Prepare Dependencies” action is available for Kali/Debian-family systems when running with sudo, providing guided installation of required forensic utilities.
"""


import errno
import hashlib
import importlib.util
import json
import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

VERSION = "3.6.3"

# High-signal "beacons" to locate Hadoop + ecosystem components across layouts
TARGETS: Dict[str, List[str]] = {
    "HDFS_Metadata": [
        "VERSION", "seen_txid", "fstime", "in_use.lock",
        "fsimage_", "fsimage.ckpt_", "edits_", "edits_inprogress_", "edits.inprogress"
    ],
    "Configs_Hadoop": [
        "core-site.xml", "hdfs-site.xml", "yarn-site.xml", "mapred-site.xml",
        "hadoop-env.sh", "hdfs-env.sh", "yarn-env.sh", "mapred-env.sh",
        "workers", "slaves",
        "capacity-scheduler.xml", "fair-scheduler.xml",
        "log4j.properties", "log4j2.properties"
    ],
    "Ecosystem_Apps": [
        # Zookeeper
        "zoo.cfg", "zookeeper-env.sh",
        # Hive
        "hive-site.xml", "hiveserver2-site.xml",
        # Spark
        "spark-defaults.conf", "spark-env.sh",
        # HBase
        "hbase-site.xml", "hbase-env.sh",
        # Kafka
        "server.properties", "kafka-server-start.sh",
        # Oozie, Flume, Sqoop, Ranger
        "oozie-site.xml", "flume.conf", "sqoop-site.xml",
        "ranger-admin-site.xml", "ranger-usersync-site.xml"
    ],
    "OS_Artifacts": [
        "os-release", "lsb-release", "hostname", "hosts",
        "passwd", "group", "shadow", "sudoers", "sshd_config",
        "crontab", "fstab"
    ],
    "Logs": [
        "auth.log", "secure", "syslog", "messages", "kern.log", "boot.log",
        "dpkg.log", "yum.log", "wtmp", "btmp", "lastlog"
    ],
    "Container_Metadata": [
        "config.v2.json", "hostconfig.json"
    ]
}

# Common locations to probe quickly (not exhaustive)
COMMON_DIR_HINTS = [
    "etc/hadoop", "etc/hadoop/conf", "etc/hadoop/conf.empty",
    "etc/hdfs", "etc/yarn", "etc/mapred",
    "opt/hadoop", "usr/hdp", "usr/lib/hadoop",
    "var/log/hadoop", "var/log/hdfs", "var/log/yarn",
    "var/lib/hadoop-hdfs", "var/lib/hdfs", "data/hdfs"
]

DEFAULT_SKIP_DIR_PREFIXES = {"/proc", "/sys", "/dev", "/run", "/var/cache", "/var/tmp"}
CONTAINER_ROOTS = ["var/lib/docker", "var/lib/containerd", "var/lib/containers"]

HASH_OPTIONS = ["sha256", "sha1", "md5", "sha512", "blake2b", "blake2s", "none"]

# ===== Utility helpers =====

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def local_now_human() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

@dataclass
class EvidenceFile:
    category: str
    src: str
    dst: str
    size: int
    mtime_utc: str
    sha256: Optional[str] = None
    hash_algo: Optional[str] = None
    hash_value: Optional[str] = None

class ToolError(RuntimeError):
    """Raised for controlled failures with actionable messages."""

class SafeRunner:
    """Runs shell commands with capture + logging; never prints secrets."""
    def __init__(self, log_fn):
        self.log = log_fn

    def run(self, args: List[str], *, timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
        self.log(f"RUN: {' '.join(args)}", level="DEBUG")
        try:
            cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.log(f"TIMEOUT: {' '.join(args)}", level="ERROR")
            raise ToolError(f"Command timed out: {' '.join(args)}")

        if cp.returncode != 0:
            # log stderr for diagnostics
            if cp.stderr.strip():
                self.log(cp.stderr.strip(), level="WARNING")
            if check:
                raise ToolError(f"Command failed (rc={cp.returncode}): {' '.join(args)}")
        return cp

# ===== GUI App =====

class HadoopForensicsGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Linux-Hadoop Forensics Extractor")
        self.root.geometry("1120x920")

        # User inputs
        self.image_path = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.root_path = tk.StringVar()  # optional: already-mounted root
        self.hash_algo = tk.StringVar(value="sha256")
        self.ref_hash = tk.StringVar()
        self.allow_no_hash = tk.BooleanVar(value=True)
        self.include_containers = tk.BooleanVar(value=True)

        # Tunables (safe defaults)
        self.max_files = tk.IntVar(value=4000)
        self.max_depth = tk.IntVar(value=14)

        # State
        self.is_running = False
        # Cooperative cancel used by Stop button (checked inside hashing/scans)
        self.stop_event = threading.Event()
        self._msg_q: "queue.Queue[Tuple[str,str]]" = queue.Queue()
        self._loop_dev: Optional[str] = None
        self._mounted_dev: Optional[str] = None
        self.temp_mount = Path(f"/mnt/hadoop_triage_mount_{int(time.time())}")

        # Outputs
        self.run_id: str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path: Optional[Path] = None
        self.evidence: List[EvidenceFile] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
        self.stats = {"walk_perm": 0, "walk_eio": 0, "walk_other": 0}

        self._build_ui()
        self._start_ui_pump()
        self._preflight_gui_checks()

    # ---------- UI ----------

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding="16")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Big Data Linux–Hadoop Forensics Extractor", font=("Helvetica", 20, "bold")).pack(pady=(0, 6))
        ttk.Label(
            frame,
            text=("Designed for investigators (including non-Linux / non-Hadoop examiners):\n"
                  "Select evidence → choose hashing → choose output → run. The tool guides you when something fails."),
            wraplength=1060, justify=tk.CENTER
        ).pack(pady=(0, 12))

        # Step 1: Source
        s1 = ttk.LabelFrame(frame, text=" 1) Evidence source ", padding=12)
        s1.pack(fill=tk.X, pady=8)
        ttk.Label(s1, text="Option A — Evidence image (DD/Raw):").grid(row=0, column=0, sticky="w")
        ttk.Entry(s1, textvariable=self.image_path, width=85).grid(row=0, column=1, padx=6, sticky="we")
        ttk.Button(s1, text="Browse…", command=self._browse_image).grid(row=0, column=2, padx=6)

        ttk.Label(s1, text="Option B — Already mounted root (recommended if you mounted manually):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(s1, textvariable=self.root_path, width=85).grid(row=1, column=1, padx=6, pady=(8, 0), sticky="we")
        ttk.Button(s1, text="Browse…", command=self._browse_root).grid(row=1, column=2, padx=6, pady=(8, 0))

        ttk.Label(
            s1,
            text=("Tip: Manual mount is often the most defensible.\n"
                  "If you use Option B, the tool will NOT mount anything — it will only read from that folder."),
            font=("Helvetica", 8, "italic")
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        s1.columnconfigure(1, weight=1)

        # Step 2: Hashing
        s2 = ttk.LabelFrame(frame, text=" 2) Integrity verification (recommended) ", padding=12)
        s2.pack(fill=tk.X, pady=8)

        ttk.Label(s2, text="Hash algorithm:").grid(row=0, column=0, sticky="w")
        self.hash_combo = ttk.Combobox(
            s2, textvariable=self.hash_algo, values=HASH_OPTIONS, width=12, state="readonly"
        )
        self.hash_combo.grid(row=0, column=1, padx=6, sticky="w")
        ttk.Label(s2, text="Expected hash (optional):").grid(row=0, column=2, padx=6, sticky="w")
        self.expected_entry = ttk.Entry(s2, textvariable=self.ref_hash, width=58)
        self.expected_entry.grid(row=0, column=3, padx=6, sticky="we")

        ttk.Checkbutton(
            s2,
            text="Allow proceed WITHOUT hashing (NOT recommended)  [Hashing supports integrity and evidential defensibility]",
            variable=self.allow_no_hash
        ).grid(row=1, column=0, columnspan=4, pady=(8, 0), sticky="w")

        # If user ticks "Allow proceed WITHOUT hashing", we treat that as an override:
        # disable hashing controls and set algorithm to 'none'. This matches investigator expectations.
        def _sync_hash_ui(*_):
            if self.allow_no_hash.get():
                # Force skip hashing
                self.hash_algo.set("none")
                try:
                    self.hash_combo.configure(state="disabled")
                except Exception:
                    pass
                try:
                    self.expected_entry.configure(state="disabled")
                except Exception:
                    pass
            else:
                # Enable hashing again
                if self.hash_algo.get().strip().lower() == "none":
                    self.hash_algo.set("sha256")
                try:
                    self.hash_combo.configure(state="readonly")
                except Exception:
                    pass
                try:
                    self.expected_entry.configure(state="normal")
                except Exception:
                    pass

        # Ensure UI sync applies on startup and when toggled
        _sync_hash_ui()
        try:
            self.allow_no_hash.trace_add("write", lambda *_: _sync_hash_ui())
        except Exception:
            # Tk < 8.6 fallback
            self.allow_no_hash.trace("w", lambda *_: _sync_hash_ui())

        s2.columnconfigure(3, weight=1)

        # Step 3: Output
        s3 = ttk.LabelFrame(frame, text=" 3) Output directory ", padding=12)
        s3.pack(fill=tk.X, pady=8)
        ttk.Entry(s3, textvariable=self.output_dir, width=85).grid(row=0, column=0, padx=6, sticky="we")
        ttk.Button(s3, text="Select…", command=self._browse_output).grid(row=0, column=1, padx=6)

        ttk.Label(
            s3,
            text=("If you do not select a folder, the tool will create one automatically:\n"
                  "~/Hadoop_Forensics_Output/<timestamp>/"),
            font=("Helvetica", 8, "italic")
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=6, pady=(6, 0))
        s3.columnconfigure(0, weight=1)

        # Step 4: Options
        s4 = ttk.LabelFrame(frame, text=" 4) Scan options (safe defaults) ", padding=12)
        s4.pack(fill=tk.X, pady=8)
        ttk.Checkbutton(s4, text="Probe container storage (Docker/overlay2) when present", variable=self.include_containers).grid(
            row=0, column=0, columnspan=4, sticky="w"
        )
        ttk.Label(s4, text="Max files to copy:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Spinbox(s4, from_=200, to=50000, increment=200, textvariable=self.max_files, width=10).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(s4, text="Max scan depth:").grid(row=1, column=2, sticky="w", padx=(16, 0), pady=(8, 0))
        ttk.Spinbox(s4, from_=3, to=80, increment=1, textvariable=self.max_depth, width=8).grid(row=1, column=3, sticky="w", pady=(8, 0))

        # Buttons row (kept ABOVE console so it is always visible even on smaller screens)
        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=(8, 8))
        self.run_btn = ttk.Button(btns, text="RUN INVESTIGATION", command=self._safe_start)
        self.run_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(btns, text="STOP", command=self._request_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="Close Case / Reset Tool", command=self._reset_tool).pack(side=tk.LEFT, padx=8)
        ttk.Button(btns, text="Prepare Dependencies", command=self._prepare_dependencies).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="Show Help / Troubleshooting", command=self._show_help).pack(side=tk.LEFT, padx=8)
        ttk.Button(btns, text="Open Output Folder", command=self._open_output_folder).pack(side=tk.LEFT, padx=8)

        # Console + progress
        self.console = tk.Text(frame, height=16, state=tk.DISABLED, bg="#101010", fg="#33ff66", font=("Courier", 10))
        self.console.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, mode="indeterminate", length=1060)
        self.progress.pack(pady=(0, 10))

        ttk.Label(frame, text="Forensic note: read-only workflow; copied artefacts go into Evidence_Vault. The image is not modified.",
                  font=("Helvetica", 8)).pack(pady=(0, 0))
    def _start_ui_pump(self):
        def pump():
            try:
                while True:
                    msg, level = self._msg_q.get_nowait()
                    self._append_console(msg, level)
                    self._write_log_line(msg, level)
            except queue.Empty:
                pass
            self.root.after(120, pump)
        self.root.after(120, pump)

    def _append_console(self, msg: str, level: str):
        self.console.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{ts}] {level}: {msg}\n")
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

    def log(self, msg: str, level: str = "INFO"):
        self._msg_q.put((msg, level))

    def _check_stop(self):
        """Raise a controlled error if Stop has been requested."""
        if self.stop_event.is_set():
            raise ToolError("Stopped by investigator.")

    def _write_log_line(self, msg: str, level: str):
        if not self.log_path:
            return
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{ts}] {level}: {msg}\n")
        except Exception:
            pass

    def _browse_image(self):
        f = filedialog.askopenfilename(title="Select DD/Raw image")
        if f:
            self.image_path.set(f)

    def _browse_root(self):
        d = filedialog.askdirectory(title="Select mounted root folder (e.g., /mnt/namenode_root)")
        if d:
            self.root_path.set(d)

    def _browse_output(self):
        d = filedialog.askdirectory(title="Select output directory")
        if d:
            self.output_dir.set(d)

    def _open_output_folder(self):
        out = self._resolve_output_dir(create=False)
        if not out or not out.exists():
            messagebox.showinfo("Output Folder", "No output folder exists yet. Run an investigation first.")
            return
        # Best-effort open
        try:
            subprocess.run(["xdg-open", str(out)], check=False)
        except Exception:
            messagebox.showinfo("Output Folder", f"Output folder:\n{out}")

    def _show_help(self):
        text = (
            "Troubleshooting / Help\n\n"
            "1) Recommended workflow (manual mount):\n"
            "   - Attach loop device read-only and mount the largest Linux partition read-only.\n"
            "   - Then select 'Already mounted root' in this tool.\n\n"
            "   Copy/paste example:\n"
            "     sudo mkdir -p /mnt/namenode_root\n"
            "     sudo losetup --find --show --read-only --partscan IMAGE.dd\n"
            "     sudo lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT /dev/loopX\n"
            "     sudo mount -o ro,noload /dev/loopXpY /mnt/namenode_root   # ext*\n"
            "     sudo mount -o ro,norecovery /dev/loopXpY /mnt/namenode_root # xfs\n\n"
            "2) If you see Input/output errors (EIO):\n"
            "   - This usually indicates a disk/image read problem (e.g., unplug/replug, bad sectors).\n"
            "   - Reconnect the drive, remount, and consider copying the image to a local SSD.\n"
            "   - You can run a read-only filesystem check (for awareness):\n"
            "       sudo e2fsck -fn /dev/loopXpY\n\n"
            "3) Dependencies:\n"
            "   - This tool detects missing commands and prints copy/paste install commands.\n\n"
            "4) Hashing:\n"
            "   - Hashing is recommended for evidential integrity.\n"
            "   - You may proceed without hashing if allowed, but defensibility may be reduced.\n"
        )
        messagebox.showinfo("Help / Troubleshooting", text)

    # ---------- Preflight ----------

    def _preflight_gui_checks(self):
        """Initial GUI preflight.

        The tool can run without sudo when using Option B (already mounted root).
        Sudo is required only when the tool needs to attach a loop device and mount an image (Option A).
        """
        if os.getuid() != 0:
            # Non-fatal: allow the GUI to open for Option B usage.
            messagebox.showwarning(
                "Limited mode (not running as root)",
                "You are not running with sudo.\\n\\n"
                "• You can still use Option B (Already mounted root).\\n"
                "• Option A (evidence image auto-mount) requires sudo.\\n\\n"
                "If needed, re-run as: sudo python3 LHFX_Tool.py"
            )

    def _dependency_check(self) -> Tuple[bool, List[str]]:
        """Return (ok, missing_items)."""
        missing = []
        for cmd in ["losetup", "mount", "umount", "lsblk", "blkid", "fdisk", "blockdev", "file", "dmesg"]:
            if shutil.which(cmd) is None:
                missing.append(cmd)
        # Optional but very useful for health check
        if shutil.which("e2fsck") is None:
            missing.append("e2fsck (optional but recommended)")
        return (len(missing) == 0, missing)

    def _dependency_guidance(self, missing: List[str]) -> str:
        # Kali/Debian-friendly guidance
        pkgs = []
        if any("losetup" in m or "mount" in m or "umount" in m for m in missing):
            pkgs.extend(["util-linux", "mount"])
        if any("lsblk" in m for m in missing):
            pkgs.append("util-linux")
        if any("blkid" in m for m in missing):
            pkgs.append("util-linux")
        if any("e2fsck" in m for m in missing):
            pkgs.append("e2fsprogs")
        if any(m.strip() == "file" or m.startswith("file") for m in missing):
            pkgs.append("file")
        pkgs = sorted(set(pkgs))
        cmd = "sudo apt update && sudo apt install -y " + " ".join(pkgs) if pkgs else "sudo apt update"
        return (
            "Missing dependencies detected:\n"
            f"  - " + "\n  - ".join(missing) + "\n\n"
            "Copy/paste to install on Kali/Debian:\n"
            f"  {cmd}\n\n"
            "Then re-run the tool."
        )

    # ---------- Run orchestration ----------

    def _prepare_dependencies(self):
        """One-click dependency setup (Kali/Debian apt) run in background.

        Since you run the GUI with sudo, installs run as root automatically.
        """
        ok, missing = self._dependency_check()
        if ok:
            self.log("All dependencies appear installed. ✅")
            messagebox.showinfo("Dependencies", "All required dependencies are already installed.")
            return

        pkgs = set()
        miss_str = " ".join(missing).lower()

        if any(x in miss_str for x in ["losetup", "lsblk", "blkid"]):
            pkgs.add("util-linux")
        if any(x in miss_str for x in ["mount", "umount"]):
            pkgs.add("mount")
        if "e2fsck" in miss_str:
            pkgs.add("e2fsprogs")
        if "sleuthkit" in miss_str or "tsk_recover" in miss_str or "fls" in miss_str:
            pkgs.add("sleuthkit")
        if "pytsk3" in miss_str:
            pkgs.add("python3-pytsk3")

        pkgs_list = sorted(pkgs)
        cmd_preview = "sudo apt update && sudo apt install -y " + " ".join(pkgs_list) if pkgs_list else "sudo apt update && sudo apt install -y <packages>"

        detail = (
            "Missing dependencies were detected:\n\n"
            + "\n".join(f" • {x}" for x in missing)
            + "\n\nRecommended install command (copy/paste):\n\n"
            + cmd_preview
            + "\n\nClick YES to install automatically now."
        )

        if os.geteuid() != 0:
            messagebox.showwarning("Dependencies Missing", detail + "\n\nRun this tool with sudo to allow one-click install.")
            self.log("Not running as root. Printed install command:")
            self.log(cmd_preview)
            return

        if not pkgs_list:
            messagebox.showerror("Install Dependencies", "Could not determine apt packages to install. Use Help/Troubleshooting for manual steps.")
            self.log("Could not map missing deps to apt packages. Missing: " + ", ".join(missing), level="ERROR")
            return

        if not messagebox.askyesno("Install Dependencies", detail):
            self.log("Dependency installation cancelled by investigator. Printed install command:")
            self.log(cmd_preview)
            return

        # Background install
        def _worker():
            self.log("Preparing dependencies: apt update + apt install ... (this may take a few minutes)")
            try:
                # Use Popen to stream output to console for transparency
                for cmd in (["apt", "update"], ["apt", "install", "-y"] + pkgs_list):
                    self.log("RUN: " + " ".join(cmd), level="DEBUG")
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        self.log(line.rstrip())
                        if self.stop_event.is_set():
                            # allow STOP to cancel install display; do not kill apt abruptly
                            pass
                    rc = proc.wait()
                    if rc != 0:
                        raise RuntimeError(f"Command failed (rc={rc}): {' '.join(cmd)}")

                ok2, missing2 = self._dependency_check()
                if ok2:
                    self.log("Dependencies installed successfully. ✅")
                    messagebox.showinfo("Dependencies", "Dependencies installed successfully.")
                else:
                    self.log("Some dependencies still missing: " + ", ".join(missing2), level="WARNING")
                    messagebox.showwarning("Dependencies", "Install finished but some items still appear missing. See console/logs for details.")
            except Exception as e:
                self.log(f"Dependency installation failed: {e}", level="ERROR")
                messagebox.showerror("Dependencies", f"Dependency installation failed:\n\n{e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _safe_start(self):
        if self.is_running:
            return

        ok, missing = self._dependency_check()
        if not ok:
            messagebox.showerror("Missing dependencies", self._dependency_guidance(missing))
            return

        # Resolve output directory (auto-create if blank)
        out = self._resolve_output_dir(create=True)
        safe_mkdir(out)
        self.log_path = out / "logs" / "tool.log"
        safe_mkdir(self.log_path.parent)

        # Validate source selection
        img = self.image_path.get().strip()
        root_dir = self.root_path.get().strip()

        if not img and not root_dir:
            messagebox.showerror("Source required", "Please choose an evidence image (Option A) OR an already-mounted root folder (Option B).")
            return

        if img and root_dir:
            if not messagebox.askyesno("Choose one source", "You selected both an image and a mounted root.\n\nUse the mounted root (recommended) and ignore the image?"):
                return
            # Prefer root_dir
            img = ""

        # If the user chose an image (Option A), require sudo for loop device + read-only mount.
        if img and os.getuid() != 0:
            messagebox.showerror(
                "Root Required for Image Auto-mount",
                "Option A (evidence image) requires sudo to attach a loop device and mount read-only.\n\n"
                "Either:\n"
                "• Re-run as: sudo python3 LHFX_Tool.py\n"
                "or\n"
                "• Mount the image manually and use Option B (Already mounted root)."
            )
            return

        if img and not Path(img).exists():
            messagebox.showerror("Image Error", "Evidence image path is invalid or not accessible.")
            return
        if root_dir and not Path(root_dir).exists():
            messagebox.showerror("Root Path Error", "Mounted root path is invalid or not accessible.")
            return

        self.is_running = True
        self.stop_event.clear()
        self.run_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(12)

        # Reset state
        self.evidence = []
        self.warnings = []
        self.errors = []
        self.stats = {"walk_perm": 0, "walk_eio": 0, "walk_other": 0}
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        threading.Thread(target=self._workflow, args=(img, root_dir, out), daemon=True).start()

    def _request_stop(self):
        """User-requested stop. We use cooperative cancellation to keep the workflow clean."""
        if not self.is_running:
            return
        self.stop_event.set()
        self.log("Stop requested by investigator. Finishing current operation safely…", "WARNING")
        # Disable Stop to prevent repeated clicks
        try:
            self.stop_btn.config(state=tk.DISABLED)
        except Exception:
            pass

    def _reset_tool(self):
        """Close the current case/session and reset the tool for a new evidence source.

        Forensic intent: prevent cross-case contamination by clearing UI + in-memory state and
        safely cleaning up any auto-mount resources (loop device + mount point).
        """
        # If a workflow is running, ask before stopping/resetting
        if self.is_running:
            if not messagebox.askyesno("Reset Tool", "An investigation is currently running. Stop and reset the tool?"):
                return
            # Cooperative cancellation
            self.stop_event.set()

        # Best-effort cleanup of auto-mount resources (safe even if nothing is mounted)
        try:
            runner = SafeRunner(self.log)
            self._cleanup_all(runner)
        except Exception:
            pass

        # Clear in-memory state
        self.evidence = []
        self.warnings = []
        self.errors = []
        self.stats = {"walk_perm": 0, "walk_eio": 0, "walk_other": 0}
        self._loop_dev = None
        self._mounted_dev = None
        self.stop_event.clear()
        self.is_running = False

        # Reset run context
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = None

        # Reset UI inputs
        self.image_path.set("")
        self.root_path.set("")
        self.output_dir.set("")
        self.ref_hash.set("")
        # keep investigator preferences (hash_algo, allow_no_hash, include_containers, tunables)

        # Reset UI controls
        try:
            self.run_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.progress.stop()
        except Exception:
            pass

        # Clear console output
        try:
            self.console.config(state=tk.NORMAL)
            self.console.delete("1.0", tk.END)
            self.console.config(state=tk.DISABLED)
        except Exception:
            pass

        self.log("Tool reset complete. Ready for a new investigation.", "INFO")
    def _resolve_output_dir(self, create: bool) -> Path:
        """Resolve output directory.

        If the user did not select an output folder, default to the *invoking* user's home
        (e.g., /home/kali) rather than /root when the tool is run with sudo.
        """
        raw = self.output_dir.get().strip()
        if raw:
            p = Path(raw).expanduser()
        else:
            sudo_user = os.environ.get("SUDO_USER")
            base_home = None
            if sudo_user:
                candidate = Path("/home") / sudo_user
                if candidate.exists():
                    base_home = candidate
                else:
                    try:
                        import pwd
                        base_home = Path(pwd.getpwnam(sudo_user).pw_dir)
                    except Exception:
                        base_home = None
            if base_home is None:
                base_home = Path.home()

            p = base_home / "Hadoop_Forensics_Output" / self.run_id
            if create:
                self.output_dir.set(str(p))
        return p


    def _workflow(self, img_path: str, root_dir: str, out: Path):
        runner = SafeRunner(self.log)
        start = time.time()

        meta = {
            "tool_version": VERSION,
            "started_utc": utc_now_iso(),
            "started_local": local_now_human(),
            "examiner": os.getenv("SUDO_USER") or os.getenv("USER") or "unknown",
            "host": os.uname().nodename,
            "source": {"image": img_path or None, "root": root_dir or None},
            "mount": {"method": None, "loop_dev": None, "mounted_dev": None, "mount_point": None},
        }

        try:
            self.log(f"Output folder: {out}", "INFO")
            self.log("Step 1/6: Preflight checks…", "INFO")
            self._preflight_source_health(runner, img_path, root_dir)
            self._check_stop()

            chosen_algo = self.hash_algo.get().strip().lower()
            if chosen_algo not in HASH_OPTIONS:
                chosen_algo = "sha256"

            self.log("Step 2/6: Integrity (hashing)…", "INFO")
            # If the user ticked 'Allow proceed WITHOUT hashing', treat this as a skip-hash override.
            if self.allow_no_hash.get():
                chosen_algo = "none"

            if img_path:
                meta["mount"]["method"] = "auto-mount"
                if chosen_algo == "none":
                    if self.allow_no_hash.get():
                        self.log("[Caution] Proceeding without hashing reduces evidential defensibility. Hashing is recommended.", "WARNING")
                        meta["image_hash"] = {"algo": "none", "value": None}
                        meta["hash_verification"] = {"expected": self.ref_hash.get().strip().lower() or None, "computed": None, "match": None}
                    else:
                        raise ToolError("Hashing disabled. Enable 'Allow proceed without hashing' or select a hash algorithm.")
                else:
                    self._check_stop()
                    ih = self._hash_file(Path(img_path), chosen_algo)
                    meta["image_hash"] = {"algo": chosen_algo, "value": ih}
                    self.log(f"Image hash ({chosen_algo}): {ih}", "INFO")
                    exp = self.ref_hash.get().strip().lower()
                    if exp:
                        if exp != ih:
                            self.log("HASH MISMATCH against expected value.", "WARNING")
                            meta["hash_verification"] = {"expected": exp, "computed": ih, "match": False}
                            if not self._ask_yes_no("Integrity warning", "Image hash does not match expected.\n\nContinue anyway?"):
                                raise ToolError("User aborted due to hash mismatch.")
                        else:
                            self.log("Hash matches expected value.", "INFO")
                            meta["hash_verification"] = {"expected": exp, "computed": ih, "match": True}
                    else:
                        meta["hash_verification"] = {"expected": None, "computed": ih, "match": None}
            else:
                meta["mount"]["method"] = "manual-mount"
                meta["image_hash"] = {"algo": "n/a (manual root)", "value": None}
                meta["hash_verification"] = {"expected": None, "computed": None, "match": None}
                if chosen_algo == "none":
                    self.log("[Caution] Proceeding without hashing. If you have the image file, hashing is recommended.", "WARNING")

            self.log("Step 3/6: Accessing the filesystem…", "INFO")
            self._check_stop()
            if root_dir:
                # Use existing mount directly
                mount_root = Path(root_dir)
                meta["mount"]["mount_point"] = str(mount_root)
            else:
                # Auto-mount
                mount_root = self.temp_mount
                self._cleanup_mount_only(runner)
                loop_dev = self._losetup_attach(runner, Path(img_path))
                self._loop_dev = loop_dev
                meta["mount"]["loop_dev"] = loop_dev
                mounted_dev = self._select_partition(runner, loop_dev)
                self._mounted_dev = mounted_dev
                meta["mount"]["mounted_dev"] = mounted_dev
                meta["mount"]["mount_point"] = str(mount_root)
                self._mount_readonly(runner, mounted_dev, mount_root)

            # Health probe (EIO awareness)
            self._health_probe(mount_root)

            self._check_stop()

            self.log("Step 4/6: Discovering Hadoop + ecosystem footprint…", "INFO")
            os_facts = self._collect_os_facts(mount_root)
            hadoop_facts = self._discover_hadoop(mount_root)
            eco_facts = self._discover_ecosystem(mount_root)

            self._check_stop()

            container_facts = {}
            if self.include_containers.get():
                self.log("Step 5/6: Container storage probe (best effort)…", "INFO")
                container_facts = self._discover_containers(mount_root)

            self._check_stop()

            self.log("Step 6/6: Extracting artefacts…", "INFO")
            vault = out / "Evidence_Vault"
            safe_mkdir(vault)
            manifest = out / "manifest.jsonl"

            extracted = self._extract(vault, manifest, mount_root, chosen_algo)

            end = time.time()
            meta["finished_utc"] = utc_now_iso()
            meta["finished_local"] = local_now_human()
            meta["execution_seconds"] = round(end - start, 3)

            self._write_reports(out, meta, os_facts, hadoop_facts, eco_facts, container_facts, extracted)

            self.log("DONE: Investigation complete.", "INFO")
            self._info("Complete", "Investigation complete.\n\nOpen Executive_Summary.md in the output folder.")

        except ToolError as e:
            self.errors.append(str(e))
            self.log(f"CRITICAL: {e}", "ERROR")
            self._error("Investigation stopped", f"{e}\n\nUse 'Show Help / Troubleshooting' for guidance.")
        except Exception as e:
            self.errors.append(repr(e))
            self.log(f"UNEXPECTED ERROR: {e}", "ERROR")
            self._error("Unexpected failure", f"Unexpected error:\n\n{e}\n\nCheck logs/tool.log for details.")
        finally:
            try:
                if not root_dir:
                    self.log("Cleanup: unmount + detach loop…", "INFO")
                    self._cleanup_all(runner)
            except Exception as e:
                self.log(f"Cleanup warning: {e}", "WARNING")
            self.is_running = False
            self.root.after(0, lambda: self.run_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.progress.stop())

    # ---------- Dialog helpers (thread safe) ----------

    def _ask_yes_no(self, title: str, text: str) -> bool:
        q: "queue.Queue[bool]" = queue.Queue()
        def _ask():
            q.put(messagebox.askyesno(title, text))
        self.root.after(0, _ask)
        return q.get()

    def _info(self, title: str, text: str):
        self.root.after(0, lambda: messagebox.showinfo(title, text))

    def _error(self, title: str, text: str):
        self.root.after(0, lambda: messagebox.showerror(title, text))

    # ---------- Mounting & source health ----------

    def _preflight_source_health(self, runner: SafeRunner, img_path: str, root_dir: str):
        # If manual root, do minimal checks
        if root_dir:
            p = Path(root_dir)
            if not p.exists():
                raise ToolError(f"Mounted root does not exist: {p}")
            # check readability of a few anchors
            for rel in ["etc", "var/log", "home", "usr"]:
                try:
                    _ = list((p / rel).iterdir())[:1] if (p / rel).exists() else None
                except PermissionError:
                    self.warnings.append(f"Permission denied probing {rel}. Some artefacts may be inaccessible.")
                    self.stats["walk_perm"] += 1
                except OSError as e:
                    if e.errno == errno.EIO:
                        self.warnings.append(f"EIO while probing {rel}. Image/device may be unstable.")
                        self.stats["walk_eio"] += 1

        # If image, ensure file is readable
        if img_path:
            ip = Path(img_path)
            try:
                with ip.open("rb") as f:
                    f.read(1024 * 1024)
            except Exception as e:
                raise ToolError(f"Cannot read image file: {ip}\nReason: {e}")

    def _cleanup_mount_only(self, runner: SafeRunner):
        safe_mkdir(self.temp_mount)
        runner.run(["umount", "-l", str(self.temp_mount)], timeout=20, check=False)

    def _cleanup_all(self, runner: SafeRunner):
        # Unmount first
        runner.run(["umount", "-l", str(self.temp_mount)], timeout=20, check=False)
        
        # Detach loop device
        if self._loop_dev:
            runner.run(["losetup", "-d", self._loop_dev], timeout=20, check=False)
        
        self._loop_dev = None
        self._mounted_dev = None
        
        # Try to remove mount point if empty
        try:
            if self.temp_mount.exists() and not any(self.temp_mount.iterdir()):
                self.temp_mount.rmdir()
        except Exception:
            pass

    def _losetup_attach(self, runner: SafeRunner, image: Path) -> str:
        """Attach image as read-only loop device with partition scanning."""
        self.log(f"Attaching image: {image}", "INFO")
        
        if not image.exists():
            raise ToolError(f"Image file does not exist: {image}")
        
        if not os.access(image, os.R_OK):
            raise ToolError(f"Image file not readable (check permissions): {image}")
        
        # Show current loop devices before
        res = runner.run(["losetup", "-a"], timeout=10)
        self.log(f"Current loop devices:\n{res.stdout}", "DEBUG")
        
        # Run losetup
        cmd = ["losetup", "--find", "--show", "--read-only", "--partscan", str(image)]
        self.log(f"Running: {' '.join(cmd)}", "DEBUG")
        
        try:
            res = runner.run(cmd, timeout=60, check=True)
        except ToolError as e:
            # More specific error
            raise ToolError(f"losetup failed. Ensure you have sudo and kernel supports loop devices.\nOriginal error: {e}")
        
        loop = res.stdout.strip()
        if not loop:
            raise ToolError("losetup returned empty string. Check dmesg for kernel errors.")
        
        self.log(f"Successfully attached to: {loop}", "INFO")
        
        # Verify it exists
        if not Path(loop).exists():
            raise ToolError(f"Loop device {loop} doesn't exist after losetup!")
        
        return loop

    def _select_partition(self, runner: SafeRunner, loop_dev: str) -> str:
        """Select the largest viable partition from loop device."""
        self.log(f"Scanning partitions on: {loop_dev}", "INFO")
        
        # First get human-readable output for logging
        res = runner.run(["lsblk", "-o", "NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT", loop_dev], timeout=30)
        self.log(f"lsblk output:\n{res.stdout}", "DEBUG")
        
        # Use fdisk to get partition information
        res = runner.run(["fdisk", "-l", loop_dev], timeout=30)
        self.log(f"fdisk output:\n{res.stdout}", "DEBUG")
        
        # Parse partitions from fdisk output
        parts = []
        in_partition_table = False
        for line in res.stdout.splitlines():
            line = line.strip()
            
            # Look for partition table start
            if "Device" in line and "Start" in line and "End" in line:
                in_partition_table = True
                continue
            
            if in_partition_table and line:
                # Parse partition line like: /dev/loop0p1      2048    4095    2048   1M BIOS boot
                cols = line.split()
                if len(cols) >= 6:
                    device = cols[0]
                    if device.startswith(f"{loop_dev}p"):
                        try:
                            # Get size (usually in bytes, KB, MB, GB)
                            size_units = cols[4]  # Size units (e.g., "1M", "500G")
                            
                            # Convert size to bytes for comparison
                            size_bytes = 0
                            if size_units.endswith('G'):
                                size_bytes = int(float(size_units[:-1]) * 1024 * 1024 * 1024)
                            elif size_units.endswith('M'):
                                size_bytes = int(float(size_units[:-1]) * 1024 * 1024)
                            elif size_units.endswith('K'):
                                size_bytes = int(float(size_units[:-1]) * 1024)
                            elif size_units.endswith('B'):
                                size_bytes = int(size_units[:-1])
                            else:  # Assume bytes if no unit
                                try:
                                    size_bytes = int(size_units)
                                except ValueError:
                                    continue
                            
                            # Skip very small partitions (like 1MB BIOS boot)
                            if size_bytes > 10 * 1024 * 1024:  # More than 10MB
                                parts.append((device, size_bytes, size_units))
                                self.log(f"Found partition: {device} size={size_units} ({size_bytes} bytes)", "DEBUG")
                        except (ValueError, IndexError) as e:
                            self.log(f"Error parsing partition line '{line}': {e}", "WARNING")
                            continue
        
        if not parts:
            self.log(f"No suitable partitions found via fdisk, trying alternative methods", "WARNING")
            
            # Alternative: check for partitions directly
            for i in range(1, 10):  # Check up to 10 partitions
                part_device = f"{loop_dev}p{i}"
                if Path(part_device).exists():
                    # Get size using blockdev
                    res = runner.run(["blockdev", "--getsize64", part_device], timeout=10)
                    if res.returncode == 0:
                        try:
                            size_bytes = int(res.stdout.strip())
                            if size_bytes > 10 * 1024 * 1024:
                                parts.append((part_device, size_bytes, f"{size_bytes/(1024*1024*1024):.1f}G"))
                                self.log(f"Found partition via direct check: {part_device} size={size_bytes} bytes", "DEBUG")
                        except ValueError:
                            continue
        
        if not parts:
            # Last resort: check if whole device is mountable
            self.log(f"No partitions found, checking if whole device is mountable...", "WARNING")
            
            # Check what blkid says about the whole device
            res = runner.run(["blkid", loop_dev], timeout=10)
            if res.returncode == 0:
                blkid_output = res.stdout.strip()
                self.log(f"blkid on whole device: {blkid_output}", "DEBUG")
                
                # Check for LUKS encryption
                if "crypto_LUKS" in blkid_output:
                    raise ToolError(
                        f"Device {loop_dev} appears to be LUKS encrypted.\n\n"
                        "Manual decryption required:\n"
                        f"  sudo cryptsetup luksOpen {loop_dev} decrypted_volume\n"
                        f"  sudo mount /dev/mapper/decrypted_volume /mnt/mountpoint"
                    )
                elif "TYPE=" in blkid_output:
                    # Whole device has a filesystem
                    self.log(f"Whole device {loop_dev} has filesystem, using it", "INFO")
                    return loop_dev
            
            # Try file command
            res = runner.run(["file", "-s", loop_dev], timeout=10)
            if res.returncode == 0:
                file_output = res.stdout.strip()
                self.log(f"file says: {file_output}", "DEBUG")
                if "filesystem" in file_output.lower() or "data" in file_output.lower():
                    self.log(f"Whole device might be mountable", "INFO")
                    return loop_dev
            
            raise ToolError(
                f"No mountable partitions found on {loop_dev}.\n\n"
                "The image might be:\n"
                "1. Encrypted (LUKS)\n"
                "2. Corrupted\n"
                "3. Have an unsupported filesystem\n\n"
                "Try manual troubleshooting:\n"
                f"  sudo blkid {loop_dev}\n"
                f"  sudo file -s {loop_dev}\n"
                f"  sudo fdisk -l {loop_dev}"
            )
        
        # Sort by size (largest first)
        parts.sort(key=lambda x: x[1], reverse=True)
        
        # Choose the largest partition
        chosen = parts[0][0]
        chosen_size_gb = parts[0][1] / (1024*1024*1024)
        self.log(f"Selected largest partition: {chosen} ({chosen_size_gb:.1f} GB)", "INFO")
        
        # Verify with blkid
        res = runner.run(["blkid", chosen], timeout=10)
        if res.returncode == 0:
            blkid_output = res.stdout.strip()
            self.log(f"blkid on {chosen}: {blkid_output}", "DEBUG")
            
            # Check for LUKS
            if "crypto_LUKS" in blkid_output:
                raise ToolError(
                    f"Partition {chosen} appears to be LUKS encrypted.\n\n"
                    "Manual decryption required:\n"
                    f"  sudo cryptsetup luksOpen {chosen} decrypted_volume\n"
                    f"  sudo mount /dev/mapper/decrypted_volume /mnt/mountpoint\n\n"
                    "After mounting, use Option B (Already mounted root) in this tool."
                )
        
        return chosen

    def _mount_readonly(self, runner: SafeRunner, device: str, mount_point: Path):
        """Mount device read-only with appropriate options."""
        self.log(f"Mounting {device} to {mount_point}", "INFO")
        
        # Check for LUKS encryption before attempting mount
        res = runner.run(["blkid", device], timeout=10)
        if res.returncode == 0:
            blkid_output = res.stdout.strip()
            self.log(f"blkid output: {blkid_output}", "DEBUG")
            if "crypto_LUKS" in blkid_output:
                raise ToolError(
                    f"Device {device} is LUKS encrypted.\n\n"
                    "Manual decryption required:\n"
                    f"  sudo cryptsetup luksOpen {device} decrypted_volume\n"
                    f"  sudo mount /dev/mapper/decrypted_volume {mount_point}\n\n"
                    "After mounting, use Option B (Already mounted root) in this tool."
                )
        
        # Clean/create mount point
        if mount_point.exists():
            self.log(f"Mount point exists: {mount_point}", "DEBUG")
            # Try to unmount if already mounted
            runner.run(["umount", "-l", str(mount_point)], timeout=20, check=False)
        else:
            safe_mkdir(mount_point)
        
        # Detect filesystem type
        fstype = "auto"
        try:
            r = runner.run(["blkid", "-o", "value", "-s", "TYPE", device], timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                fstype = r.stdout.strip().lower()
                self.log(f"Detected filesystem via blkid: {fstype}", "INFO")
            else:
                # Try file command as fallback
                r = runner.run(["file", "-s", device], timeout=10)
                if r.returncode == 0:
                    file_output = r.stdout.strip().lower()
                    if "ext4" in file_output:
                        fstype = "ext4"
                    elif "ext3" in file_output:
                        fstype = "ext3"
                    elif "xfs" in file_output:
                        fstype = "xfs"
                    elif "btrfs" in file_output:
                        fstype = "btrfs"
                    elif "ntfs" in file_output:
                        fstype = "ntfs"
                    self.log(f"Detected filesystem via file: {fstype}", "INFO")
        except Exception as e:
            self.log(f"Filesystem detection warning: {e}", "WARNING")
        
        # Set mount options based on filesystem
        opts = "ro"
        if fstype.startswith("ext"):
            opts = "ro,noload"
            self.log("Using ext* options: ro,noload", "DEBUG")
        elif fstype == "xfs":
            opts = "ro,norecovery"
            self.log("Using XFS options: ro,norecovery", "DEBUG")
        elif fstype == "ntfs":
            opts = "ro,users"
            self.log("Using NTFS options: ro,users", "DEBUG")
        elif fstype == "vfat" or fstype == "fat":
            opts = "ro,uid=1000,gid=1000,utf8"
            self.log("Using FAT options: ro,uid=1000,gid=1000,utf8", "DEBUG")
        
        # Try mounting with detected filesystem type
        success = False
        error_msgs = []
        
        # First try with detected filesystem
        if fstype != "auto":
            mount_cmd = ["mount", "-t", fstype, "-o", opts, device, str(mount_point)]
            self.log(f"Attempt 1: Mount command: {' '.join(mount_cmd)}", "DEBUG")
            
            r = runner.run(mount_cmd, timeout=50)
            if r.returncode == 0:
                success = True
                self.log(f"Successfully mounted with fstype={fstype}", "INFO")
            else:
                error_msgs.append(f"With fstype={fstype}: {r.stderr.strip()}")
        
        # If first attempt failed, try common filesystem types
        if not success:
            common_fstypes = ["ext4", "ext3", "xfs", "btrfs", "ntfs", "vfat", "ext2"]
            for try_fstype in common_fstypes:
                if try_fstype == fstype:  # Skip already tried
                    continue
                    
                mount_cmd = ["mount", "-t", try_fstype, "-o", opts, device, str(mount_point)]
                self.log(f"Attempt with fstype={try_fstype}: {' '.join(mount_cmd)}", "DEBUG")
                
                r = runner.run(mount_cmd, timeout=30)
                if r.returncode == 0:
                    success = True
                    self.log(f"Successfully mounted with fstype={try_fstype}", "INFO")
                    break
                else:
                    error_msgs.append(f"With fstype={try_fstype}: {r.stderr.strip()}")
        
        # Last resort: try auto detection
        if not success:
            self.log("Trying mount with auto detection...", "DEBUG")
            r = runner.run(["mount", "-o", "ro", device, str(mount_point)], timeout=30)
            
            if r.returncode == 0:
                success = True
                self.log("Successfully mounted with auto detection", "INFO")
            else:
                error_msgs.append(f"Auto detection: {r.stderr.strip()}")
        
        if not success:
            # Get more detailed error info
            dmesg = runner.run(["dmesg", "--color=never", "-T"], timeout=10)
            dmesg_tail = "\n".join(dmesg.stdout.splitlines()[-20:]) if dmesg.returncode == 0 else "Could not read dmesg"
            
            # Try to get filesystem info
            fs_info = ""
            res = runner.run(["blkid", device], timeout=10)
            if res.returncode == 0:
                fs_info = f"blkid says: {res.stdout.strip()}\n"
            
            res = runner.run(["file", "-s", device], timeout=10)
            if res.returncode == 0:
                fs_info += f"file says: {res.stdout.strip()}\n"
            
            raise ToolError(
                f"All mount attempts failed for {device}.\n\n"
                f"Filesystem info:\n{fs_info}\n"
                f"Error messages:\n" + "\n".join(error_msgs[-3:]) + "\n\n"
                "Recent kernel messages:\n"
                f"{dmesg_tail}\n\n"
                "Try manual troubleshooting:\n"
                f"  1. Check filesystem: sudo blkid {device}\n"
                f"  2. Examine raw data: sudo file -s {device}\n"
                f"  3. Try manual mount: sudo mount -o ro {device} {mount_point}\n"
                f"  4. Check if filesystem needs repair: sudo fsck -n {device}"
            )

    def _health_probe(self, root: Path):
        # Quick probe for I/O errors. Doesn't "repair" anything.
        probe_paths = [root / "etc", root / "var/log", root / "var/lib/docker", root / "var/lib/docker/overlay2"]
        for p in probe_paths:
            try:
                if p.exists() and p.is_dir():
                    _ = next(p.iterdir(), None)
            except OSError as e:
                if e.errno == errno.EIO:
                    self.stats["walk_eio"] += 1
                    self.warnings.append(f"EIO while probing {p}. Some artefacts may be unreadable.")
                    self.log(f"[EIO] Input/output error while probing: {p}", "WARNING")
            except PermissionError:
                self.stats["walk_perm"] += 1
                self.warnings.append(f"Permission denied probing {p}. Some artefacts may be inaccessible.")
                self.log(f"[PERM] Permission denied while probing: {p}", "WARNING")

    # ---------- Discovery logic ----------

    def _read_text(self, p: Path, max_bytes: int = 400_000) -> Optional[str]:
        try:
            if p.exists() and p.is_file():
                return p.read_text(errors="replace")[:max_bytes]
        except PermissionError:
            self.stats["walk_perm"] += 1
        except OSError as e:
            if e.errno == errno.EIO:
                self.stats["walk_eio"] += 1
        except Exception:
            self.stats["walk_other"] += 1
        return None

    def _collect_os_facts(self, root: Path) -> Dict[str, object]:
        """Collect OS identification facts + 'Hadoop-related users' hints.

        Note: On containerised stacks (e.g., HDP sandbox), service users may exist *inside*
        container layers rather than in the host /etc/passwd. We therefore:
          1) parse host /etc/passwd + /etc/group
          2) if Docker overlay2 exists, sample a few overlay diffs for /etc/passwd + /etc/group

        The goal is a *hint list* for investigators, not a complete account database dump.
        """
        facts: Dict[str, object] = {"distro": None, "hostname": None, "users_hint": []}

        # --- Distro
        osr = self._read_text(root / "etc/os-release")
        if osr:
            for line in osr.splitlines():
                if line.startswith("PRETTY_NAME="):
                    facts["distro"] = line.split("=", 1)[1].strip().strip('"')
                    break

        # --- Hostname
        hn = self._read_text(root / "etc/hostname")
        if hn:
            facts["hostname"] = hn.strip().splitlines()[0] if hn.strip() else None

        KEYWORDS = [
            "hadoop", "hdfs", "yarn", "mapred", "spark", "hive", "hbase", "oozie",
            "zookeeper", "zoo", "zk", "ranger", "kafka", "ambari", "tez", "livy",
        ]

        def parse_passwd_group(passwd_text: str, group_text: str) -> List[str]:
            # Map gid -> groupname, and collect groups whose name suggests Hadoop/ecosystem
            gid_to_name: Dict[str, str] = {}
            target_gids: set[str] = set()
            group_members: set[str] = set()

            if group_text:
                for line in group_text.splitlines():
                    if not line or ":" not in line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    gname, gid = parts[0], parts[2]
                    gid_to_name[gid] = gname
                    if any(k in gname.lower() for k in KEYWORDS):
                        target_gids.add(gid)
                        # members list (may be empty)
                        if len(parts) >= 4 and parts[3].strip():
                            for u in parts[3].split(","):
                                if u.strip():
                                    group_members.add(u.strip())

            # Passwd scan: (a) username contains keyword, (b) user's primary gid maps to target group
            users: set[str] = set(group_members)
            if passwd_text:
                for line in passwd_text.splitlines():
                    if ":" not in line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 4:
                        continue
                    u = parts[0]
                    gid = parts[3]
                    if any(k in u.lower() for k in KEYWORDS):
                        users.add(u)
                        continue
                    if gid in target_gids:
                        users.add(u)
                        continue
            return sorted(users)

        # 1) Host-level files
        host_passwd = self._read_text(root / "etc/passwd") or ""
        host_group = self._read_text(root / "etc/group") or ""
        users = parse_passwd_group(host_passwd, host_group)

        # 2) Container overlay sampling (best effort)
        overlay2 = root / "var/lib/docker/overlay2"
        if overlay2.exists():
            sampled = 0
            # sample first ~15 overlay 'diff/etc/passwd' occurrences
            for d, files in self._bounded_walk(overlay2, max_depth=5):
                if sampled >= 15:
                    break
                # look for diff/etc/passwd and diff/etc/group
                if d.name != "etc":
                    continue
                parent = d.parent  # .../diff
                if parent.name != "diff":
                    continue
                p_passwd = d / "passwd"
                p_group = d / "group"
                if p_passwd.exists() or p_group.exists():
                    pw = self._read_text(p_passwd) or ""
                    gr = self._read_text(p_group) or ""
                    users.extend(parse_passwd_group(pw, gr))
                    sampled += 1

            users = sorted(set(users))

        facts["users_hint"] = users[:30]
        return facts


    def _bounded_walk(self, start: Path, *, max_depth: int, follow_symlinks: bool = False) -> Iterable[Tuple[Path, List[Path]]]:
        start = start.resolve()
        start_depth = len(start.parts)
        stack = [start]
        while stack:
            self._check_stop()
            d = stack.pop()
            try:
                depth = len(d.parts) - start_depth
                if depth > max_depth:
                    continue
                try:
                    s = "/" + "/".join(d.resolve().parts[1:])
                except Exception:
                    s = str(d)
                if any(s.startswith(pref) for pref in DEFAULT_SKIP_DIR_PREFIXES):
                    continue
                if d.is_symlink() and not follow_symlinks:
                    continue
                entries = list(d.iterdir())
            except PermissionError:
                self.stats["walk_perm"] += 1
                continue
            except OSError as e:
                if e.errno == errno.EIO:
                    self.stats["walk_eio"] += 1
                    continue
                self.stats["walk_other"] += 1
                continue

            files = []
            for e in entries:
                self._check_stop()
                try:
                    if e.is_dir():
                        stack.append(e)
                    elif e.is_file():
                        files.append(e)
                except PermissionError:
                    self.stats["walk_perm"] += 1
                except OSError as oe:
                    if oe.errno == errno.EIO:
                        self.stats["walk_eio"] += 1
                    else:
                        self.stats["walk_other"] += 1
            yield (d, files)

    def _discover_hadoop(self, root: Path) -> Dict[str, object]:
        names = set(TARGETS["Configs_Hadoop"])
        hits: List[Path] = []

        # Quick hints first (fast)
        for rel in COMMON_DIR_HINTS:
            p = root / rel
            if not p.exists() or not p.is_dir():
                continue
            try:
                for f in p.iterdir():
                    if f.is_file() and f.name in names:
                        hits.append(f)
            except Exception:
                continue

        # Bounded walk
        for d, files in self._bounded_walk(root, max_depth=int(self.max_depth.get())):
            for f in files:
                if f.name in names:
                    hits.append(f)
            if len(hits) > 500:
                break

        cfg_dirs = sorted({str(p.parent) for p in hits})
        # Infer Hadoop home candidates from .../etc/hadoop patterns
        hhomes = set()
        for cd in cfg_dirs:
            if cd.endswith("/etc/hadoop"):
                hhomes.add(str(Path(cd).parent.parent))
            if cd.endswith("/etc/hadoop/conf"):
                hhomes.add(str(Path(cd).parent.parent.parent))
        hdfs_props = self._parse_hadoop_xml(hits)
        workers = self._parse_workers(hits)

        return {
            "config_candidates": len(hits),
            "config_dirs_sample": cfg_dirs[:25],
            "hadoop_home_candidates": sorted(hhomes)[:15],
            "hdfs_props": hdfs_props,
            "workers": workers
        }

    def _discover_ecosystem(self, root: Path) -> Dict[str, object]:
        # Detect presence of ecosystem configs (best effort)
        eco_names = set(TARGETS["Ecosystem_Apps"])
        found = {}
        count = 0
        for d, files in self._bounded_walk(root, max_depth=int(self.max_depth.get())):
            for f in files:
                if f.name in eco_names:
                    found.setdefault(f.name, []).append(str(f))
                    count += 1
            if count > 400:
                break
        # Summarise "components" by typical signature presence
        components = set()
        for k in found.keys():
            lk = k.lower()
            if "zoo" in lk:
                components.add("ZooKeeper")
            elif "hive" in lk:
                components.add("Hive")
            elif "spark" in lk:
                components.add("Spark")
            elif "hbase" in lk:
                components.add("HBase")
            elif "oozie" in lk:
                components.add("Oozie")
            elif "flume" in lk:
                components.add("Flume")
            elif "sqoop" in lk:
                components.add("Sqoop")
            elif "ranger" in lk:
                components.add("Ranger")
            elif "server.properties" in lk:
                components.add("Kafka")
        return {"components": sorted(components), "hits": found, "hit_count": count}

    def _parse_hadoop_xml(self, cfg_hits: List[Path]) -> Dict[str, str]:
        want = {
            "fs.defaultFS", "dfs.replication", "dfs.namenode.name.dir", "dfs.datanode.data.dir",
            "hadoop.security.authentication", "hadoop.security.authorization",
            "dfs.encrypt.data.transfer", "dfs.data.transfer.protection",
            "hadoop.http.authentication.type", "dfs.webhdfs.enabled"
        }
        out: Dict[str, str] = {}
        for p in cfg_hits:
            if not p.name.endswith("-site.xml"):
                continue
            txt = self._read_text(p)
            if not txt:
                continue
            parts = txt.split("<property>")
            for chunk in parts[1:]:
                if "<name>" not in chunk or "<value>" not in chunk:
                    continue
                try:
                    name = chunk.split("<name>", 1)[1].split("</name>", 1)[0].strip()
                    if name not in want or name in out:
                        continue
                    val = chunk.split("<value>", 1)[1].split("</value>", 1)[0].strip()
                    if val:
                        out[name] = val
                except Exception:
                    continue
        return out

    def _parse_workers(self, cfg_hits: List[Path]) -> List[str]:
        out = []
        for p in cfg_hits:
            if p.name in ("workers", "slaves"):
                txt = self._read_text(p)
                if not txt:
                    continue
                for line in txt.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.append(line)
        return sorted(set(out))[:60]

    def _discover_containers(self, root: Path) -> Dict[str, object]:
        facts: Dict[str, object] = {
            "roots_present": [],
            "docker_present": False,
            "overlay2_present": False,
            "containers_count": 0,
            "container_meta_files": 0,
            "overlay_config_candidates": 0,
            "volume_config_candidates": 0
        }
        for r in CONTAINER_ROOTS:
            if (root / r).exists():
                facts["roots_present"].append("/" + r)

        docker_root = root / "var/lib/docker"
        containers_dir = docker_root / "containers"
        overlay2 = docker_root / "overlay2"
        volumes = docker_root / "volumes"

        if docker_root.exists():
            facts["docker_present"] = True
        if overlay2.exists():
            facts["overlay2_present"] = True

        # container metadata
        meta_hits = 0
        container_ids = set()
        if containers_dir.exists():
            for d, files in self._bounded_walk(containers_dir, max_depth=4):
                for f in files:
                    if f.name in TARGETS["Container_Metadata"] or f.name.endswith("-json.log"):
                        meta_hits += 1
                        container_ids.add(f.parent.name)
                if meta_hits > 500:
                    break
        facts["container_meta_files"] = meta_hits
        facts["containers_count"] = len(container_ids)

        # overlay configs
        cfg_names = set(TARGETS["Configs_Hadoop"] + TARGETS["Ecosystem_Apps"])
        overlay_hits = 0
        if overlay2.exists():
            for d, files in self._bounded_walk(overlay2, max_depth=7):
                for f in files:
                    if f.name in cfg_names:
                        overlay_hits += 1
                if overlay_hits > 700:
                    break
        facts["overlay_config_candidates"] = overlay_hits

        vol_hits = 0
        if volumes.exists():
            for d, files in self._bounded_walk(volumes, max_depth=7):
                for f in files:
                    if f.name in cfg_names:
                        vol_hits += 1
                if vol_hits > 700:
                    break
        facts["volume_config_candidates"] = vol_hits

        return facts

    # ---------- Extraction + hashing ----------

    def _hash_file(self, path: Path, algo: str) -> str:
        """Hash a file with progress updates so examiners don't think it froze."""
        h = hashlib.new(algo)
        try:
            total = path.stat().st_size
        except Exception:
            total = 0

        chunk_size = 4 * 1024 * 1024  # 4 MiB
        read_bytes = 0
        started = time.time()
        last_ui = started

        def _fmt(n: int) -> str:
            # Friendly size formatter (bytes → KiB/MiB/GiB)
            units = ["B", "KiB", "MiB", "GiB", "TiB"]
            v = float(max(n, 0))
            i = 0
            while v >= 1024.0 and i < len(units) - 1:
                v /= 1024.0
                i += 1
            if i == 0:
                return f"{int(v)} {units[i]}"
            return f"{v:.2f} {units[i]}"

        with path.open("rb") as f:
            while True:
                self._check_stop()
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
                read_bytes += len(chunk)

                now = time.time()
                # Update console about once per second (or on completion)
                if now - last_ui >= 1.0:
                    elapsed = max(now - started, 0.001)
                    speed = read_bytes / elapsed  # B/s
                    if total > 0:
                        pct = (read_bytes / total) * 100.0
                        eta = (total - read_bytes) / max(speed, 1.0)
                        self.log(
                            f"Hashing progress: {pct:5.1f}%  ({_fmt(read_bytes)} / {_fmt(total)})  "
                            f"speed {_fmt(int(speed))}/s  ETA ~{int(eta)}s",
                            "INFO",
                        )
                    else:
                        self.log(
                            f"Hashing progress: {_fmt(read_bytes)} read  speed {_fmt(int(speed))}/s",
                            "INFO",
                        )
                    last_ui = now

        # Final line (always)
        elapsed = max(time.time() - started, 0.001)
        speed = read_bytes / elapsed
        if total > 0:
            self.log(f"Hashing complete: {_fmt(read_bytes)} / {_fmt(total)} at {_fmt(int(speed))}/s", "INFO")
        else:
            self.log(f"Hashing complete: {_fmt(read_bytes)} read at {_fmt(int(speed))}/s", "INFO")
        return h.hexdigest()

    def _safe_stat(self, p: Path) -> Tuple[int, str]:
        try:
            st = p.stat()
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            return st.st_size, mtime
        except PermissionError:
            self.stats["walk_perm"] += 1
        except OSError as e:
            if e.errno == errno.EIO:
                self.stats["walk_eio"] += 1
            else:
                self.stats["walk_other"] += 1
        except Exception:
            self.stats["walk_other"] += 1
        return 0, utc_now_iso()

    def _copy2(self, src: Path, dst: Path) -> bool:
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            return True
        except PermissionError:
            self.stats["walk_perm"] += 1
        except OSError as e:
            if e.errno == errno.EIO:
                self.stats["walk_eio"] += 1
            else:
                self.stats["walk_other"] += 1
        except Exception:
            self.stats["walk_other"] += 1
        return False

    def _match_category(self, filename: str) -> Optional[str]:
        for cat, sigs in TARGETS.items():
            for s in sigs:
                if filename == s or filename.startswith(s):
                    return cat
        # handle fsimage_/edits_ patterns
        if filename.startswith(("fsimage_", "edits_", "edits_inprogress_", "edits.inprogress")):
            return "HDFS_Metadata"
        return None

    def _extract(self, vault: Path, manifest_path: Path, root: Path, algo: str) -> Dict[str, int]:
        copied = 0
        considered = 0
        max_files = int(self.max_files.get())
        max_depth = int(self.max_depth.get())

        anchors: List[Tuple[str, Path]] = [("host_root", root)]
        if self.include_containers.get():
            docker_root = root / "var/lib/docker"
            if docker_root.exists():
                anchors.extend([
                    ("docker_containers", docker_root / "containers"),
                    ("docker_volumes", docker_root / "volumes"),
                    ("docker_overlay2", docker_root / "overlay2"),
                ])

        with manifest_path.open("w", encoding="utf-8") as mf:
            for anchor_name, anchor in anchors:
                self._check_stop()
                if not anchor.exists():
                    continue
                self.log(f"Scanning anchor: {anchor_name} → {anchor}", "INFO")

                for d, files in self._bounded_walk(anchor, max_depth=max_depth):
                    self._check_stop()
                    for f in files:
                        self._check_stop()
                        if copied >= max_files:
                            self.warnings.append(f"Reached max file cap ({max_files}). Extraction stopped early.")
                            self.log(f"Reached max file cap ({max_files}). Stopping extraction.", "WARNING")
                            return {"copied": copied, "considered": considered}

                        considered += 1
                        cat = self._match_category(f.name)
                        if not cat:
                            continue

                        try:
                            rel = f.relative_to(root)
                        except Exception:
                            rel = f.name

                        dst = vault / cat / rel
                        if not self._copy2(f, dst):
                            continue

                        size, mtime = self._safe_stat(f)
                        ef = EvidenceFile(category=cat, src=str(f), dst=str(dst), size=size, mtime_utc=mtime)

                        if algo != "none":
                            try:
                                self._check_stop()
                                hv = self._hash_file(dst, algo)
                                ef.hash_algo = algo
                                ef.hash_value = hv
                                ef.sha256 = hv if algo == "sha256" else self._hash_file(dst, "sha256")
                            except Exception:
                                self.stats["walk_other"] += 1

                        self.evidence.append(ef)
                        copied += 1

                        mf.write(json.dumps({
                            "category": ef.category,
                            "src": ef.src,
                            "dst": ef.dst,
                            "size": ef.size,
                            "mtime_utc": ef.mtime_utc,
                            "sha256": ef.sha256,
                            "hash": {"algo": ef.hash_algo, "value": ef.hash_value} if ef.hash_algo else None
                        }) + "\n")

                        if copied % 100 == 0:
                            self.log(f"Copied {copied} artefacts…", "INFO")

        return {"copied": copied, "considered": considered}

    # ---------- Reporting ----------

    def _write_reports(self, out: Path, meta: Dict[str, object], os_facts: Dict[str, object],
                       hadoop_facts: Dict[str, object], eco_facts: Dict[str, object],
                       container_facts: Dict[str, object], extracted: Dict[str, int]):

        safe_mkdir(out / "logs")

        # report.json
        report_json = out / "report.json"
        report_json.write_text(json.dumps({
            "meta": meta,
            "os_facts": os_facts,
            "hadoop_facts": hadoop_facts,
            "ecosystem_facts": eco_facts,
            "container_facts": container_facts,
            "extraction": extracted,
            "warnings": self.warnings,
            "errors": self.errors,
            "stats": self.stats,
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        # summary markdown for non-technical examiners
        by_cat: Dict[str, int] = {}
        for ef in self.evidence:
            by_cat[ef.category] = by_cat.get(ef.category, 0) + 1

        def bullets(items: List[str], limit: int = 20) -> str:
            if not items:
                return "  - *(none)*"
            return "\n".join([f"  - `{x}`" for x in items[:limit]])

        hdfs_props = hadoop_facts.get("hdfs_props") or {}
        props_md = "\n".join([f"- **{k}:** `{v}`" for k, v in hdfs_props.items()]) if hdfs_props else "- *(No Hadoop XML key properties parsed)*"
        workers = hadoop_facts.get("workers") or []

        # Interpretations (brief, examiner-friendly)
        interpretations = [
            ("HDFS metadata (fsimage/edits/seen_txid)", "Reconstructs namespace, timeline, and metadata state for HDFS."),
            ("Hadoop configs (core-site/hdfs-site/yarn-site/mapred-site)", "Shows cluster topology, storage paths, replication factor, and security settings."),
            ("OS artefacts (/etc/passwd,/etc/shadow,/etc/ssh/sshd_config)", "Supports user attribution, privilege analysis, and remote access auditing."),
            ("Logs (auth/syslog/messages)", "Supports timeline building and detection of suspicious access or failures."),
            ("Container metadata (Docker config.v2.json, logs)", "Maps services running in containers and their config/log locations.")
        ]

        exec_md = out / "Executive_Summary.md"
        exec_md.write_text(
            f"""# Hadoop Forensics Kickstart — Executive Summary

## Run metadata
- **Tool version:** {meta.get('tool_version')}
- **Started (UTC):** {meta.get('started_utc')}
- **Finished (UTC):** {meta.get('finished_utc')}
- **Execution time (sec):** {meta.get('execution_seconds')}
- **Examiner:** {meta.get('examiner')}
- **Workstation:** {meta.get('host')}

## Evidence & integrity
- **Source image:** `{meta.get('source', {}).get('image')}`
- **Mounted root (if manual):** `{meta.get('source', {}).get('root')}`
- **Mount method:** `{meta.get('mount', {}).get('method')}`
- **Loop device:** `{meta.get('mount', {}).get('loop_dev')}`
- **Mounted device:** `{meta.get('mount', {}).get('mounted_dev')}`
- **Mount point used:** `{meta.get('mount', {}).get('mount_point')}`
- **Image hash:** {json.dumps(meta.get('image_hash'), ensure_ascii=False)}
- **Hash verification:** {json.dumps(meta.get('hash_verification'), ensure_ascii=False)}

> [Caution] Hashing is recommended for evidential defensibility. If hashing was skipped, document the reason.

## System identification (from mounted image)
- **Distro:** `{os_facts.get('distro')}`
- **Hostname:** `{os_facts.get('hostname')}`
- **Hadoop-related OS users (hint):** {", ".join(os_facts.get('users_hint') or []) or "*none observed in /etc/passwd*"}

## Hadoop footprint probe (generic)
- **Config candidates found:** `{hadoop_facts.get('config_candidates')}`
- **Config directories inferred (sample):**
{bullets(hadoop_facts.get('config_dirs_sample') or [])}
- **HADOOP_HOME candidates (sample):**
{bullets(hadoop_facts.get('hadoop_home_candidates') or [])}

## HDFS configuration snapshot (key properties)
{props_md}

## Node topology (best effort)
- **DataNodes (workers/slaves):**
{bullets(workers, limit=60)}

## Ecosystem components (best effort)
- **Detected components:** {", ".join(eco_facts.get("components") or []) or "none detected"}
- **Evidence hits (count):** {eco_facts.get("hit_count", 0)}

## Container runtime probe (best effort)
{json.dumps(container_facts, indent=2, ensure_ascii=False) if container_facts else "- *(disabled or not detected)*"}

## Extraction results
- **Files considered:** {extracted.get('considered', 0)}
- **Files copied (Evidence_Vault):** {extracted.get('copied', 0)}
- **Copied by category:** {json.dumps(by_cat, ensure_ascii=False)}

## Scan health diagnostics
- **Permission errors encountered:** {self.stats.get('walk_perm', 0)}
- **Input/output (EIO) errors encountered:** {self.stats.get('walk_eio', 0)}
- **Other errors encountered:** {self.stats.get('walk_other', 0)}

## Warnings
{bullets(self.warnings, limit=30)}

## What these artefacts represent (quick guide)
{chr(10).join([f"- **{k}:** {v}" for k, v in interpretations])}

## Output structure
- `Evidence_Vault/` — extracted artefacts grouped by category and original relative path
- `manifest.jsonl` — one JSON line per extracted file (hashes + metadata)
- `report.json` — machine-readable full report (facts, warnings, stats)
- `logs/tool.log` — detailed execution log
""",
            encoding="utf-8"
        )

    # ---------- End ----------

def main():
    root = tk.Tk()
    app = HadoopForensicsGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
