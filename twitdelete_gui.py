#!/usr/bin/env python3
"""Legacy-only GUI launcher for twitdelete.py."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk


def app_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name: str) -> str:
    """Resolve file path for normal and PyInstaller-frozen runs."""
    meipass = getattr(sys, "_MEIPASS", "")
    candidates = []
    if meipass:
        candidates.append(os.path.join(meipass, name))
    candidates.append(os.path.join(app_base_dir(), name))
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


BASE_DIR = app_base_dir()
DEFAULT_BROWSER = "edge"
DEFAULT_CDP_URL = "http://127.0.0.1:9222"
DEFAULT_AUTH_FILE = "auth.json"
MAX_LOG_LINES = 3000


class TwitDeleteGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("twitdelete GUI (Legacy)")
        self.geometry("960x660")
        self.minsize(860, 580)

        self.process: subprocess.Popen[str] | None = None
        self.read_thread: threading.Thread | None = None
        self.log_queue: queue.Queue[str | None] = queue.Queue()
        self.python_command = self._detect_python_command()
        self.log_line_count = 0
        self.is_closing = False

        self._init_vars()
        self._build_ui()
        self._update_command_preview()
        self.protocol("WM_DELETE_WINDOW", self._on_close_requested)

    def _init_vars(self) -> None:
        # User-facing options
        self.max_var = tk.StringVar(value="0")
        self.timeline_pages_var = tk.StringVar(value="8")
        self.timeline_page_size_var = tk.StringVar(value="40")
        self.batch_limit_var = tk.StringVar(value="20")
        self.delay_var = tk.StringVar(value="1.5")
        self.timeout_var = tk.StringVar(value="20")
        self.pass_delay_var = tk.StringVar(value="2.0")
        self.pass_limit_var = tk.StringVar(value="0")
        self.before_var = tk.StringVar()
        self.after_var = tk.StringVar()
        self.contains_var = tk.StringVar()

        self.include_replies_var = tk.BooleanVar(value=True)
        self.delete_all_var = tk.BooleanVar(value=True)
        self.media_tab_var = tk.BooleanVar(value=False)
        self.media_delete_conversation_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=False)

        self.command_preview_var = tk.StringVar()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        opts = ttk.LabelFrame(root, text="옵션", padding=10)
        opts.grid(row=0, column=0, sticky="ew")
        opts.columnconfigure(1, weight=1)
        opts.columnconfigure(3, weight=1)

        ttk.Label(opts, text="max").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.max_var, width=12).grid(row=0, column=1, sticky="w", pady=2)

        ttk.Label(opts, text="batch limit").grid(row=0, column=2, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.batch_limit_var, width=12).grid(row=0, column=3, sticky="w", pady=2)

        ttk.Label(opts, text="timeline pages").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.timeline_pages_var, width=12).grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(opts, text="timeline page size").grid(row=1, column=2, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.timeline_page_size_var, width=12).grid(row=1, column=3, sticky="w", pady=2)

        ttk.Label(opts, text="delay (sec)").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.delay_var, width=12).grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(opts, text="timeout (sec)").grid(row=2, column=2, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.timeout_var, width=12).grid(row=2, column=3, sticky="w", pady=2)

        ttk.Label(opts, text="pass delay").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.pass_delay_var, width=12).grid(row=3, column=1, sticky="w", pady=2)

        ttk.Label(opts, text="pass limit").grid(row=3, column=2, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.pass_limit_var, width=12).grid(row=3, column=3, sticky="w", pady=2)

        ttk.Label(opts, text="before (UTC)").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.before_var).grid(row=4, column=1, sticky="ew", pady=2)

        ttk.Label(opts, text="after (UTC)").grid(row=4, column=2, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.after_var).grid(row=4, column=3, sticky="ew", pady=2)

        ttk.Label(opts, text="contains").grid(row=5, column=0, sticky="w", pady=2)
        ttk.Entry(opts, textvariable=self.contains_var).grid(row=5, column=1, columnspan=3, sticky="ew", pady=2)

        checks = ttk.Frame(opts)
        checks.grid(row=6, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Checkbutton(checks, text="media tab", variable=self.media_tab_var).pack(side="left")
        ttk.Checkbutton(
            checks,
            text="media conversation",
            variable=self.media_delete_conversation_var,
        ).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(checks, text="include replies", variable=self.include_replies_var).pack(side="left")
        ttk.Checkbutton(checks, text="delete all", variable=self.delete_all_var).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(checks, text="dry run", variable=self.dry_run_var).pack(side="left", padx=(12, 0))

        for var in self._all_vars_for_tracing():
            var.trace_add("write", lambda *_: self._update_command_preview())

        preview = ttk.LabelFrame(root, text="Command Preview", padding=10)
        preview.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        preview.columnconfigure(0, weight=1)
        ttk.Entry(preview, textvariable=self.command_preview_var).grid(row=0, column=0, sticky="ew")

        logs = ttk.LabelFrame(root, text="실행 로그", padding=10)
        logs.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        logs.columnconfigure(0, weight=1)
        logs.rowconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        self.log_text = tk.Text(logs, wrap="word", height=12)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(logs, orient="vertical", command=self.log_text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=yscroll.set)

        btn_row = ttk.Frame(root)
        btn_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self.run_button = ttk.Button(btn_row, text="실행", command=self._run)
        self.run_button.pack(side="left")
        self.stop_button = ttk.Button(btn_row, text="중지", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="로그 지우기", command=self._clear_log).pack(side="left", padx=(8, 0))

    def _all_vars_for_tracing(self) -> list[tk.Variable]:
        return [
            self.max_var,
            self.timeline_pages_var,
            self.timeline_page_size_var,
            self.batch_limit_var,
            self.delay_var,
            self.timeout_var,
            self.pass_delay_var,
            self.pass_limit_var,
            self.before_var,
            self.after_var,
            self.contains_var,
            self.media_tab_var,
            self.media_delete_conversation_var,
            self.include_replies_var,
            self.delete_all_var,
            self.dry_run_var,
        ]

    def _detect_python_command(self) -> list[str]:
        if not getattr(sys, "frozen", False):
            return [sys.executable]

        candidates = [["py", "-3"], ["py"], ["python"]]
        for cand in candidates:
            try:
                probe = subprocess.run(
                    cand + ["--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3,
                )
                if probe.returncode == 0:
                    return cand
            except Exception:
                continue
        return []

    def _validate_int(self, field_name: str, raw: str) -> str:
        value = raw.strip()
        if value == "":
            raise ValueError(f"{field_name} 값을 입력하세요.")
        try:
            int(value)
        except ValueError as exc:
            raise ValueError(f"{field_name}는 정수여야 합니다: {value}") from exc
        return value

    def _validate_float(self, field_name: str, raw: str) -> str:
        value = raw.strip()
        if value == "":
            raise ValueError(f"{field_name} 값을 입력하세요.")
        try:
            float(value)
        except ValueError as exc:
            raise ValueError(f"{field_name}는 숫자여야 합니다: {value}") from exc
        return value

    def _append_optional(self, cmd: list[str], flag: str, value: str) -> None:
        text = value.strip()
        if text:
            cmd.extend([flag, text])

    def _build_command(self) -> list[str]:
        if not self.python_command:
            raise ValueError("Python 실행기를 찾지 못했습니다. Python 또는 py 런처를 설치하세요.")

        script_path = resource_path("twitdelete.py")
        if not os.path.exists(script_path):
            raise ValueError("실행 파일이 없습니다: twitdelete.py")

        cmd: list[str] = [*self.python_command, "-u", script_path]
        cmd.extend(["--auth-file", DEFAULT_AUTH_FILE])
        cmd.extend(["--auto-auth", "--browser", DEFAULT_BROWSER, "--cdp-url", DEFAULT_CDP_URL])

        cmd.extend(["--max", self._validate_int("max", self.max_var.get())])
        cmd.extend(["--timeline-pages", self._validate_int("timeline pages", self.timeline_pages_var.get())])
        cmd.extend(
            ["--timeline-page-size", self._validate_int("timeline page size", self.timeline_page_size_var.get())]
        )
        cmd.extend(["--batch-limit", self._validate_int("batch limit", self.batch_limit_var.get())])
        cmd.extend(["--delay", self._validate_float("delay", self.delay_var.get())])
        cmd.extend(["--timeout", self._validate_float("timeout", self.timeout_var.get())])
        cmd.extend(["--pass-delay", self._validate_float("pass delay", self.pass_delay_var.get())])
        cmd.extend(["--pass-limit", self._validate_int("pass limit", self.pass_limit_var.get())])

        self._append_optional(cmd, "--before", self.before_var.get())
        self._append_optional(cmd, "--after", self.after_var.get())
        self._append_optional(cmd, "--contains", self.contains_var.get())

        if self.include_replies_var.get():
            cmd.append("--include-replies")
        if self.delete_all_var.get() or self.media_tab_var.get() or self.media_delete_conversation_var.get():
            cmd.append("--delete-all")
        if self.media_tab_var.get():
            cmd.append("--media-tab")
        if self.media_delete_conversation_var.get():
            cmd.append("--media-delete-conversation")
        if self.dry_run_var.get():
            cmd.append("--dry-run")

        return cmd

    def _update_command_preview(self) -> None:
        try:
            cmd = self._build_command()
            self.command_preview_var.set(subprocess.list2cmdline(cmd))
        except Exception as exc:
            self.command_preview_var.set(f"(설정 확인 필요) {exc}")

    def _set_running_state(self, running: bool) -> None:
        self.run_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def _append_log(self, text: str) -> None:
        self._append_log_lines([text])

    def _append_log_lines(self, lines: list[str]) -> None:
        if not lines:
            return
        self.log_text.insert("end", "\n".join(lines) + "\n")
        self.log_line_count += len(lines)
        if self.log_line_count > MAX_LOG_LINES:
            over = self.log_line_count - MAX_LOG_LINES
            # Keep latest log lines to prevent Text widget memory bloat.
            self.log_text.delete("1.0", f"{over + 1}.0")
            self.log_line_count = MAX_LOG_LINES
        self.log_text.see("end")

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", "end")
        self.log_line_count = 0

    def _terminate_managed_process(self) -> None:
        proc = self.process
        if proc is None or proc.poll() is not None:
            return

        pid = proc.pid
        try:
            proc.terminate()
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        # Kill only the tree spawned by this GUI process PID.
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                proc.kill()
        except Exception:
            pass

    def _on_close_requested(self) -> None:
        if self.is_closing:
            return
        self.is_closing = True

        proc = self.process
        if proc is not None and proc.poll() is None:
            ok = messagebox.askyesno(
                "종료 확인",
                "실행 중인 작업이 있습니다.\nGUI를 닫으면 GUI가 시작한 백그라운드 작업도 함께 종료됩니다.\n종료할까요?",
            )
            if not ok:
                self.is_closing = False
                return
            self._append_log("[GUI] Closing: terminating managed process tree...")
            self._terminate_managed_process()

        self.destroy()

    def _run(self) -> None:
        if self.process and self.process.poll() is None:
            messagebox.showwarning("실행 중", "이미 실행 중입니다.")
            return

        if self.dry_run_var.get():
            ok = messagebox.askyesno(
                "DRY-RUN 모드",
                "현재 DRY-RUN이 켜져 있습니다.\n후보만 출력하고 실제 삭제는 하지 않습니다.\n계속 실행할까요?",
            )
            if not ok:
                return
        else:
            ok = messagebox.askyesno(
                "실제 삭제 모드",
                "현재 실제 삭제 모드입니다.\n게시물이 실제로 삭제됩니다.\n계속 실행할까요?",
            )
            if not ok:
                return

        try:
            cmd = self._build_command()
        except Exception as exc:
            messagebox.showerror("설정 오류", str(exc))
            return

        self._set_running_state(True)
        self._append_log("")
        self._append_log("==== RUN ====")
        if (self.media_tab_var.get() or self.media_delete_conversation_var.get()) and not self.delete_all_var.get():
            self._append_log("[INFO] media mode forces --delete-all for continuous capture/delete.")
        self._append_log(subprocess.list2cmdline(cmd))

        try:
            creationflags = 0
            startupinfo = None
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0

            self.process = subprocess.Popen(
                cmd,
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception as exc:
            self._set_running_state(False)
            messagebox.showerror("실행 실패", str(exc))
            return

        self.read_thread = threading.Thread(target=self._read_output_worker, daemon=True)
        self.read_thread.start()
        self.after(100, self._drain_log_queue)

    def _read_output_worker(self) -> None:
        proc = self.process
        if proc is None:
            self.log_queue.put(None)
            return

        try:
            if proc.stdout is not None:
                for line in proc.stdout:
                    self.log_queue.put(line.rstrip("\r\n"))
            rc = proc.wait()
            self.log_queue.put(f"[GUI] process exit code: {rc}")
        except Exception as exc:
            self.log_queue.put(f"[GUI] output read error: {exc}")
        finally:
            self.log_queue.put(None)

    def _drain_log_queue(self) -> None:
        if self.is_closing:
            return
        finished = False
        buffered: list[str] = []
        while True:
            try:
                item = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                finished = True
                break
            buffered.append(item)

        if buffered:
            self._append_log_lines(buffered)

        if finished:
            self.process = None
            self.read_thread = None
            self._set_running_state(False)
            return

        self.after(100, self._drain_log_queue)

    def _stop(self) -> None:
        proc = self.process
        if proc is None or proc.poll() is not None:
            self._set_running_state(False)
            return
        self._append_log("[GUI] terminate requested (managed process tree).")
        self._terminate_managed_process()


def main() -> int:
    app = TwitDeleteGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
