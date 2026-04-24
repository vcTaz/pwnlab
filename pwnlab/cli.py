"""CLI entry point for pwnlab."""
from __future__ import annotations

import argparse
import cmd
import subprocess
import sys
from pathlib import Path

from . import __version__
from . import config as cfg_mod
from . import generate, probe, recon, solve as solve_mod, strategy


# ─────────────────────────────────────────────────────────── colour helpers ──

def _tty() -> bool:
    return sys.stdout.isatty()


def _c(text: str, *codes: str) -> str:
    if not _tty():
        return text
    return "\033[" + ";".join(codes) + "m" + text + "\033[0m"


def bold(t: str)   -> str: return _c(t, "1")
def dim(t: str)    -> str: return _c(t, "2")
def cyan(t: str)   -> str: return _c(t, "36")
def green(t: str)  -> str: return _c(t, "32")
def yellow(t: str) -> str: return _c(t, "33")
def red(t: str)    -> str: return _c(t, "31")


# ──────────────────────────────────────────────────────────── helpers ────────

def _save_local_config(cfg: cfg_mod.Config) -> None:
    """Write current config to .pwnlab.toml in cwd."""
    path = Path.cwd() / cfg_mod.LOCAL_CONFIG_NAME
    lines = [
        "[target]",
        f'arch    = "{cfg.target.arch}"',
        f'wrapper = "{cfg.target.wrapper}"',
        "",
        "[env]",
    ]
    for k, v in cfg.env.items():
        lines.append(f'{k} = "{v}"')
    lines += [
        "",
        "[probe]",
        f"pattern_length = {cfg.probe.pattern_length}",
        f"gdb_timeout    = {cfg.probe.gdb_timeout}",
        f"rop_timeout    = {cfg.probe.rop_timeout}",
        "",
        "[output]",
        f'dir     = "{cfg.output.dir}"',
        f"verbose = {str(cfg.output.verbose).lower()}",
    ]
    path.write_text("\n".join(lines) + "\n")
    print(f"  {green('✓')} Saved: {bold(str(path))}")
    print(f"  {dim('This file overrides ~/.config/pwnlab/config.toml for this directory.')}")


def _banner(cfg: cfg_mod.Config) -> str:
    W = 54
    sep = "─" * W
    rows = [
        bold(f"  pwnlab {__version__}") + "  —  binary exploitation assistant",
        dim(f"  {sep}"),
        f"  {bold('Quick start')}",
        f"  {cyan(f'load <binary>'):<38}  load a target binary",
        f"  {cyan('auto'):<38}  full pipeline: recon → probe → exploit",
        f"  {cyan('help [<cmd>]'):<38}  list all commands / detailed help",
        f"  {dim(sep)}",
        f"  {bold('Active settings')}  {dim('(change with  set  or  config save)')}",
        f"  {'arch':<12}{cyan(cfg.target.arch)}",
        f"  {'wrapper':<12}{cyan(cfg.target.wrapper) if cfg.target.wrapper else dim('(none)')}",
    ]
    for k, v in cfg.env.items():
        rows.append(f"  {'env ' + k:<12}{cyan(v)}")
    rows += [
        f"  {dim(sep)}",
        f"  {dim('set wrapper  /  set env  /  set arch')} to change settings",
        f"  {dim('gdb')} to print matching GDB commands",
        "",
    ]
    return "\n".join(rows)


# ─────────────────────────────────────────────────────────────── REPL ───────

class _PwnLabRepl(cmd.Cmd):
    intro = ""  # printed by cmdloop(); we use our own banner in cmdloop override
    doc_header = bold("Commands") + "  (type  help <cmd>  for details):"

    def __init__(self, cfg: cfg_mod.Config) -> None:
        super().__init__()
        self.cfg = cfg
        self.binary: Path | None = None
        self.r = None
        self.offset: int | None = None
        self.input_mode: str | None = None
        self.strat = None
        self.out_path: Path | None = None
        self._skip_rop = False
        self._force_strategy: str | None = None
        self._addr_override: int | None = None
        self._esp_at_crash: int = 0

    @property
    def prompt(self) -> str:
        label = f"({self.binary.name}) " if self.binary else ""
        if _tty():
            return bold(cyan("pwnlab")) + dim(f" {label}") + "> "
        return f"pwnlab {label}> "

    def _ok(self, thing: object, msg: str) -> bool:
        if thing is None:
            print(f"  {yellow('!')} {msg}")
            return False
        return True

    def cmdloop(self, intro: object = None) -> None:
        print(_banner(self.cfg))
        super().cmdloop(intro="")

    # ── load ──────────────────────────────────────────────────────────────────

    def do_load(self, line: str) -> None:
        """load <path>
Load a binary for analysis.  Resets all session state.

  Example:  load ./bin.0
            load /path/to/challenge"""
        path = line.strip().strip("'\"")
        if not path:
            print(f"  {yellow('Usage:')} load <path>")
            return
        b = Path(path).expanduser().resolve()
        if not b.exists():
            print(f"  {red('Error:')} not found: {b}")
            return
        self.binary = b
        self.r = self.offset = self.input_mode = self.strat = self.out_path = None
        self._esp_at_crash = 0
        print(f"  {green('✓')} Loaded: {bold(self.binary.name)}")

    # ── recon ─────────────────────────────────────────────────────────────────

    def do_recon(self, line: str) -> None:
        """recon [--no-rop]
Static analysis: security flags, PLT functions, strings, ROP gadgets.

  --no-rop   skip ROPgadget scan (faster for large binaries)"""
        if not self._ok(self.binary, "Load a binary first:  load <path>"):
            return
        self._skip_rop = "--no-rop" in line
        print("  Running recon…")
        self.r = recon.run(self.binary, self.cfg, skip_rop=self._skip_rop)
        print(recon.summarize(self.r))

    # ── probe ─────────────────────────────────────────────────────────────────

    def do_probe(self, line: str) -> None:
        """probe [--input-mode <mode>] [--verbose]
Detect how the binary reads input, then find the EIP/RIP offset
by crashing it with a cyclic pattern under GDB.

  --input-mode <mode>   force instead of auto-detect
                        choices: stdin  file-raw  file-size-data
  --verbose             print every GDB probe attempt

  Requires: recon  (run first)

  Example:  probe
            probe --input-mode file-size-data
            probe --verbose"""
        if not self._ok(self.binary, "Load a binary first"):
            return
        if not self._ok(self.r, "Run recon first:  recon"):
            return
        parts = line.split()
        forced_mode = None
        if "--input-mode" in parts:
            idx = parts.index("--input-mode")
            if idx + 1 < len(parts):
                forced_mode = parts[idx + 1]
        verbose = "--verbose" in parts
        if forced_mode:
            self.input_mode = forced_mode
            print(f"  Input mode: {cyan(self.input_mode)} (forced)")
        else:
            print("  Detecting input mode…")
            self.input_mode = probe.detect_input_mode(
                self.binary, self.cfg, strings_found=self.r.strings_found
            )
            print(f"  Input mode: {cyan(self.input_mode)}")
            if self.input_mode == "unknown":
                self.input_mode = "stdin"
                print(f"  {yellow('WARNING:')} unknown — defaulted to stdin")
        print("  Probing for EIP offset via GDB…")
        pr = probe.find_offset(self.binary, self.input_mode, self.cfg, verbose=verbose)
        if pr is not None:
            self.offset = pr.offset
            self._esp_at_crash = pr.esp_at_crash
            print(
                f"  {green('✓')} Offset: {bold(str(self.offset))}"
                f"  (ESP at crash: {cyan(hex(pr.esp_at_crash))})"
            )
        else:
            self.offset = None
            print(f"  {red('✗')} Probe failed — set manually:  set offset <N>")

    # ── set ───────────────────────────────────────────────────────────────────

    def do_set(self, line: str) -> None:
        """set <key> <value>
Override session values and config settings.

  ── exploit parameters ──────────────────────────────────────
  set offset   <N>          EIP/RIP offset (bytes)
  set addr     <0xHEX>      buffer address (shellcode path)
  set strategy <name>       force a strategy:
                              shellcode  ret2libc  rop
                              canary-fmt  canary-brute  heap
  set input-mode <mode>     force input mode:
                              stdin  file-raw  file-size-data

  ── runtime config ──────────────────────────────────────────
  set arch     <i386|x86_64>
  set wrapper  <cmd>        exec-wrapper  (e.g. setarch i686 -R -3)
                            use empty string to clear:  set wrapper
  set env      KEY=VALUE    add / update an environment variable
  set env      KEY          remove an environment variable

  Changes apply for this session only.
  Run  config save  to persist to .pwnlab.toml.

  Examples:
    set offset 56
    set arch i386
    set wrapper setarch i686 -R -3
    set env TEMP=1000
    set env LD_PRELOAD=/lib32/libfoo.so
    set env TEMP                          (removes TEMP)
    set wrapper                           (no wrapper / bare execution)"""
        parts = line.split(None, 1)
        if not parts:
            print(self.do_set.__doc__)
            return
        key = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if key == "offset":
            try:
                self.offset = int(rest)
                print(f"  offset = {bold(str(self.offset))}")
            except ValueError:
                print(f"  {red('Error:')} expected integer, got {rest!r}")

        elif key == "addr":
            try:
                self._addr_override = int(rest, 16)
                print(f"  addr (ESP_AT_OVERFLOW) = {cyan(hex(self._addr_override))}")
            except ValueError:
                print(f"  {red('Error:')} expected hex value like 0xbfffe2e4, got {rest!r}")

        elif key == "strategy":
            valid = {"shellcode", "ret2libc", "rop", "canary-fmt", "canary-brute", "heap"}
            if rest not in valid:
                print(f"  {red('Error:')} unknown strategy {rest!r}")
                print(f"  Valid choices: {', '.join(sorted(valid))}")
                return
            self._force_strategy = rest
            print(f"  strategy = {bold(rest)}")

        elif key == "input-mode":
            valid = {"stdin", "file-raw", "file-size-data"}
            if rest not in valid:
                print(f"  {red('Error:')} unknown mode {rest!r}")
                print(f"  Valid choices: {', '.join(sorted(valid))}")
                return
            self.input_mode = rest
            print(f"  input_mode = {bold(rest)}")

        elif key == "arch":
            aliases = {"i686": "i386", "x86": "i386", "amd64": "x86_64", "x64": "x86_64"}
            rest = aliases.get(rest, rest)
            valid = {"i386", "x86_64"}
            if rest not in valid:
                print(f"  {red('Error:')} unknown arch {rest!r}  (i386 / i686 or x86_64 / amd64)")
                return
            self.cfg.target.arch = rest
            print(f"  arch = {bold(rest)}")

        elif key == "wrapper":
            self.cfg.target.wrapper = rest
            if rest:
                print(f"  wrapper = {bold(rest)}")
            else:
                print(f"  wrapper = {dim('(none — binary will run without a wrapper)')}")

        elif key == "env":
            if "=" in rest:
                k, _, v = rest.partition("=")
                self.cfg.env[k.strip()] = v
                print(f"  env[{bold(k.strip())}] = {v!r}")
            else:
                k = rest.strip()
                if not k:
                    print(f"  {yellow('Usage:')} set env KEY=VALUE   or   set env KEY (to remove)")
                    return
                removed = self.cfg.env.pop(k, None)
                if removed is not None:
                    print(f"  env[{bold(k)}] removed  (was {removed!r})")
                else:
                    print(f"  {yellow('!')} env[{k}] was not set")

        else:
            print(f"  {yellow('!')} Unknown key: {key!r}  (type  help set  for all options)")

    # ── config ────────────────────────────────────────────────────────────────

    def do_config(self, line: str) -> None:
        """config [save]
Show or save the current effective configuration.

  config        print all active settings
  config save   write settings to .pwnlab.toml in the current directory

  Config files (lower overrides higher):
    ~/.config/pwnlab/config.toml   global defaults
    .pwnlab.toml                   per-directory overrides

  Run  pwnlab config init  to create the global config.
  Run  pwnlab config show  to inspect the merged config without entering the REPL.

  Tip: use  set wrapper / set env / set arch  to change settings for
       this session, then  config save  to persist them."""
        if line.strip().lower() == "save":
            _save_local_config(self.cfg)
            return
        # ── show ──
        sep = dim("─" * 42)
        print(f"\n  {bold('── target')}  {sep}")
        print(f"  {'arch':<16}{cyan(self.cfg.target.arch)}")
        w = self.cfg.target.wrapper
        print(f"  {'wrapper':<16}{cyan(w) if w else dim('(none)')}")
        print(f"\n  {bold('── env')}  {sep}")
        if self.cfg.env:
            for k, v in self.cfg.env.items():
                print(f"  {k:<16}{cyan(v)}")
        else:
            print(f"  {dim('(empty)')}")
        print(f"\n  {bold('── probe')}  {sep}")
        print(f"  {'pattern_length':<16}{self.cfg.probe.pattern_length}")
        print(f"  {'gdb_timeout':<16}{self.cfg.probe.gdb_timeout}s")
        print(f"  {'rop_timeout':<16}{self.cfg.probe.rop_timeout}s")
        print(f"\n  {bold('── output')}  {sep}")
        print(f"  {'dir':<16}{self.cfg.output.dir}")
        print(f"  {'verbose':<16}{self.cfg.output.verbose}")
        print(f"\n  {dim('Files:')}")
        print(f"  {dim('  global:')} {cfg_mod.GLOBAL_CONFIG_PATH}")
        print(f"  {dim('  local: ')} {Path.cwd() / cfg_mod.LOCAL_CONFIG_NAME}")
        print()

    # ── gdb ───────────────────────────────────────────────────────────────────

    def do_gdb(self, line: str) -> None:
        """gdb
Print GDB commands that match the current pwnlab environment.

Paste these into GDB (or a .gdbinit file) so the GDB probe uses the
same wrapper and environment variables that the exploit uses at runtime.

Why this matters: GDB adds its own environment variables which shift
the stack layout, causing libc and stack addresses to differ from the
real run.  Setting the same env and exec-wrapper makes GDB's addresses
match the exploit's addresses.

  Example:
    (gdb) set environment TEMP 1000
    (gdb) set exec-wrapper setarch i686 -R -3
    (gdb) set disable-randomization on
    (gdb) run <input_file>"""
        sep = dim("─" * 50)
        print(f"\n  {bold('── GDB commands')}  {sep}")
        print(f"  {dim('# Paste into GDB or add to .gdbinit:')}")
        print()
        # Unset GDB's default extra env vars so stack matches runtime
        print(f"  {dim('# Strip GDB-added env vars (makes stack layout match runtime):')}")
        for var in ("LINES", "COLUMNS"):
            print(f"  unset environment {var}")
        print()
        print(f"  {dim('# Set the same env vars as pwnlab:')}")
        for k, v in self.cfg.env.items():
            print(f"  set environment {k} {v}")
        w = self.cfg.target.wrapper.strip()
        if w:
            print()
            print(f"  {dim('# Run the binary through the same wrapper:')}")
            print(f"  set exec-wrapper {w}")
        print()
        print(f"  {dim('# Disable ASLR (same effect as setarch -R):')}")
        print(f"  set disable-randomization on")
        print()
        # One-liner
        print(f"  {bold('── One-liner to start GDB with all settings ──')}")
        env_flags  = " ".join(f"-ex 'set environment {k} {v}'" for k, v in self.cfg.env.items())
        unset_flags = "-ex 'unset environment LINES' -ex 'unset environment COLUMNS'"
        wrap_flag  = f"-ex 'set exec-wrapper {w}'" if w else ""
        rand_flag  = "-ex 'set disable-randomization on'"
        run_flag   = "-ex 'run <input_file>'"
        bname      = str(self.binary) if self.binary else "<binary>"
        flags      = " ".join(f for f in [unset_flags, env_flags, wrap_flag, rand_flag, run_flag] if f)
        print(f"  gdb {flags} {bname}")
        print()

    # ── strategy ──────────────────────────────────────────────────────────────

    def do_strategy(self, line: str) -> None:
        """strategy
Select the best exploit strategy based on security flags and offset.
Run  recon  and  probe  first.

  Strategies:
    shellcode    NX disabled — inject shellcode, jump to buffer
    ret2libc     NX enabled — redirect execution to system()
    rop          NX enabled — chain gadgets to call execve or system
    canary-fmt   stack canary present + format-string leak
    canary-brute stack canary, fork() binary — byte-by-byte brute
    heap         heap overflow / use-after-free

  Override:  set strategy <name>"""
        if not self._ok(self.r, "Run recon first:  recon"):
            return
        self.strat = strategy.select(
            self.r,
            self.offset,
            self.input_mode or "stdin",
            self.cfg,
            force=self._force_strategy,
        )
        print(f"  {green('✓')} Strategy: {bold(self.strat.name)}")
        for n in self.strat.notes:
            print(f"    {dim('→')} {n}")
        if self.strat.addresses:
            for k, v in self.strat.addresses.items():
                if isinstance(v, int):
                    print(f"    {k+':':<28} {cyan(hex(v))}")
        if self.strat.todos:
            print(f"  {yellow('TODOs:')}")
            for t in self.strat.todos:
                print(f"    {yellow('▸')} {t}")

    # ── exploit ───────────────────────────────────────────────────────────────

    def do_exploit(self, line: str) -> None:
        """exploit [<out.py>] [--dry-run]
Generate a ready-to-run Python exploit script.

  exploit              write exploit_<binary>.py
  exploit out.py       write to a specific file
  exploit --dry-run    show payload layout without writing

  After generating, run the exploit with:  run"""
        if not self._ok(self.r, "Run recon first:  recon"):
            return
        if self.strat is None:
            self.do_strategy("")
            if self.strat is None:
                return
        if self._addr_override is not None and self.strat.name == "shellcode":
            self.strat.addresses["esp_at_overflow"] = self._addr_override
        dry = "--dry-run" in line
        if dry:
            print(f"  Strategy:   {bold(self.strat.name)}")
            print(f"  Offset:     {self.strat.offset}")
            print(f"  Input mode: {self.strat.input_mode}")
            for k, v in self.strat.addresses.items():
                print(f"  {k+':':<28} {cyan(hex(v)) if isinstance(v, int) else v}")
            return
        parts = [p for p in line.split() if p != "--dry-run"]
        out = (
            Path(parts[0])
            if parts
            else Path(self.cfg.output.dir) / f"exploit_{self.binary.name}.py"  # type: ignore[union-attr]
        )
        generate.render(self.strat, self.cfg, out)
        self.out_path = out
        print(f"  {green('✓')} Written: {bold(str(out))}")
        if self.strat.todos:
            print(f"  {yellow('TODOs before running:')}")
            for t in self.strat.todos:
                print(f"    {yellow('▸')} {t}")

    # ── auto ──────────────────────────────────────────────────────────────────

    def do_auto(self, line: str) -> None:
        """auto [--verbose]
Full automatic pipeline:
  recon → detect input mode → find offset → select strategy → solve → generate exploit

  --verbose    show detailed output at every stage

  Workflow:
    load ./bin.0
    auto
    run"""
        if not self._ok(self.binary, "Load a binary first:  load <path>"):
            return
        verbose = "--verbose" in line
        print(f"\n{bold('[auto]')} {cyan(self.binary.name)}")
        print("─" * 50)

        print(f"{bold('[1/5]')} Recon …")
        self.r = recon.run(self.binary, self.cfg, skip_rop=self._skip_rop)
        sec = self.r.security
        print(f"      NX={sec.nx}  Canary={sec.canary}  PIE={sec.pie}")

        print(f"{bold('[2/5]')} Input mode …")
        self.input_mode = probe.detect_input_mode(
            self.binary, self.cfg, strings_found=self.r.strings_found
        )
        if self.input_mode == "unknown":
            self.input_mode = "stdin"
            print(f"      {yellow('WARNING:')} could not determine — defaulted to stdin")
            print(f"      {dim('(override with: set input-mode file-size-data)')}")
        else:
            print(f"      {cyan(self.input_mode)}")

        print(f"{bold('[3/5]')} Offset probe (GDB) …")
        if self.r.security.canary == "present" and self.offset is None:
            # GDB cyclic probe always triggers the canary check (SIGABRT) before
            # returning — skip it entirely.  For canary strategies the solve phase
            # probes OFFSET_TO_CANARY and OFFSET using its own canary-aware method.
            print(f"      {cyan('─')} skipped (canary-protected; offset resolved during solve)")
        else:
            pr = probe.find_offset(self.binary, self.input_mode, self.cfg, verbose=verbose)
            if pr is not None:
                self.offset, self._esp_at_crash = pr.offset, pr.esp_at_crash
                print(
                    f"      {green('✓')} offset={bold(str(self.offset))}"
                    f"  esp_at_crash={cyan(hex(self._esp_at_crash))}"
                )
            else:
                if self.offset is not None:
                    print(f"      {yellow('!')} probe failed — keeping manually set offset={bold(str(self.offset))}")
                else:
                    print(f"      {red('✗')} probe failed — set manually:  set offset <N>")

        print(f"{bold('[4/5]')} Strategy …")
        self.strat = strategy.select(
            self.r, self.offset, self.input_mode, self.cfg, force=self._force_strategy
        )
        print(f"      {bold(self.strat.name)}")

        print(f"{bold('[5/5]')} Solving …")
        res = solve_mod.solve(self.strat, self.r, self.cfg, verbose=verbose)
        solve_mod.display(res)
        if "esp_at_overflow" in res.addresses:
            self.strat.addresses["esp_at_overflow"] = res.addresses["esp_at_overflow"]
            self._addr_override = res.addresses["esp_at_overflow"]

        out = Path(self.cfg.output.dir) / f"exploit_{self.binary.name}.py"
        generate.render(self.strat, self.cfg, out)
        self.out_path = out
        print(f"\n  {green('✓')} Exploit written: {bold(str(out))}")
        print(f"  Run with: {bold('run')}\n")

    # ── solve ─────────────────────────────────────────────────────────────────

    def do_solve(self, line: str) -> None:
        """solve [--verbose]
Actively probe the binary to find concrete exploit values.

  shellcode    → scan stack for the buffer start address
  ret2libc     → resolve system() and /bin/sh addresses
  rop          → build ROP chain from available gadgets
  canary-fmt   → probe format string positions for canary leak

  --verbose    print every probe attempt

  Requires: strategy (run first, or it runs automatically)"""
        if not self._ok(self.r, "Run recon first:  recon"):
            return
        if self.strat is None:
            self.do_strategy("")
            if self.strat is None:
                return
        verbose = "--verbose" in line
        print(f"  Solving {bold(self.strat.name)}…")
        res = solve_mod.solve(
            self.strat, self.r, self.cfg, verbose=verbose, esp_at_crash=self._esp_at_crash
        )
        solve_mod.display(res)
        if "esp_at_overflow" in res.addresses:
            self.strat.addresses["esp_at_overflow"] = res.addresses["esp_at_overflow"]
            self._addr_override = res.addresses["esp_at_overflow"]
        if res.canary is not None:
            self.strat.addresses["canary"] = res.canary
            self.strat.addresses["canary_pos"] = res.canary_pos  # type: ignore[assignment]

    # ── run ───────────────────────────────────────────────────────────────────

    def do_run(self, line: str) -> None:
        """run [<script.py>]
Execute the generated exploit.

  run              run the last generated exploit script
  run exploit.py   run a specific script"""
        path = line.strip() or (str(self.out_path) if self.out_path else "")
        if not path:
            print(f"  {yellow('!')} Generate exploit first:  exploit")
            return
        subprocess.run([sys.executable, path])

    # ── status ────────────────────────────────────────────────────────────────

    def do_status(self, line: str) -> None:
        """status
Show the current session state and active config."""
        W = 16

        def row(label: str, value: str) -> None:
            print(f"  {dim(f'{label:<{W}}')} {value}")

        print(f"\n  {bold('── Session ──────────────────────────────────────')}")
        row("binary",     str(self.binary) if self.binary else dim("(none)"))
        row("recon",      green("done") if self.r else dim("(not run)"))
        row("input_mode", cyan(self.input_mode) if self.input_mode else dim("(not set)"))
        row("offset",
            bold(str(self.offset)) if self.offset is not None else dim("(not found)"))
        if self._addr_override is not None:
            row("addr",   cyan(hex(self._addr_override)))
        if self._esp_at_crash:
            row("esp@crash", cyan(hex(self._esp_at_crash)))
        strat_name = (
            (self._force_strategy + " (forced)") if self._force_strategy
            else (self.strat.name if self.strat else None)
        )
        row("strategy",  bold(strat_name) if strat_name else dim("(not selected)"))
        row("exploit",   str(self.out_path) if self.out_path else dim("(not generated)"))

        print(f"\n  {bold('── Config ───────────────────────────────────────')}")
        row("arch",    cyan(self.cfg.target.arch))
        row("wrapper", cyan(self.cfg.target.wrapper) if self.cfg.target.wrapper else dim("(none)"))
        for k, v in self.cfg.env.items():
            row(f"env[{k}]", cyan(v))
        if not self.cfg.env:
            row("env", dim("(empty)"))

        print(f"\n  {dim('Commands:  set wrapper  /  set env  /  set arch  /  config save')}\n")

    # ── quit ──────────────────────────────────────────────────────────────────

    def do_quit(self, line: str) -> bool:  # type: ignore[override]
        """quit   Exit pwnlab"""
        return True

    do_exit = do_quit  # type: ignore[assignment]

    def do_EOF(self, line: str) -> bool:  # type: ignore[override]
        print()
        return True

    def default(self, line: str) -> None:
        cmd_name = line.split()[0] if line.split() else ""
        print(
            f"  {yellow('?')} Unknown command: {bold(cmd_name)}"
            f"  (type {bold('help')} for a list)"
        )


# ─────────────────────────────────────────────────────── one-shot parser ────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwnlab",
        description="Binary exploitation assistant — auto-analyze ELF binaries",
        epilog=(
            "one-shot examples:\n"
            "  pwnlab ./bin.0                        auto-analyze, generate exploit\n"
            "  pwnlab ./bin.0 --offset 44            skip GDB probe\n"
            "  pwnlab ./bin.0 --wrapper ''           run without setarch\n"
            "  pwnlab ./bin.0 --env TEMP=1000        set env variable\n"
            "  pwnlab ./bin.0 --solve                also probe for concrete addresses\n"
            "  pwnlab ./bin.0 --dry-run              show strategy without writing file\n"
            "\nconfig commands:\n"
            "  pwnlab config init                    write default config to ~/.config/pwnlab/\n"
            "  pwnlab config show                    show merged effective config\n"
            "\ninteractive REPL:\n"
            "  pwnlab                                enter interactive mode\n"
            "  pwnlab> load ./bin.0\n"
            "  pwnlab> set wrapper setarch i686 -R -3\n"
            "  pwnlab> set env TEMP=1000\n"
            "  pwnlab> auto\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"pwnlab {__version__}")

    p.add_argument("binary", nargs="?", type=str,
                   help="Target ELF binary path (or 'config')")
    p.add_argument("--arch",       default=None,
                   help="Target architecture  (i386 | x86_64)")
    p.add_argument("--wrapper",    default=None,
                   help='Exec wrapper  (e.g. "setarch i686 -R -3", or "" to disable)')
    p.add_argument("--env",        action="append", metavar="KEY=VAL",
                   help="Set environment variable (repeatable, e.g. --env TEMP=1000)")
    p.add_argument("--input-mode", default=None,
                   choices=["auto", "stdin", "file-raw", "file-size-data"],
                   help="Force input mode (default: auto-detect)")
    p.add_argument("--offset",     type=int, default=None,
                   help="Known EIP offset — skip GDB probe")
    p.add_argument("--strategy",   default=None,
                   choices=["auto", "shellcode", "ret2libc", "rop",
                             "canary-fmt", "canary-brute", "heap"],
                   help="Force exploit strategy")
    p.add_argument("--libc",       default=None, metavar="PATH",
                   help="Path to libc ELF (if auto-detection fails)")
    p.add_argument("--output",     type=Path, default=None,
                   help="Output exploit script path")
    p.add_argument("--timeout",    type=int, default=None,
                   help="GDB probe timeout (seconds)")
    p.add_argument("--no-rop",     action="store_true",
                   help="Skip ROPgadget scan")
    p.add_argument("--verbose",    action="store_true",
                   help="Detailed output")
    p.add_argument("--dry-run",    action="store_true",
                   help="Show strategy and payload layout without writing exploit")
    p.add_argument("--solve",      action="store_true",
                   help="Probe binary for concrete values (address scan, canary, gadgets)")
    p.add_argument("config_command", nargs="?", choices=["init", "show"],
                   help=argparse.SUPPRESS)
    return p


def _parse_env_args(env_args: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in (env_args or []):
        if "=" in item:
            k, _, v = item.partition("=")
            result[k] = v
    return result


def _cli_overrides(args: argparse.Namespace) -> dict:
    overrides: dict = {}
    if args.arch:
        _arch_aliases = {"i686": "i386", "x86": "i386", "amd64": "x86_64", "x64": "x86_64"}
        overrides.setdefault("target", {})["arch"] = _arch_aliases.get(args.arch, args.arch)
    if args.wrapper is not None:
        overrides.setdefault("target", {})["wrapper"] = args.wrapper
    extra_env = _parse_env_args(args.env)
    if extra_env:
        overrides["env"] = extra_env
    if args.timeout:
        overrides.setdefault("probe", {})["gdb_timeout"] = args.timeout
    if args.verbose:
        overrides.setdefault("output", {})["verbose"] = True
    return overrides


# ─────────────────────────────────────────────────────────────── main ───────

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ── config subcommand ────────────────────────────────────────────────────
    if args.binary == "config":
        if args.config_command == "init":
            path = cfg_mod.init_global()
            print(f"Config written: {path}")
            return 0
        elif args.config_command == "show":
            cfg = cfg_mod.load()
            print(cfg_mod.show(cfg))
            print(f"\nGlobal: {cfg_mod.GLOBAL_CONFIG_PATH}")
            print(f"Local:  {Path.cwd() / cfg_mod.LOCAL_CONFIG_NAME}")
            return 0
        else:
            print("Usage: pwnlab config [init|show]")
            return 1

    # ── interactive REPL when no binary given ────────────────────────────────
    if args.binary is None:
        cfg = cfg_mod.load(_cli_overrides(args))
        repl = _PwnLabRepl(cfg)
        try:
            repl.cmdloop()
        except KeyboardInterrupt:
            print()
        return 0

    binary = Path(args.binary).resolve()
    if not binary.exists():
        print(f"error: {binary} does not exist", file=sys.stderr)
        return 1

    cfg = cfg_mod.load(_cli_overrides(args))
    verbose = cfg.output.verbose

    out_path = args.output or (Path(cfg.output.dir) / f"exploit_{binary.name}.py")

    print(f"\n[pwnlab {__version__}] {binary.name}")
    print("─" * 50)

    # Phase 1: Recon
    print("[1/4] Static recon ...")
    r = recon.run(binary, cfg, skip_rop=args.no_rop)
    if args.libc:
        r.libc_path = args.libc
    if verbose:
        print(recon.summarize(r))
    else:
        sec = r.security
        print(f"      PIE={sec.pie}  NX={sec.nx}  Canary={sec.canary}  RELRO={sec.relro}")
        if r.libc_path:
            print(f"      libc: {r.libc_path}")
        if r.plt.get("system"):
            print(f"      system@plt: {hex(r.plt['system'])}")
        if r.strings_found.get("/bin/sh"):
            print(f"      /bin/sh: {hex(r.strings_found['/bin/sh'])}")
        if r.rop_gadgets:
            print(f"      gadgets: {', '.join(r.rop_gadgets.keys())}")

    # Phase 2: Input mode
    forced_mode = args.input_mode if args.input_mode and args.input_mode != "auto" else None
    if forced_mode:
        input_mode = forced_mode
        print(f"[2/4] Input mode: {input_mode} (forced)")
    else:
        print("[2/4] Detecting input mode ...")
        input_mode = probe.detect_input_mode(binary, cfg, strings_found=r.strings_found)
        print(f"      Detected: {input_mode}")
        if input_mode == "unknown":
            print("      WARNING: could not determine — defaulting to stdin")
            print("      Use --input-mode to override")
            input_mode = "stdin"

    # Phase 3: Offset
    esp_at_crash = 0
    if args.offset is not None:
        offset = args.offset
        print(f"[3/4] Offset: {offset} (provided)")
    else:
        print("[3/4] Probing for offset ...")
        pr = probe.find_offset(binary, input_mode, cfg, verbose=verbose)
        if pr is not None:
            offset = pr.offset
            esp_at_crash = pr.esp_at_crash
            print(f"      Found: {offset} bytes  (esp_at_crash={hex(esp_at_crash)})")
        else:
            offset = None
            print("      Probe failed — offset will be marked TODO in exploit")
            print("      Tip: use --verbose or --offset N to skip")

    # Phase 4: Strategy
    force_strategy = None if (not args.strategy or args.strategy == "auto") else args.strategy
    print("[4/4] Selecting strategy ...")
    strat = strategy.select(r, offset, input_mode, cfg, force=force_strategy)
    print(f"      Strategy: {strat.name}")
    for n in strat.notes:
        print(f"      ✓ {n}")

    # Solve phase
    if args.solve:
        print("[5/5] Solving — probing binary for addresses / gadgets / canary ...")
        res = solve_mod.solve(strat, r, cfg, verbose=verbose, esp_at_crash=esp_at_crash)
        solve_mod.display(res)
        if "esp_at_overflow" in res.addresses:
            strat.addresses["esp_at_overflow"] = res.addresses["esp_at_overflow"]

    # Dry run
    if args.dry_run:
        print("\n── Dry run ──────────────────────────────────────────────────")
        print(f"  Strategy:   {strat.name}")
        print(f"  Offset:     {strat.offset}")
        print(f"  Input mode: {strat.input_mode}")
        for k, v in strat.addresses.items():
            print(f"  {k}: {hex(v) if isinstance(v, int) else v}")
        if strat.todos:
            print("  TODOs:")
            for t in strat.todos:
                print(f"    - {t}")
        print("─" * 60)
        return 0

    # Generate exploit
    generate.render(strat, cfg, out_path)
    print(f"\n  Exploit written: {out_path}")
    if strat.todos:
        print("\n  TODOs before running:")
        for t in strat.todos:
            print(f"    ▸ {t}")
    print(f"\n  Run with:  python3 {out_path.name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
