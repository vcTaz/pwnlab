"""Strategy decision tree: maps recon + probe results to an exploit strategy."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .recon import ReconResult


@dataclass
class Strategy:
    name: str
    binary: Path
    offset: int | None
    input_mode: str          # 'stdin' | 'file-raw' | 'file-size-data'
    binary_args: list[str]   # extra args after binary path (e.g. input file placeholder)
    addresses: dict[str, Any] = field(default_factory=dict)
    todos: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    libc_path: str | None = None


def _nx_off(r: ReconResult) -> bool:
    return r.security.nx == "disabled"


def _canary(r: ReconResult) -> bool:
    return r.security.canary == "present"


def _has_fmt(r: ReconResult) -> bool:
    return "printf" in r.imports or "fprintf" in r.imports or "snprintf" in r.imports


def _has_fork(r: ReconResult) -> bool:
    return "fork" in r.imports


def _has_heap(r: ReconResult) -> bool:
    return "malloc" in r.imports or "calloc" in r.imports


def _system_addr(r: ReconResult) -> int | None:
    return r.plt.get("system") or r.functions.get("system")


def _binsh_addr(r: ReconResult) -> int | None:
    return r.strings_found.get("/bin/sh")


def _input_file_placeholder(input_mode: str) -> list[str]:
    if input_mode in ("file-raw", "file-size-data"):
        return ["{INPUT_FILE}"]
    return []


def select(
    r: ReconResult,
    offset: int | None,
    input_mode: str,
    cfg: Config,
    force: str | None = None,
) -> Strategy:
    """Walk the priority list and return the first viable strategy."""
    order = cfg.strategies.order if not force else [force]
    binary_args = _input_file_placeholder(input_mode)

    for name in order:
        s = _try_strategy(name, r, offset, input_mode, binary_args, cfg)
        if s is not None:
            return s

    # Fallback: return an 'unsupported' strategy with recon notes
    return Strategy(
        name="unsupported",
        binary=r.binary,
        offset=offset,
        input_mode=input_mode,
        binary_args=binary_args,
        notes=["No automated strategy matched. Manual analysis required."],
    )


def _try_strategy(
    name: str,
    r: ReconResult,
    offset: int | None,
    input_mode: str,
    binary_args: list[str],
    cfg: Config,
) -> Strategy | None:
    base = dict(
        binary=r.binary,
        offset=offset,
        input_mode=input_mode,
        binary_args=binary_args,
        libc_path=r.libc_path,
    )

    if name == "shellcode":
        if not _nx_off(r):
            return None
        s = Strategy(name="shellcode", **base)
        s.todos.append("ESP_AT_OVERFLOW: find with GDB — x/wx $esp after crash, locate start of pattern")
        s.notes.append("NX disabled — executable stack confirmed")
        if offset is None:
            s.todos.insert(0, "OFFSET: run pwnlab with --verbose to debug GDB probe, or use --offset N")
        return s

    if name == "ret2libc":
        if _nx_off(r) or _canary(r):
            return None
        sys_addr = _system_addr(r)
        binsh_addr = _binsh_addr(r)
        s = Strategy(name="ret2libc", **base)
        if sys_addr:
            s.addresses["system"] = sys_addr
        else:
            s.todos.append("system_addr: not in PLT — need libc base (see rop strategy)")
        if binsh_addr:
            s.addresses["binsh"] = binsh_addr
        else:
            s.notes.append("/bin/sh not in binary — searching libc")
            if r.libc_path:
                s.addresses["binsh_via_libc"] = True
            else:
                s.todos.append("binsh_addr: libc not found — locate /bin/sh manually")
        if offset is None:
            s.todos.insert(0, "OFFSET: GDB probe failed — use --offset N")
        return s

    if name == "rop":
        if _canary(r):
            return None
        s = Strategy(name="rop", **base)
        s.addresses["gadgets"] = r.rop_gadgets
        if not r.rop_gadgets:
            s.notes.append("No gadgets found — ROPgadget may not be installed")
        if r.libc_path:
            s.notes.append("pwntools ROP class will chain automatically with libc")
        else:
            s.todos.append("libc_path: ldd failed — find libc manually and pass via --libc")
        if offset is None:
            s.todos.insert(0, "OFFSET: GDB probe failed — use --offset N")
        return s

    if name == "canary-fmt":
        if not _canary(r) or not _has_fmt(r):
            return None
        s = Strategy(name="canary-fmt", **base)
        s.todos.append("CANARY_FMT_POS: run the probe loop at top of generated script to find position")
        s.todos.append("OFFSET_TO_CANARY: OFFSET - 12 is a starting estimate; verify with GDB")
        sys_addr = _system_addr(r)
        if sys_addr:
            s.addresses["system"] = sys_addr
        binsh_addr = _binsh_addr(r)
        if binsh_addr:
            s.addresses["binsh"] = binsh_addr
        if offset is None:
            s.todos.insert(0, "OFFSET: GDB probe failed — use --offset N")
        return s

    if name == "canary-brute":
        if not _canary(r) or not _has_fork(r):
            return None
        s = Strategy(name="canary-brute", **base)
        s.notes.append("fork() detected — byte-by-byte canary brute force is viable")
        sys_addr = _system_addr(r)
        if sys_addr:
            s.addresses["system"] = sys_addr
        binsh_addr = _binsh_addr(r)
        if binsh_addr:
            s.addresses["binsh"] = binsh_addr
        if offset is None:
            s.todos.insert(0, "OFFSET: GDB probe failed — use --offset N")
        return s

    if name == "heap":
        if not _has_heap(r):
            return None
        s = Strategy(name="heap", **base)
        s.notes.append("malloc/free detected — generating heap analysis skeleton")
        s.todos.append("Heap exploitation requires manual GDB analysis (see generated skeleton)")
        return s

    return None
