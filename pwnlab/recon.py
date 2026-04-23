"""Static binary analysis: security flags, imports, addresses, gadgets."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config


RISKY_IMPORTS = frozenset([
    "gets", "strcpy", "strncpy", "strcat", "sprintf", "vsprintf",
    "scanf", "fscanf", "sscanf", "read", "recv", "memcpy", "memmove",
    "printf", "fprintf", "snprintf", "malloc", "calloc", "realloc",
    "free", "fork", "system", "execve", "popen",
])

INTERESTING_STRINGS = ("size", "record", "render", "menu", "hidden",
                        "debug", "/bin/sh", "usage", "root", "flag")


@dataclass
class SecurityInfo:
    pie: str = "EXEC"
    nx: str = "enabled"
    stack: str = "non-executable"
    relro: str = "none"
    canary: str = "absent"


@dataclass
class ReconResult:
    binary: Path
    arch: str = "i386"
    file_info: str = ""
    security: SecurityInfo = field(default_factory=SecurityInfo)
    imports: list[str] = field(default_factory=list)
    functions: dict[str, int] = field(default_factory=dict)
    got: dict[str, int] = field(default_factory=dict)
    plt: dict[str, int] = field(default_factory=dict)
    strings_found: dict[str, int] = field(default_factory=dict)
    rop_gadgets: dict[str, int] = field(default_factory=dict)
    libc_path: str | None = None
    candidate_functions: list[str] = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _security(binary: Path) -> SecurityInfo:
    info = SecurityInfo()
    headers = _run(["readelf", "-W", "-l", str(binary)])
    dynamic = _run(["readelf", "-W", "-d", str(binary)])
    symbols = _run(["readelf", "-W", "-s", str(binary)])

    if "Elf file type is DYN" in headers:
        info.pie = "PIE"

    stack_line = next((l for l in headers.splitlines() if "GNU_STACK" in l), "")
    if "RWE" in stack_line:
        info.nx = "disabled"
        info.stack = "executable"
    elif "RW " in stack_line or stack_line.rstrip().endswith("RW"):
        info.nx = "enabled"
        info.stack = "non-executable"

    if "BIND_NOW" in dynamic:
        info.relro = "full"
    elif "GNU_RELRO" in headers:
        info.relro = "partial"

    if "__stack_chk_fail" in symbols:
        info.canary = "present"

    return info


def _imports(binary: Path) -> list[str]:
    out = _run(["objdump", "-T", str(binary)])
    found: set[str] = set()
    for line in out.splitlines():
        for sym in RISKY_IMPORTS:
            if re.search(rf"\b{re.escape(sym)}(@|$)", line):
                found.add(sym)
    return sorted(found)


def _functions(binary: Path) -> dict[str, int]:
    out = _run(["nm", "-n", str(binary)])
    result: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in {"T", "t"}:
            try:
                result[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    return result


def _strings_search(binary: Path) -> dict[str, int]:
    out = _run(["strings", "-a", "-t", "x", "-n", "4", str(binary)])
    found: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        text = parts[1]
        if "/bin/sh" in text:
            found["/bin/sh"] = addr
        for tok in INTERESTING_STRINGS:
            if tok in text.lower() and tok not in found:
                found[tok] = addr
    return found


def _pwntools_addresses(binary: Path, arch: str) -> tuple[dict, dict, dict]:
    """Return (got, plt, extra_symbols) using pwntools ELF."""
    try:
        from pwn import ELF, context  # type: ignore
        context.log_level = "error"
        context.arch = arch
        elf = ELF(str(binary), checksec=False)
        extra: dict[str, int] = {}
        for name, addr in elf.symbols.items():
            if addr and name not in ("", "_start"):
                extra[name] = addr
        return dict(elf.got), dict(elf.plt), extra
    except Exception:
        return {}, {}, {}


def _libc(binary: Path) -> str | None:
    out = _run(["ldd", str(binary)])
    m = re.search(r"libc(?:\.so\.[0-9]+|-[0-9.]+\.so)\s*=>\s*(\S+)", out)
    return m.group(1) if m else None


def _rop_gadgets(binary: Path, timeout: int = 20) -> dict[str, int]:
    searches = {
        "ret":               r"(0x[0-9a-f]+) : ret$",
        "pop_eax_ret":       r"(0x[0-9a-f]+) : pop eax ; ret",
        "pop_ebx_ret":       r"(0x[0-9a-f]+) : pop ebx ; ret",
        "pop_ecx_ebx_ret":   r"(0x[0-9a-f]+) : pop ecx ; pop ebx ; ret",
        "pop_edx_ecx_ebx":   r"(0x[0-9a-f]+) : pop edx ; pop ecx ; pop ebx ; ret",
        "int80":             r"(0x[0-9a-f]+) : int 0x80",
        "leave_ret":         r"(0x[0-9a-f]+) : leave ; ret",
        "pop_rdi_ret":       r"(0x[0-9a-f]+) : pop rdi ; ret",
        "pop_rsi_r15_ret":   r"(0x[0-9a-f]+) : pop rsi ; pop r15 ; ret",
        "syscall":           r"(0x[0-9a-f]+) : syscall",
    }
    gadgets: dict[str, int] = {}
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", str(binary), "--rop"],
            capture_output=True, text=True, timeout=timeout,
        )
        for name, pattern in searches.items():
            m = re.search(pattern, result.stdout, re.MULTILINE)
            if m:
                gadgets[name] = int(m.group(1), 16)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    return gadgets


def run(binary: Path, cfg: Config, skip_rop: bool = False) -> ReconResult:
    result = ReconResult(binary=binary)

    result.file_info = _run(["file", str(binary)]).strip()
    result.arch = cfg.target.arch
    result.security = _security(binary)
    result.imports = _imports(binary)
    result.functions = _functions(binary)
    result.strings_found = _strings_search(binary)
    result.libc_path = _libc(binary)

    got, plt, extra = _pwntools_addresses(binary, cfg.target.arch)
    result.got = got
    result.plt = plt
    for name, addr in extra.items():
        if name not in result.functions:
            result.functions[name] = addr

    if not skip_rop:
        result.rop_gadgets = _rop_gadgets(binary, timeout=cfg.probe.rop_timeout)

    # Find /bin/sh via pwntools search (more reliable than strings)
    if "/bin/sh" not in result.strings_found:
        try:
            from pwn import ELF, context  # type: ignore
            context.log_level = "error"
            context.arch = cfg.target.arch
            elf = ELF(str(binary), checksec=False)
            for needle in (b"/bin/sh\x00", b"/bin/sh"):
                try:
                    result.strings_found["/bin/sh"] = next(elf.search(needle))
                    break
                except StopIteration:
                    pass
        except Exception:
            pass

    # Candidate functions (have bulk copy or format string)
    disasm = _run(["objdump", "-d", "-Mintel", str(binary)])
    for func, addr in result.functions.items():
        block_start = disasm.find(f"<{func}>:")
        if block_start == -1:
            continue
        block = disasm[block_start:block_start + 2000]
        if any(t in block for t in ("memcpy", "memmove", "strcpy", "gets", "scanf", "fscanf")):
            result.candidate_functions.append(func)

    return result


def summarize(r: ReconResult) -> str:
    lines = [
        f"Binary:   {r.binary.name}",
        f"Arch:     {r.arch}",
        f"PIE:      {r.security.pie}",
        f"NX:       {r.security.nx}",
        f"Canary:   {r.security.canary}",
        f"RELRO:    {r.security.relro}",
        f"libc:     {r.libc_path or 'not found'}",
        f"Imports:  {', '.join(r.imports) or 'none'}",
    ]
    if r.candidate_functions:
        lines.append(f"Vuln candidates: {', '.join(r.candidate_functions)}")
    if r.strings_found.get("/bin/sh"):
        lines.append(f"/bin/sh:  {hex(r.strings_found['/bin/sh'])}")
    if r.plt.get("system"):
        lines.append(f"system@plt: {hex(r.plt['system'])}")
    if r.rop_gadgets:
        lines.append(f"ROP gadgets: {', '.join(r.rop_gadgets.keys())}")
    return "\n".join(lines)
