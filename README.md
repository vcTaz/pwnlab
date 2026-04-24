# pwnlab

Interactive CLI for automated binary exploitation analysis on i386 ELF binaries.

Given a binary, `pwnlab` automatically:
- Detects security mitigations (NX, canary, PIE, RELRO)
- Finds the EIP overflow offset via GDB
- Selects the right exploit strategy (shellcode / ret2libc / ROP / canary)
- Scans runtime memory for embedded RWX gadgets
- Generates a ready-to-run Python exploit script

## Install

**System dependencies** (Debian/Ubuntu):
```bash
sudo apt install gdb python3-pip

# For 32-bit binaries on a 64-bit system:
sudo apt install gcc-multilib libc6-i386 lib32stdc++6
```

**Python package:**
```bash
git clone https://github.com/tsazeides/pwnlab
cd pwnlab
pip install -e .
```

Requires Python 3.11+. Installs `pwntools` and `ROPgadget` automatically.

## Quick start

```
pwnlab                    # interactive REPL
pwnlab ./bin              # one-shot: analyse and generate exploit
pwnlab ./bin --dry-run    # show strategy without writing file
```

### REPL workflow

```
pwnlab> load ./bin.0
pwnlab> auto              # full pipeline in one command
pwnlab> run               # execute the generated exploit
```

### One-shot with options

```bash
pwnlab ./bin --offset 56 --wrapper "setarch i686 -R -3" --env TEMP=1000
```

## Commands

| Command | Description |
|---|---|
| `load <path>` | Load a target binary |
| `auto` | Full pipeline: recon → probe → solve → generate |
| `recon` | Static analysis (NX, canary, PIE, PLT, strings, gadgets) |
| `probe` | Find EIP offset via GDB cyclic pattern |
| `strategy` | Select exploit strategy |
| `solve` | Probe binary for concrete addresses / gadgets |
| `exploit` | Generate exploit script |
| `run` | Execute the generated exploit |
| `set <key> <value>` | Change settings (see below) |
| `gdb` | Print matching GDB commands |
| `config` | Show / save current config |
| `status` | Show session state |

### `set` options

```
set offset   56
set arch     i386          # or i686, x86_64, amd64
set wrapper  setarch i686 -R -3
set env      TEMP=1000
set env      TEMP          # removes the variable
set wrapper                # clears wrapper (bare execution)
set strategy shellcode     # force a strategy
```

### Strategies

| Strategy | When |
|---|---|
| `shellcode` | NX disabled — inject execve shellcode |
| `ret2libc` | NX enabled, system() in PLT |
| `rop-rwx` | NX enabled, binary maps its own RWX gadget page |
| `rop` | NX enabled, build chain from binary gadgets |
| `canary-fmt` | Stack canary + format-string leak |
| `canary-brute` | Stack canary + fork() binary |

## Config

Settings are loaded in this order (last wins):

1. Built-in defaults (`wrapper = setarch i686 -R -3`, `env TEMP=1000`)
2. `~/.config/pwnlab/config.toml` — global overrides
3. `.pwnlab.toml` in the current directory — per-lab overrides

Save the current session settings to `.pwnlab.toml`:

```
pwnlab> config save
```

Generate the global config file:

```bash
pwnlab config init
pwnlab config show
```

## Troubleshooting

### `ModuleNotFoundError: No module named '_curses'`

pwntools requires the `_curses` C extension. This extension is compiled into
Python when Python is built — if the ncurses development headers were not
installed beforehand, the module is silently skipped.

**Fix A — if you have sudo (or the headers are already installed):**

```bash
# 1. Install ncurses development headers
sudo apt install libncurses5-dev libncursesw5-dev

# 2. Recompile your Python version (replace 3.11.9 with your version)
pyenv install --force 3.11.9
```

**Fix B — no sudo on a university/shared machine:**

Check whether the system Python already has curses support:

```bash
python3 -c "import curses; print('OK')"
```

If that prints `OK`, use the system Python instead of your pyenv one:

```bash
# Install pwntools for the system Python
pip3 install --user pwntools

# Run exploits with the system Python
python3 exploit_bin.0.py
```

If `python3` also fails the check, ask your sysadmin to install
`libncurses5-dev` and either recompile Python or install pwntools system-wide.

## GDB integration

The `gdb` command prints commands to paste into GDB so its environment
matches pwnlab's (same wrapper, env vars, no LINES/COLUMNS):

```
pwnlab> gdb
  unset environment LINES
  unset environment COLUMNS
  set environment TEMP 1000
  set exec-wrapper setarch i686 -R -3
  set disable-randomization on
```

Also prints a ready-to-run one-liner.
