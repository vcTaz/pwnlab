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

First check whether the system Python already has curses support:

```bash
python3 -c "import curses; print('OK')"
```

If that prints `OK`, install pwntools and pwnlab under the system Python.
Use `pip3` (not `pip` — `pip` may point to your broken pyenv):

```bash
pip3 install --user pwntools
cd /path/to/pwnlab
pip3 install --user -e .

# Make sure ~/.local/bin is in your PATH
export PATH="$HOME/.local/bin:$PATH"
```

Now `pwnlab` runs under system Python, so both the tool and the `run`
command inside it work correctly.

**Fix C — system Python also lacks curses (use Miniconda):**

Miniconda ships pre-built Python binaries that always include `_curses`.
No sudo required — it installs entirely under your home directory.

```bash
# 1. Download the installer (run from your working directory)
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh

# 2. Install silently into ~/miniconda3
bash Miniconda3-latest-Linux-x86_64.sh -b -p ~/miniconda3

# 3. Add conda to PATH for this session
export PATH="$HOME/miniconda3/bin:$PATH"

# 4. Initialise conda so 'conda activate' works in future shells
conda init
source ~/.bashrc

# 5. Create a dedicated environment
conda create -n pwn python=3.11 -y
conda activate pwn

# 6. Install pwntools and pwnlab
pip install pwntools
cd /path/to/pwnlab
pip install -e .
```

After the one-time setup, all future sessions only need:

```bash
conda activate pwn
```

> **Common pitfalls**
> - Run `bash Miniconda3-...sh` from the directory where it was downloaded,
>   not from `~/` unless you moved it there first.
> - `conda activate` requires `conda init` + a shell reload (`source ~/.bashrc`)
>   before it works — doing them in the same shell without sourcing won't help.
> - `export PATH=...` only lasts for the current terminal session; after
>   `conda init` + `source ~/.bashrc` you no longer need the manual export.

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
