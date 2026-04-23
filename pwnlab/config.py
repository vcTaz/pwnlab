"""Config loading, merging, and persistence using stdlib tomllib."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GLOBAL_CONFIG_PATH = Path.home() / ".config" / "pwnlab" / "config.toml"
LOCAL_CONFIG_NAME = ".pwnlab.toml"

DEFAULT_TOML = """\
[target]
arch    = "i386"
wrapper = "setarch i686 -R -3"

[env]
TEMP = "1000"

[probe]
pattern_length = 500
gdb_timeout    = 15
rop_timeout    = 20

[output]
dir     = "."
verbose = false

[strategies]
order = ["shellcode", "ret2libc", "rop", "canary-fmt", "canary-brute", "heap"]
"""


@dataclass
class TargetConfig:
    arch: str = "i386"
    wrapper: str = "setarch i686 -R -3"


@dataclass
class ProbeConfig:
    pattern_length: int = 500
    gdb_timeout: int = 15
    rop_timeout: int = 20


@dataclass
class OutputConfig:
    dir: str = "."
    verbose: bool = False


@dataclass
class StrategiesConfig:
    order: list[str] = field(default_factory=lambda: [
        "shellcode", "ret2libc", "rop", "canary-fmt", "canary-brute", "heap"
    ])


@dataclass
class Config:
    target: TargetConfig = field(default_factory=TargetConfig)
    env: dict[str, str] = field(default_factory=lambda: {"TEMP": "1000"})
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    strategies: StrategiesConfig = field(default_factory=StrategiesConfig)

    def wrapper_parts(self) -> list[str]:
        return self.target.wrapper.split() if self.target.wrapper.strip() else []

    def eip_register(self) -> str:
        return "$rip" if self.target.arch == "x86_64" else "$eip"

    def ptr_size(self) -> int:
        return 8 if self.target.arch == "x86_64" else 4


def _parse_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _merge(result[k], v)
        else:
            result[k] = v
    return result


def _dict_to_config(d: dict) -> Config:
    t = d.get("target", {})
    p = d.get("probe", {})
    o = d.get("output", {})
    s = d.get("strategies", {})
    return Config(
        target=TargetConfig(
            arch=t.get("arch", "i386"),
            wrapper=t.get("wrapper", "setarch i686 -R -3"),
        ),
        env=d.get("env", {"TEMP": "1000"}),
        probe=ProbeConfig(
            pattern_length=p.get("pattern_length", 500),
            gdb_timeout=p.get("gdb_timeout", 15),
            rop_timeout=p.get("rop_timeout", 20),
        ),
        output=OutputConfig(
            dir=o.get("dir", "."),
            verbose=o.get("verbose", False),
        ),
        strategies=StrategiesConfig(
            order=s.get("order", ["shellcode", "ret2libc", "rop",
                                   "canary-fmt", "canary-brute", "heap"]),
        ),
    )


def load(cli_overrides: dict | None = None) -> Config:
    """Load global config, merge local override, then apply CLI overrides."""
    base = _parse_toml(GLOBAL_CONFIG_PATH)
    local = _parse_toml(Path.cwd() / LOCAL_CONFIG_NAME)
    merged = _merge(base, local)
    if cli_overrides:
        merged = _merge(merged, cli_overrides)
    if not merged:
        return Config()
    return _dict_to_config(merged)


def init_global() -> Path:
    """Write the default config file if it doesn't already exist."""
    GLOBAL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not GLOBAL_CONFIG_PATH.exists():
        GLOBAL_CONFIG_PATH.write_text(DEFAULT_TOML)
        return GLOBAL_CONFIG_PATH
    return GLOBAL_CONFIG_PATH


def show(cfg: Config) -> str:
    lines = [
        "[target]",
        f'  arch    = "{cfg.target.arch}"',
        f'  wrapper = "{cfg.target.wrapper}"',
        "",
        "[env]",
    ]
    for k, v in cfg.env.items():
        lines.append(f'  {k} = "{v}"')
    lines += [
        "",
        "[probe]",
        f"  pattern_length = {cfg.probe.pattern_length}",
        f"  gdb_timeout    = {cfg.probe.gdb_timeout}",
        f"  rop_timeout    = {cfg.probe.rop_timeout}",
        "",
        "[output]",
        f'  dir     = "{cfg.output.dir}"',
        f"  verbose = {str(cfg.output.verbose).lower()}",
        "",
        "[strategies]",
        f"  order = {cfg.strategies.order}",
    ]
    return "\n".join(lines)
