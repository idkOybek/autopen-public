import pathlib, yaml, subprocess, shlex

def load_plugin(home: pathlib.Path, name: str) -> dict:
    p = home / "plugins.d" / f"{name}.yaml"
    if not p.exists():
        raise FileNotFoundError(f"plugin yaml not found: {p}")
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}

def render_cmd(tpl: str, ctx: dict) -> str:
    # простая подстановка {{var}}
    cmd = tpl
    for k, v in ctx.items():
        cmd = cmd.replace(f"{{{{{k}}}}}", str(v))
    return cmd

def run_plugin(home: pathlib.Path, run_id: str, name: str) -> int:
    meta = load_plugin(home, name)
    image = meta.get("image", "")
    cmd_tpl = meta.get("cmd", "")
    if not cmd_tpl:
        raise ValueError(f"{name}: empty cmd")
    ctx = {
        "image": image,
        "run_id": run_id,
    }
    cmd = render_cmd(cmd_tpl, ctx)
    # Выполним как shell-команду (нам нужно пайплайны/редиректы, docker run и т.п.)
    proc = subprocess.run(cmd, shell=True)
    return proc.returncode
