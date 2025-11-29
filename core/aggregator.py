# core/aggregator.py
import os
import sys
import ipaddress
import socket
import subprocess
from pathlib import Path
from typing import Dict, List

import yaml

from .utils import write_text, read_lines
from . import discovery


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def expand_targets(lines: List[str]) -> List[str]:
    """
    Принимает строки с целями:
      - IP: 1.2.3.4
      - CIDR: 10.0.0.0/24
      - диапазоны: 10.0.0.1-10.0.0.10 или 10.0.0.1-10
      - URL/hostname: https://example.com, example.com, 1.1.1.1:443
    Возвращает нормализованный список IP/host, каждый один раз.
    """
    out: List[str] = []

    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue

        # отрежем схему и путь
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0]

        # отрежем порт, если есть
        if ":" in s:
            s = s.split(":", 1)[0]

        # диапазон IP: A.B.C.D-E или A.B.C.D-E.F.G.H
        if "-" in s:
            left, right = s.split("-", 1)
            try:
                start = ipaddress.ip_address(left)
                if "." in right:
                    end = ipaddress.ip_address(right)
                else:
                    # если правая часть только последний октет
                    base = left.split(".")
                    if len(base) != 4:
                        raise ValueError()
                    end = ipaddress.ip_address(".".join(base[:3] + [right]))
                if int(start) <= int(end):
                    cur = start
                    while int(cur) <= int(end):
                        out.append(str(cur))
                        cur = ipaddress.ip_address(int(cur) + 1)
                    continue
            except ValueError:
                # не смогли понять как диапазон — пойдём дальше
                pass

        # CIDR
        try:
            net = ipaddress.ip_network(s, strict=False)
            for ip in net.hosts():
                out.append(str(ip))
            continue
        except ValueError:
            pass

        # одно IP?
        try:
            ip = ipaddress.ip_address(s)
            out.append(str(ip))
            continue
        except ValueError:
            # не IP — считаем, что это hostname
            out.append(s)

    return _dedupe_preserve_order(out)


def fping_alive(hosts: List[str]) -> List[str]:
    """
    Прогоняем список через fping, возвращаем только живые (по ICMP).
    Если fping не доступен — простой TCP connect к 80/tcp.
    """
    if not hosts:
        return []

    try:
        proc = subprocess.run(
            ["bash", "-lc", "fping -a -q -f /dev/stdin 2>/dev/null"],
            input=("\n".join(hosts)).encode(),
            capture_output=True,
            check=False,
        )
        alive = proc.stdout.decode().splitlines()
        return _dedupe_preserve_order([x.strip() for x in alive if x.strip()])
    except Exception:
        alive: List[str] = []
        for h in hosts:
            try:
                with socket.create_connection((h, 80), timeout=1):
                    alive.append(h)
            except Exception:
                pass
        return _dedupe_preserve_order(alive)


def _load_ftp_cfg_from_yaml(project_root: Path) -> Dict[str, str] | None:
    cfg_path = project_root / "config" / "ftp.yaml"
    if not cfg_path.exists():
        return None
    try:
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
    except Exception as e:
        print(f"[01] aggregation: WARNING: failed to parse ftp.yaml: {e}", file=sys.stderr)
        return None

    host = cfg.get("host") or cfg.get("server")
    if not host:
        return None

    return {
        "host": host,
        "user": cfg.get("user") or cfg.get("username") or "anonymous",
        "password": cfg.get("password") or cfg.get("pass") or "anonymous@",
        "path": cfg.get("path") or "/targets.txt",
        "protocol": cfg.get("protocol") or cfg.get("scheme") or "ftp",
    }


def load_ftp_targets(project_root: Path, agg_dir: Path, env: Dict[str, str]) -> List[str]:
    """
    1) Пытаемся прочитать config/ftp.yaml
    2) Если нет — смотрим переменные окружения FTP_HOST/FTP_USER/FTP_PASS/FTP_PATH
    3) Если и там ничего — возвращаем пустой список
    """
    cfg = _load_ftp_cfg_from_yaml(project_root)

    if cfg is None:
        host = env.get("FTP_HOST") or ""
        if not host:
            return []
        cfg = {
            "host": host,
            "user": env.get("FTP_USER") or "anonymous",
            "password": env.get("FTP_PASS") or "anonymous@",
            "path": env.get("FTP_PATH") or "/targets.txt",
            "protocol": env.get("FTP_PROTO") or "ftp",
        }

    url = f"{cfg['protocol']}://{cfg['user']}:{cfg['password']}@{cfg['host']}{cfg['path']}"
    out_file = agg_dir / "raw_ftp.txt"
    cmd = f'curl -m 15 --silent --show-error "{url}" -o "{out_file}" || true'
    subprocess.run(["bash", "-lc", cmd], check=False)

    return read_lines(out_file)


def aggregate(run_dir: str, env: Dict[str, str]) -> Dict[str, object]:
    """
    Главный вход: собираем цели из FTP, локального файла, TG-файла, autodiscovery.
    run_dir: /workspace/out/<run_id>
    """
    run_path = Path(run_dir)
    project_root = run_path.parents[1]  # /workspace
    agg_dir = run_path / "01-aggregated"
    agg_dir.mkdir(parents=True, exist_ok=True)

    # --- 1. Источники целевых хостов ---
    ftp_lines = load_ftp_targets(project_root, agg_dir, env)

    tg_file = project_root / "data" / "incoming" / "targets_tg.txt"
    tg_lines = read_lines(str(tg_file))

    local_file = project_root / "config" / "targets.txt"
    local_lines = read_lines(str(local_file))

    auto_nets: List[str] = discovery.routes_cidr() if env.get("AUTO_DISCOVERY", "1") == "1" else []

    # --- 2. Объединяем «сырой» список ---
    raw_all = sorted(set(ftp_lines + tg_lines + local_lines + auto_nets))

    # сохраняем сырые источники
    write_text(str(agg_dir / "raw_tg.txt"), "\n".join(tg_lines))
    write_text(str(agg_dir / "raw_local.txt"), "\n".join(local_lines))
    write_text(str(agg_dir / "raw_all.txt"), "\n".join(raw_all))
    write_text(str(agg_dir / "raw_autodiscovery.txt"), "\n".join(auto_nets))

    # --- 3. Если совсем пусто — просто создаём пустые файлы и выходим ---
    if not raw_all:
        write_text(str(agg_dir / "expanded.txt"), "")
        write_text(str(agg_dir / "alive.txt"), "")
        return {
            "ftp": len(ftp_lines),
            "tg": len(tg_lines),
            "local": len(local_lines),
            "autodiscovery": len(auto_nets),
            "raw_all": 0,
            "expanded": [],
            "alive": [],
        }

    # --- 4. Расширение (диапазоны/CIDR -> отдельные IP/host) ---
    expanded = expand_targets(raw_all)
    write_text(str(agg_dir / "expanded.txt"), "\n".join(expanded))

    # --- 5. Живые хосты через fping/TCP ---
    alive = fping_alive(expanded)

    write_text(str(agg_dir / "alive.txt"), "\n".join(alive))

    return {
        "ftp": len(ftp_lines),
        "tg": len(tg_lines),
        "local": len(local_lines),
        "autodiscovery": len(auto_nets),
        "raw_all": len(raw_all),
        "expanded": expanded,
        "alive": alive,
    }
