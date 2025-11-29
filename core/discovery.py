# core/discovery.py
import subprocess
import ipaddress


def routes_cidr() -> list[str]:
    """
    Берём линк-сети из `ip -o route` (Linux), исключаем default/loopback.
    Возвращаем список строк вида '10.0.0.0/24'.
    """
    cmd = r"ip -o route | awk '$1 !~ /^(default|unreachable)$/ && $3 == \"link\" {print $1}'"
    p = subprocess.run(
        ["bash", "-lc", cmd],
        capture_output=True,
        text=True,
        check=False,
    )
    nets: list[str] = []
    for line in p.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            ipaddress.ip_network(s, strict=False)  # валидация
            nets.append(s)
        except ValueError:
            # вдруг какая-то странная строка в ip route
            continue
    # убираем дубли, сортируем
    return sorted(set(nets))
