# core/utils.py
from pathlib import Path
from typing import List, Union
import sys


def write_text(path: Union[str, Path], content: str) -> None:
    """
    Записать текст в файл:
    - гарантируем, что родительская директория существует
    - кодировка UTF-8
    """
    p = Path(path)
    if p.parent:
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content or "", encoding="utf-8")


def read_lines(path: Union[str, Path]) -> List[str]:
    """
    Прочитать файл построчно:
    - если файла нет — вернуть []
    - обрезать пробелы
    - пропускать пустые строки и строки-комментарии (начинающиеся с '#')
    """
    p = Path(path)

    if not p.exists():
        return []

    try:
        data = p.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[utils.read_lines] WARNING: can't read {p}: {e}", file=sys.stderr)
        return []

    lines: List[str] = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        lines.append(line)

    return lines
