import os, asyncio, json, pathlib, datetime, re
from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message
from aiogram.filters import Command
from collections import Counter
from aiogram.types import Message, FSInputFile


import re


BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
ALLOW = {x.strip() for x in os.getenv("TELEGRAM_ALLOW", "").split(",") if x.strip()}
HOME = pathlib.Path(os.getenv("AUTOPEN_HOME", "/workspace"))

STEP_RE = re.compile(r"^\[(\d{2}|\d{2}\.\d{2})\]")  # [01], [02.03], [03], [04]

router = Router()

def _allow(msg: Message) -> bool:
    return (not ALLOW) or (str(msg.chat.id) in ALLOW)

async def _send_lines(msg: Message, lines):
    for ln in lines:
        if STEP_RE.match(ln):
            await msg.answer(ln[:4096])
            
async def _stream_cmd(cmd: str, msg: Message):
    """
    Запускает команду и обновляет ОДНО сообщение msg текущим прогрессом.
    Показываем только строки вида [01] ..., [02.03] ..., [03] ..., [04] ...
    """
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    buf: list[str] = []

    while True:
        line = await proc.stdout.readline()
        if not line:
            break

        s = line.decode(errors="ignore").rstrip()
        if not s:
            continue

        # оставляем только красивые этапные строки
        if STEP_RE.match(s):
            buf.append(s)
            # храним только последние 15 строк, чтобы не раздувать сообщение
            buf = buf[-15:]

            text = "Прогресс скана:\n" + "\n".join(buf)
            try:
                await msg.edit_text(text)
            except Exception:
                # если вдруг Telegram ругается (лимит по длине/частоте) — просто пропускаем
                pass

    rc = await proc.wait()
    return rc, buf


def _last_report():
    p = HOME / "out"
    if not p.exists():
        return None
    runs = sorted(p.glob("*/04-report/report.html"))
    return runs[-1] if runs else None


def _norm_severity(s: str) -> str:
    if not s:
        return "unknown"
    s = str(s).strip().lower()
    if s in ("informational", "info"):
        return "info"
    return s


def _last_severity_stats():
    """
    Считает статистику по критичностям для последнего прогона:
    возвращает dict с полями total и by (словарь severity -> count),
    либо None, если не удалось прочитать данные.
    """
    try:
        # используем _last_run_info, которую мы уже добавляли
        report_path, meta = _last_run_info()
    except NameError:
        # если вдруг _last_run_info нет, fallback на _last_report
        report_path = _last_report()
        meta = None

    if not report_path:
        return None

    run_root = report_path.parents[1]  # .../out/<run_id>
    findings_file = run_root / "03-merge" / "findings_merged.ndjson"

    if not findings_file.exists():
        return None

    total = 0
    counts = Counter()

    try:
        with findings_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                total += 1
                sev = _norm_severity(obj.get("severity"))
                counts[sev] += 1
    except Exception:
        return None

    return {"total": total, "by": dict(counts)}

def _last_run_info():
    """
    Возвращает (report_path, meta_dict) для последнего прогона
    или (None, None), если отчётов нет.
    """
    r = _last_report()
    if not r:
        return None, None

    run_root = r.parents[1]  # .../out/<run_id>
    meta_path = run_root / "00-meta" / "meta.json"
    meta = None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        meta = None
    return r, meta

@router.message(Command("start"))
async def start(m: Message):
    if not _allow(m): return
    await m.answer("Привет! Команды: /run, /status, /stop, /last")

@router.message(Command("status"))
async def status(m: Message):
    if not _allow(m):
        return

    # вызываем CLI-статус внутри core-контейнера
    rc, buf = await _stream_cmd("python /app/autopen.py status", m)

    if rc != 0:
        await m.answer(f"⚠️ status завершился с кодом {rc}")
        return

    # берём последнюю непустую строку вывода
    line = ""
    for s in reversed(buf):
        if s.strip():
            line = s.strip()
            break

    if not line:
        await m.answer("Не удалось получить статус ядра (пустой вывод)")
        return

    # парсим формат вида:
    # AUTOPEN_HOME=/workspace  OUT_EXISTS=True  RUN_LOCK=False
    parts = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            parts[k] = v

    home = parts.get("AUTOPEN_HOME", "?")
    out_exists = parts.get("OUT_EXISTS")
    lock = parts.get("RUN_LOCK")

    out_txt = "ok" if out_exists == "True" else "нет /out"
    if lock == "True":
        run_txt = "идёт скан (RUN_LOCK=True)"
    elif lock == "False":
        run_txt = "нет активного скана (RUN_LOCK=False)"
    else:
        run_txt = "статус lock неизвестен"

    await m.answer(
        "Статус ядра:\n"
        f"- home: {home}\n"
        f"- out: {out_txt}\n"
        f"- скан: {run_txt}"
    )

@router.message(Command("last"))
async def last(m: Message):
    if not _allow(m):
        return

    report_html, meta = _last_run_info()
    if not report_html:
        await m.answer("Нет отчётов")
        return

    run_root = report_html.parents[1]  # .../out/<run_id>
    rid = run_root.name
    ts = meta.get("ts") if isinstance(meta, dict) else None

    text = f"Последний отчёт:\n{report_html}\nrun_id: {rid}"
    if ts:
        text += f"\nЗапуск: {ts}"

    await m.answer(text)

    # Пытаемся отправить HTML и PDF как файлы
    html_path = report_html
    pdf_path = run_root / "04-report" / "report.pdf"

    if html_path.exists():
        try:
            await m.answer_document(
                FSInputFile(str(html_path)),
                caption="HTML-отчёт (последний скан)"
            )
        except Exception as e:
            await m.answer(f"⚠️ Не удалось отправить HTML-отчёт: {e}")

    if pdf_path.exists():
        try:
            await m.answer_document(
                FSInputFile(str(pdf_path)),
                caption="PDF-отчёт (последний скан)"
            )
        except Exception as e:
            await m.answer(f"⚠️ Не удалось отправить PDF-отчёт: {e}")

@router.message(Command("run"))
async def run(m: Message):
    if not _allow(m):
        return

    # одно сообщение, которое будем обновлять
    log_msg = await m.answer("Старт скана…")

    # стримим вывод CLI в это сообщение
    rc, _ = await _stream_cmd("python /app/autopen.py run", log_msg)

    # достаём последний отчёт и мета-инфу
    r, meta = _last_run_info()
    stats = _last_severity_stats()

    # базовый текст итога
    if rc == 0:
        text = "✅ Скан завершён\n"
    else:
        text = f"⚠️ Скан завершён с кодом {rc}\n"

    if r:
        text += f"\nПоследний HTML: {r}"

    # добавляем краткую сводку по критичностям, если смогли посчитать
    if stats:
        total = stats.get("total", 0)
        by = stats.get("by") or {}

        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        parts = []
        for name in sev_order:
            cnt = by.get(name, 0)
            if cnt:
                parts.append(f"{name}: {cnt}")
        sev_line = ", ".join(parts) if parts else "нет данных по критичностям"

        text += (
            f"\n\n📊 Итоги последнего прогона:\n"
            f"- всего находок: {total}\n"
            f"- по критичности: {sev_line}"
        )

    text += "\n\nЧтобы скачать отчёт, используйте /last"

    # заменяем прогресс на финальный текст
    try:
        await log_msg.edit_text(text)
    except Exception:
        # если вдруг сообщение слишком длинное — отправим новым
        await m.answer(text)


@router.message(Command("stop"))
async def stop(m: Message):
    if not _allow(m): return
    await m.answer("Экстренная остановка…")
    rc, _ = await _stream_cmd("python /app/autopen.py stop", m)
    await m.answer("🛑 Остановлено и очищено" if rc==0 else f"⚠️ Код {rc}")

async def main():
    dp = Dispatcher()
    dp.include_router(router)
    bot = Bot(BOT_TOKEN)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
