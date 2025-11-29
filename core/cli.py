import argparse, os, uuid, datetime, pathlib, sys, json, traceback
from core.pipeline import load_pipeline
from core.pipeline import load_pipeline
from core.plugins import run_plugin
from core.parse_engine import parse_and_merge
from core.report_html import load_findings, render_html
from core.pdf import html_to_pdf
from . import aggregator


def _run_id():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]

def _mk(p: pathlib.Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def _write_metrics_empty_run(home: pathlib.Path, rid: str, reason: str) -> None:
    """
    Записать метрики для случая, когда мы решили не запускать тулзы
    (нет целей / нет alive). run_status=0, findings_total=0.
    """
    metdir = _mk(home / "metrics")
    prom = metdir / "autopen.prom"
    prom.write_text(
        "\n".join(
            [
                f'autopen_run_status{{run_id="{rid}"}} 0',
                "autopen_findings_total 0",
                "autopen_pdf_failed 0",
                "autopen_tools_errors 0",
                f'autopen_empty_reason{{run_id="{rid}"}} "{reason}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

def cmd_run(args):
    home = pathlib.Path(os.getenv("AUTOPEN_HOME", "/workspace"))
    out_root = _mk(home / "out")
    rid = _run_id()
    rid_root = _mk(out_root / rid)

    # --- lock-файл, защита от параллельных прогонов ---
    lock_path = out_root / ".run.lock"
    if lock_path.exists():
        try:
            info = lock_path.read_text(encoding="utf-8").strip()
        except Exception:
            info = ""
        print(
            f"[ERROR] run: lock file {lock_path} already exists. "
            f"Another scan may be running. Lock: {info or '<empty>'}"
        )
        sys.exit(1)

    lock_payload = {
        "run_id": rid,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "pid": os.getpid(),
    }
    try:
        lock_path.write_text(
            json.dumps(lock_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        print(f"[WARN] run: failed to write lock file {lock_path}: {e}")

    errors = []
    pdf_failed = 0

    try:
        # 00: meta
        meta = {
            "run_id": rid,
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "initiator": "cli",
        }
        _mk(rid_root / "00-meta")
        (rid_root / "00-meta" / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # [01] aggregation
        run_dir = str(rid_root)      # /workspace/out/<run_id>
        env = dict(os.environ)       # FTP_*, AUTO_DISCOVERY и т.п.
        agg_res = aggregator.aggregate(run_dir, env)

        local_cnt = agg_res.get("local", 0) or 0
        ftp_cnt = agg_res.get("ftp", 0) or 0
        autodiscovery_cnt = agg_res.get("autodiscovery", 0) or 0
        raw_all_cnt = agg_res.get("raw_all", 0) or 0
        alive = agg_res.get("alive") or []

        print(
            "[01] aggregation: "
            f"local={local_cnt} "
            f"ftp={ftp_cnt} "
            f"autodiscovery={autodiscovery_cnt} "
            f"raw_all={raw_all_cnt} "
            f"alive={len(alive)}"
        )

        # если вообще нет целей — выходим без запуска тулов
        if raw_all_cnt == 0:
            print("[01] aggregation: нет целей (raw_all=0) — тулзы не запускаем")
            _write_metrics_empty_run(home, rid, reason="no_targets")
            return

        # если есть цели, но никто не живой — тоже не запускаем тулзы
        if not alive:
            print("[01] aggregation: ни один хост не отвечает (alive=0) — тулзы не запускаем")
            _write_metrics_empty_run(home, rid, reason="no_alive")
            return

        print("[01] aggregation: ok")

        # 02: scan — читаем внешний pipeline и запускаем реальные шаги
        pipe = load_pipeline(home)
        print(
            f"[02] pipeline: steps={pipe.steps}, "
            f"concurrency={pipe.concurrency}, "
            f"continue_on_error={pipe.continue_on_error}"
        )
        scan_root = _mk(rid_root / "02-scan" / "_global")

        for i, step in enumerate(pipe.steps, 1):
            try:
                rc = run_plugin(home, rid, step)
                if rc != 0:
                    errors.append({"step": step, "error": f"exit {rc}"})
                    print(f"[02.{i:02d}] {step}: ERROR (exit {rc}) — продолжим")
                else:
                    print(f"[02.{i:02d}] {step}: ok")
            except Exception as e:
                errors.append({"step": step, "error": str(e)})
                print(f"[02.{i:02d}] {step}: ERROR -> {e} — продолжим")
                if not pipe.continue_on_error:
                    raise

        # 03: merge
        n = parse_and_merge(rid_root, home)
        print(f"[03] merge: parsed={n}")

        # 04: report (HTML + попытка PDF; PDF-fail не валит весь run)
        rep_dir = _mk(rid_root / "04-report")
        findings = load_findings(rid_root / "03-merge" / "findings_merged.ndjson")
        html_str = render_html(rid, findings)
        html_path = rep_dir / "report.html"
        html_path.write_text(html_str, encoding="utf-8")
        print("[04] report: html ok")

        pdf_path = rep_dir / "report.pdf"
        try:
            html_to_pdf(html_path, pdf_path)
            print("[04] report: pdf ok")
        except Exception as e:
            pdf_failed = 1
            print(f"[04] report: pdf WARNING -> {e} (HTML есть, продолжаем)")

        # 05: metrics (.prom) — успешный run с запуском тулов
        metdir = _mk(home / "metrics")
        prom = metdir / "autopen.prom"
        tools_err = len(errors)
        findings_total = len(findings)
        prom.write_text(
            "\n".join(
                [
                    f'autopen_run_status{{run_id="{rid}"}} 1',
                    f"autopen_findings_total {findings_total}",
                    f"autopen_pdf_failed {pdf_failed}",
                    f"autopen_tools_errors {tools_err}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        # Снимаем lock в любом случае
        try:
            if lock_path.exists():
                lock_path.unlink()
        except Exception as e:
            print(f"[WARN] run: failed to remove lock file {lock_path}: {e}")

def cmd_status(args):
    home = pathlib.Path(os.getenv("AUTOPEN_HOME", "/workspace"))
    out_dir = home / "out"
    ok = home.exists() and out_dir.exists()
    lock_path = out_dir / ".run.lock"
    lock_exists = lock_path.exists()
    print(f"AUTOPEN_HOME={home}  OUT_EXISTS={ok}  RUN_LOCK={lock_exists}")

def cmd_stop(args):
    home = pathlib.Path(os.getenv("AUTOPEN_HOME", "/workspace"))
    lock_path = home / "out" / ".run.lock"
    if lock_path.exists():
        try:
            lock_path.unlink()
            print(f"[INFO] stop: removed lock file {lock_path}")
        except Exception as e:
            print(f"[WARN] stop: failed to remove lock file {lock_path}: {e}")
    else:
        print("[INFO] stop: no lock file found (nothing to stop at CLI level).")

def main():
    p = argparse.ArgumentParser(prog="autopen")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run").set_defaults(fn=cmd_run)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("stop").set_defaults(fn=cmd_stop)
    args = p.parse_args()
    args.fn(args)
