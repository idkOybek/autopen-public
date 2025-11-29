import os, json, glob, datetime, pathlib
import yaml, jmespath
from lxml import etree as ET

def _sub_literals(s: str, ctx: dict) -> str:
    out = s
    for k, v in ctx.items():
        out = out.replace(f"{{{{{k}}}}}", str(v))
    return out

def _eval_jmes(expr, record, ctx):
    if isinstance(expr, str) and len(expr) >= 2 and expr[0] == expr[-1] == "'":
        return _sub_literals(expr[1:-1], ctx)
    try:
        return jmespath.search(expr, record)
    except Exception:
        return None

def _eval_xpath(expr, elem, ctx):
    if isinstance(expr, str) and len(expr) >= 2 and expr[0] == expr[-1] == "'":
        return _sub_literals(expr[1:-1], ctx)
    try:
        val = elem.xpath(expr)
    except Exception:
        return None
    # lxml возвращает list или scalar
    if isinstance(val, list):
        if not val:
            return None
        v0 = val[0]
        if hasattr(v0, "text") and not isinstance(v0, (str, bytes)):
            return v0.text
        return v0
    return val

def _ensure_soft_schema(obj: dict, ctx: dict) -> dict:
    obj.setdefault("run_id", ctx["run_id"])
    obj.setdefault("ts", datetime.datetime.utcnow().isoformat() + "Z")

    if not obj.get("asset"):
        for k in ("url", "host", "ip", "domain"):
            if obj.get(k):
                obj["asset"] = obj[k]
                break

    if not obj.get("summary"):
        title = obj.get("title") or obj.get("service") or obj.get("status")
        obj["summary"] = str(title or "finding")

    missing = [k for k in ("asset", "summary") if not obj.get(k)]
    obj["partial"] = bool(missing)

    if "severity" not in obj:
        obj["severity"] = "unknown"

    return obj

def _emit(obj, ctx, out_records):
    obj = _ensure_soft_schema(obj, ctx)
    if not obj.get("tool") or not obj.get("asset") or not obj.get("summary"):
        return
    out_records.append(obj)

def parse_and_merge(run_root: pathlib.Path, home: pathlib.Path) -> int:
    out_records = []
    parsers = sorted(glob.glob(str(home / "parsers.d" / "*.yaml")))
    ctx_global = {"run_id": run_root.name}

    for p in parsers:
        meta = yaml.safe_load(open(p, "rb")) or {}
        ptype = meta.get("type")
        if ptype == "ndjson":
            glob_pat = meta.get("glob", "")
            rec_expr = meta.get("record_jmes", "@")
            fields = meta.get("fields", {})
            for path in glob.glob(str(run_root / glob_pat)):
                try:
                    fh = open(path, "r", encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                with fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                        except Exception:
                            continue
                        base = jmespath.search(rec_expr, raw)
                        items = base if isinstance(base, list) else [base]
                        for itm in items:
                            if itm is None:
                                continue
                            obj = {}
                            for k, expr in fields.items():
                                obj[k] = _eval_jmes(expr, itm, ctx_global)
                            _emit(obj, ctx_global, out_records)

        elif ptype == "xml":
            glob_pat = meta.get("glob", "")
            rx = meta.get("record_xpath", "")
            fields = meta.get("fields", {})
            for path in glob.glob(str(run_root / glob_pat)):
                try:
                    tree = ET.parse(path)
                    root = tree.getroot()
                except Exception:
                    continue
                for elem in root.xpath(rx):
                    obj = {}
                    for k, expr in fields.items():
                        obj[k] = _eval_xpath(expr, elem, ctx_global)
                    _emit(obj, ctx_global, out_records)
        else:
            continue

    merge_dir = run_root / "03-merge"
    merge_dir.mkdir(parents=True, exist_ok=True)
    out_file = merge_dir / "findings_merged.ndjson"
    with open(out_file, "w", encoding="utf-8") as fw:
        for r in out_records:
            fw.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(out_records)
