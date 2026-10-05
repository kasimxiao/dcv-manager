"""企业功能数据层：权限模板、实例绑定、批量任务、巡检结果、全局审计查询。

与 db.py 共用同一 SQLite 文件与连接工具。
"""
import json
import time

from db import _conn, _lock
from templates_builtin import BUILTIN_TEMPLATES


def init():
    with _conn() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS perm_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,              -- 内置模板的稳定键；自定义模板为空
                name TEXT NOT NULL,
                description TEXT,
                level TEXT,
                spec_json TEXT NOT NULL,
                builtin INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at REAL NOT NULL,
                updated_by TEXT
            );
            -- 实例当前绑定的模板与版本；spec 仍保存在 permissions 表（实际下发内容）
            CREATE TABLE IF NOT EXISTS instance_template (
                instance_id TEXT PRIMARY KEY,
                template_id INTEGER,          -- NULL 表示自定义（非模板）
                template_version INTEGER,
                applied_at REAL,
                applied_by TEXT
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,           -- power / apply_template / inspect / launch
                title TEXT NOT NULL,
                params_json TEXT,
                status TEXT NOT NULL,         -- running / success / partial / failed
                total INTEGER NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                finished_at REAL,
                operator TEXT
            );
            CREATE TABLE IF NOT EXISTS job_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                instance_id TEXT NOT NULL,
                name TEXT,
                status TEXT NOT NULL,         -- pending / running / success / failed / skipped
                message TEXT,
                started_at REAL,
                finished_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_job_items ON job_items(job_id);
            CREATE TABLE IF NOT EXISTS inspections (
                instance_id TEXT PRIMARY KEY,
                checked_at REAL NOT NULL,
                data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                bucket TEXT NOT NULL,
                prefix TEXT NOT NULL DEFAULT '',
                region TEXT NOT NULL,
                drive TEXT NOT NULL,             -- 盘符，如 S
                mode TEXT NOT NULL,              -- ro / rw
                scope TEXT NOT NULL,             -- all 全部服务器 / selected 指定服务器
                cache_gb INTEGER NOT NULL DEFAULT 20,
                kms_key TEXT,
                policy_arn TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                updated_by TEXT
            );
            CREATE TABLE IF NOT EXISTS share_targets (
                share_id INTEGER NOT NULL,
                instance_id TEXT NOT NULL,
                added_at REAL NOT NULL,
                added_by TEXT,
                PRIMARY KEY (share_id, instance_id)
            );
            """
        )
    seed_builtin_templates()


# ---------------- 共享盘 ----------------

_SHARE_FIELDS = ("name", "bucket", "prefix", "region", "drive", "mode", "scope", "cache_gb", "kms_key", "policy_arn")


def create_share(operator, **f):
    now = time.time()
    with _lock, _conn() as con:
        cur = con.execute(
            f"INSERT INTO shares({','.join(_SHARE_FIELDS)},created_at,updated_at,updated_by) VALUES({','.join('?' * len(_SHARE_FIELDS))},?,?,?)",
            [f.get(k) for k in _SHARE_FIELDS] + [now, now, operator])
        return cur.lastrowid


def update_share(sid, operator, **f):
    sets = [k for k in _SHARE_FIELDS if k in f]
    if not sets:
        return
    with _lock, _conn() as con:
        con.execute(f"UPDATE shares SET {','.join(k + '=?' for k in sets)}, updated_at=?, updated_by=? WHERE id=?",
                    [f[k] for k in sets] + [time.time(), operator, sid])


def get_share(sid):
    with _conn() as con:
        r = con.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
        return dict(r) if r else None


def list_shares():
    with _conn() as con:
        shares = [dict(r) for r in con.execute("SELECT * FROM shares ORDER BY id").fetchall()]
        tg = {}
        for r in con.execute("SELECT share_id, instance_id FROM share_targets").fetchall():
            tg.setdefault(r[0], []).append(r[1])
    for s in shares:
        s["target_ids"] = sorted(tg.get(s["id"], []))
    return shares


def delete_share(sid):
    with _lock, _conn() as con:
        con.execute("DELETE FROM share_targets WHERE share_id=?", (sid,))
        con.execute("DELETE FROM shares WHERE id=?", (sid,))


def add_share_targets(sid, instance_ids, operator):
    now = time.time()
    with _lock, _conn() as con:
        con.executemany("INSERT OR IGNORE INTO share_targets(share_id,instance_id,added_at,added_by) VALUES(?,?,?,?)",
                        [(sid, i, now, operator) for i in instance_ids])


def remove_share_targets(sid, instance_ids):
    with _lock, _conn() as con:
        con.executemany("DELETE FROM share_targets WHERE share_id=? AND instance_id=?", [(sid, i) for i in instance_ids])



# ---------------- 权限模板 ----------------

def _tpl_row(r):
    d = dict(r)
    d["spec"] = json.loads(d.pop("spec_json"))
    d["builtin"] = bool(d["builtin"])
    return d


def seed_builtin_templates():
    """首次启动写入内置模板；已存在则不覆盖（管理员可能已调整）。"""
    with _lock, _conn() as con:
        for t in BUILTIN_TEMPLATES:
            exists = con.execute("SELECT 1 FROM perm_templates WHERE key=?", (t["key"],)).fetchone()
            if exists:
                continue
            con.execute(
                "INSERT INTO perm_templates(key,name,description,level,spec_json,builtin,version,updated_at,updated_by)"
                " VALUES(?,?,?,?,?,1,1,?,?)",
                (t["key"], t["name"], t["description"], t["level"], json.dumps(t["spec"]), time.time(), "system"),
            )


def list_templates():
    with _conn() as con:
        rows = con.execute("SELECT * FROM perm_templates ORDER BY builtin DESC, id").fetchall()
        tpls = [_tpl_row(r) for r in rows]
        counts = dict(con.execute(
            "SELECT template_id, count(*) FROM instance_template WHERE template_id IS NOT NULL GROUP BY template_id"
        ).fetchall())
    for t in tpls:
        t["instance_count"] = counts.get(t["id"], 0)
    return tpls


def get_template(tid):
    with _conn() as con:
        r = con.execute("SELECT * FROM perm_templates WHERE id=?", (tid,)).fetchone()
        return _tpl_row(r) if r else None


def create_template(name, description, level, spec, operator):
    with _lock, _conn() as con:
        cur = con.execute(
            "INSERT INTO perm_templates(name,description,level,spec_json,builtin,version,updated_at,updated_by)"
            " VALUES(?,?,?,?,0,1,?,?)",
            (name, description, level, json.dumps(spec), time.time(), operator),
        )
        return cur.lastrowid


def update_template(tid, name, description, level, spec, operator):
    """修改模板会使版本号 +1，已应用旧版本的服务器将显示"模板已更新，待重新应用"。"""
    with _lock, _conn() as con:
        con.execute(
            "UPDATE perm_templates SET name=?,description=?,level=?,spec_json=?,version=version+1,updated_at=?,updated_by=?"
            " WHERE id=?",
            (name, description, level, json.dumps(spec), time.time(), operator, tid),
        )


def delete_template(tid):
    with _lock, _conn() as con:
        con.execute("DELETE FROM perm_templates WHERE id=? AND builtin=0", (tid,))
        con.execute("UPDATE instance_template SET template_id=NULL, template_version=NULL WHERE template_id=?", (tid,))


def bind_template(instance_id, template_id, version, operator):
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO instance_template(instance_id,template_id,template_version,applied_at,applied_by) VALUES(?,?,?,?,?)"
            " ON CONFLICT(instance_id) DO UPDATE SET template_id=excluded.template_id,"
            " template_version=excluded.template_version, applied_at=excluded.applied_at, applied_by=excluded.applied_by",
            (instance_id, template_id, version, time.time(), operator),
        )


def all_bindings():
    """返回 {instance_id: {template_id, template_name, template_version, current_version, applied_at, applied_by}}"""
    with _conn() as con:
        rows = con.execute(
            "SELECT b.*, t.name AS template_name, t.version AS current_version, t.level AS template_level,"
            " t.spec_json AS template_spec_json"
            " FROM instance_template b LEFT JOIN perm_templates t ON t.id=b.template_id"
        ).fetchall()
        out = {}
        for r in rows:
            d = dict(r)
            sj = d.pop("template_spec_json")
            d["template_spec"] = json.loads(sj) if sj else None
            out[r["instance_id"]] = d
        return out


# ---------------- 批量任务 ----------------

def create_job(jtype, title, params, items, operator):
    """items: [(instance_id, name)]"""
    now = time.time()
    with _lock, _conn() as con:
        cur = con.execute(
            "INSERT INTO jobs(type,title,params_json,status,total,created_at,operator) VALUES(?,?,?,?,?,?,?)",
            (jtype, title, json.dumps(params, ensure_ascii=False), "running", len(items), now, operator),
        )
        jid = cur.lastrowid
        con.executemany(
            "INSERT INTO job_items(job_id,instance_id,name,status) VALUES(?,?,?,'pending')",
            [(jid, iid, name) for iid, name in items],
        )
        return jid


def update_item(job_id, instance_id, status, message=""):
    now = time.time()
    with _lock, _conn() as con:
        if status == "running":
            con.execute("UPDATE job_items SET status=?, started_at=? WHERE job_id=? AND instance_id=?",
                        (status, now, job_id, instance_id))
            return
        con.execute("UPDATE job_items SET status=?, message=?, finished_at=? WHERE job_id=? AND instance_id=?",
                    (status, message[:1000], now, job_id, instance_id))


def finish_job(job_id):
    with _lock, _conn() as con:
        stats = dict(con.execute(
            "SELECT status, count(*) FROM job_items WHERE job_id=? GROUP BY status", (job_id,)
        ).fetchall())
        ok = stats.get("success", 0)
        skipped = stats.get("skipped", 0)
        failed = stats.get("failed", 0)
        total = sum(stats.values())
        if failed == 0:
            status = "success"
        elif ok == 0 and skipped == 0:
            status = "failed"
        else:
            status = "partial"
        con.execute("UPDATE jobs SET status=?, done=?, failed=?, finished_at=? WHERE id=?",
                    (status, ok + skipped + failed, failed, time.time(), job_id))
        return status, total, failed


def refresh_progress(job_id):
    with _lock, _conn() as con:
        r = con.execute(
            "SELECT sum(status IN ('success','failed','skipped')), sum(status='failed') FROM job_items WHERE job_id=?",
            (job_id,),
        ).fetchone()
        con.execute("UPDATE jobs SET done=?, failed=? WHERE id=?", (r[0] or 0, r[1] or 0, job_id))


def list_jobs(limit=50):
    with _conn() as con:
        rows = con.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d.pop("params_json") or "{}")
            out.append(d)
        return out


def get_job(job_id):
    with _conn() as con:
        r = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["params"] = json.loads(d.pop("params_json") or "{}")
        d["items"] = [dict(x) for x in con.execute(
            "SELECT * FROM job_items WHERE job_id=? ORDER BY status='failed' DESC, name", (job_id,)
        ).fetchall()]
        return d


def running_jobs_for(instance_ids):
    """返回正在被未完成任务占用的实例集合（防止同一台机器并发执行两个任务）。"""
    if not instance_ids:
        return set()
    q = ",".join("?" * len(instance_ids))
    with _conn() as con:
        rows = con.execute(
            f"SELECT DISTINCT instance_id FROM job_items WHERE status IN ('pending','running') AND instance_id IN ({q})",
            list(instance_ids),
        ).fetchall()
        return {r[0] for r in rows}


def mark_stale_jobs():
    """服务重启时，把上次未完成的任务标记为失败（执行线程已不存在）。"""
    with _lock, _conn() as con:
        con.execute("UPDATE job_items SET status='failed', message='平台重启，任务中断' WHERE status IN ('pending','running')")
        con.execute("UPDATE jobs SET status='failed', finished_at=? WHERE status='running'", (time.time(),))


# ---------------- 巡检 ----------------

def all_specs():
    """{instance_id: (spec 或 None, owner 或 None)}：平台记录的期望配置。"""
    out = {}
    with _conn() as con:
        for r in con.execute("SELECT instance_id, spec_json FROM permissions").fetchall():
            out[r["instance_id"]] = [json.loads(r["spec_json"]), None]
        for r in con.execute("SELECT instance_id, owner FROM instance_meta").fetchall():
            out.setdefault(r["instance_id"], [None, None])[1] = r["owner"]
    return {k: tuple(v) for k, v in out.items()}


def unbind_template(instance_id, operator):
    """单台自定义权限后解除模板绑定（配置已不再等于模板）。"""
    bind_template(instance_id, None, None, operator)

def save_inspection(instance_id, data):
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO inspections(instance_id,checked_at,data_json) VALUES(?,?,?)"
            " ON CONFLICT(instance_id) DO UPDATE SET checked_at=excluded.checked_at, data_json=excluded.data_json",
            (instance_id, time.time(), json.dumps(data, ensure_ascii=False)),
        )


def all_inspections():
    with _conn() as con:
        rows = con.execute("SELECT * FROM inspections").fetchall()
        return {r["instance_id"]: dict(json.loads(r["data_json"]), checked_at=r["checked_at"]) for r in rows}


# ---------------- 全局审计 ----------------

def query_audit(q="", action="", operator="", since=0, limit=200, offset=0):
    where, args = ["ts>=?"], [since]
    if action:
        where.append("action=?"); args.append(action)
    if operator:
        where.append("operator=?"); args.append(operator)
    if q:
        where.append("(instance_id LIKE ? OR detail LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
    w = " AND ".join(where)
    with _conn() as con:
        total = con.execute(f"SELECT count(*) FROM audit WHERE {w}", args).fetchone()[0]
        rows = con.execute(f"SELECT * FROM audit WHERE {w} ORDER BY ts DESC LIMIT ? OFFSET ?",
                           args + [limit, offset]).fetchall()
        operators = [r[0] for r in con.execute("SELECT DISTINCT operator FROM audit ORDER BY operator").fetchall()]
        return {"total": total, "items": [dict(r) for r in rows], "operators": operators}
