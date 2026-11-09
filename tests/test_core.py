"""后端核心逻辑单元测试（不访问 AWS）。运行：cd backend && python -m pytest -q ../tests"""
import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("AWS_REGION", "eu-central-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")


@pytest.fixture()
def fresh_db(monkeypatch):
    path = tempfile.mktemp(suffix=".db")
    import config
    monkeypatch.setattr(config, "DB_PATH", path)
    import db
    monkeypatch.setattr(db, "DB_PATH", path)
    import store
    db.init_db()
    store.init()
    yield store
    os.remove(path)


# ---------------- 权限文件与模板 ----------------

def test_build_perm_content_groups_rules():
    from dcv_service import build_perm_content
    from dcv_features import ALL_FEATURE_KEYS
    spec = {k: "allow" for k in ALL_FEATURE_KEYS}
    spec.update({"usb": "disallow", "clipboard-copy": "deny"})
    text = build_perm_content(spec)
    lines = text.strip().split("\r\n")
    assert lines[0] == "[permissions]"
    assert "%any% disallow usb" in lines
    assert "%any% deny clipboard-copy" in lines
    # 不得出现给属主放开全部权限的规则，否则属主会绕过限制
    assert "%owner%" not in text


def test_builtin_templates_are_complete_and_usable():
    from templates_builtin import BUILTIN_TEMPLATES
    from dcv_features import ALL_FEATURE_KEYS
    keys = set()
    for t in BUILTIN_TEMPLATES:
        assert t["key"] not in keys
        keys.add(t["key"])
        assert set(t["spec"]) == set(ALL_FEATURE_KEYS)
        assert all(v in ("allow", "disallow", "deny") for v in t["spec"].values())
        for base in ("display", "keyboard", "mouse"):
            assert t["spec"][base] == "allow", f"{t['name']} 必须保留 {base}"
    hs = next(t for t in BUILTIN_TEMPLATES if t["key"] == "high-security")["spec"]
    for k in ("clipboard-copy", "clipboard-paste", "file-download", "file-upload", "usb", "printer", "screenshot"):
        assert hs[k] == "deny"
    out = next(t for t in BUILTIN_TEMPLATES if t["key"] == "outsourcing-restricted")["spec"]
    assert out["clipboard-paste"] == "allow" and out["clipboard-copy"] == "deny"


def test_seed_is_idempotent_and_keeps_admin_edits(fresh_db):
    store = fresh_db
    tpls = store.list_templates()
    assert len(tpls) == 5
    t = tpls[0]
    store.update_template(t["id"], "改过的名字", t["description"], t["level"], t["spec"], "tester")
    store.seed_builtin_templates()
    again = store.list_templates()
    assert len(again) == 5
    assert store.get_template(t["id"])["name"] == "改过的名字"
    assert store.get_template(t["id"])["version"] == 2


def test_builtin_template_cannot_be_deleted(fresh_db):
    store = fresh_db
    t = store.list_templates()[0]
    store.delete_template(t["id"])
    assert store.get_template(t["id"]) is not None


# ---------------- 批量任务状态 ----------------

def test_job_lifecycle_statuses(fresh_db):
    store = fresh_db
    jid = store.create_job("power", "t", {}, [("i-1", "a"), ("i-2", "b"), ("i-3", "c")], "tester")
    assert store.running_jobs_for(["i-1", "i-9"]) == {"i-1"}
    store.update_item(jid, "i-1", "success", "ok")
    store.update_item(jid, "i-2", "skipped", "已在运行")
    store.update_item(jid, "i-3", "failed", "boom")
    status, total, failed = store.finish_job(jid)
    assert (status, total, failed) == ("partial", 3, 1)
    assert store.running_jobs_for(["i-1"]) == set()
    job = store.get_job(jid)
    assert job["items"][0]["status"] == "failed"  # 失败项排在最前，便于排查


@pytest.mark.parametrize("statuses,expected", [
    (["success", "success"], "success"),
    (["success", "skipped"], "success"),
    (["failed", "failed"], "failed"),
    (["skipped", "failed"], "partial"),
])
def test_job_final_status(fresh_db, statuses, expected):
    store = fresh_db
    items = [(f"i-{n}", str(n)) for n in range(len(statuses))]
    jid = store.create_job("inspect", "t", {}, items, "tester")
    for (iid, _), st in zip(items, statuses):
        store.update_item(jid, iid, st)
    assert store.finish_job(jid)[0] == expected


def test_stale_jobs_marked_failed_on_restart(fresh_db):
    store = fresh_db
    jid = store.create_job("apply_template", "t", {}, [("i-1", "a")], "tester")
    store.mark_stale_jobs()
    j = store.get_job(jid)
    assert j["status"] == "failed" and j["items"][0]["message"] == "平台重启，任务中断"


def test_audit_query_filters(fresh_db):
    import db
    store = fresh_db
    db.add_audit("i-1", "stop", "alice", "批量任务 #1")
    db.add_audit("i-2", "permissions", "bob", "应用模板「高安全涉密」")
    db.add_audit("-", "login", "alice", "登录平台")
    assert store.query_audit(since=0)["total"] == 3
    assert store.query_audit(operator="alice", since=0)["total"] == 2
    assert store.query_audit(action="permissions", since=0)["items"][0]["operator"] == "bob"
    assert store.query_audit(q="高安全", since=0)["total"] == 1
    assert store.query_audit(since=time.time() + 10)["total"] == 0


# ---------------- 合规与健康评估 ----------------

def _insp(**kw):
    from dcv_service import build_perm_content
    from templates_builtin import BUILTIN_TEMPLATES
    spec = BUILTIN_TEMPLATES[0]["spec"]
    base = {"dcv_service": "Running", "session_owner": "dcvuser", "auto_owner": "dcvuser",
            "auto_perm": r"C:\dcv\console.perm", "perm_file": build_perm_content(spec).replace("\r\n", "\n"),
            "connections": 0, "disk_free_gb": 30, "owner_is_admin": False, "license": "licensed",
            "session_created": "2026-09-30T08:00:00Z", "last_disconnect": ""}
    base.update(kw)
    return base, spec


RUN = {"state": "running", "ssm": "Online"}


def test_compliant_host():
    from inspect_service import evaluate
    insp, spec = _insp()
    ev = evaluate(RUN, insp, spec, "dcvuser", None)
    assert ev["compliance"] == "compliant" and ev["health"] == "ok"
    assert ev["idle_since"] is not None


def test_drift_when_perm_file_tampered():
    from inspect_service import evaluate
    insp, spec = _insp(perm_file="[permissions]\n%any% allow builtin\n")
    ev = evaluate(RUN, insp, spec, "dcvuser", None)
    assert ev["compliance"] == "drift"
    assert any("权限文件" in r for r in ev["compliance_reasons"])


def test_system_owned_session_is_critical():
    """复现 "No sessions available"：会话属主为 SYSTEM 必须被标记为严重问题。"""
    from inspect_service import evaluate
    insp, spec = _insp(session_owner="SYSTEM", auto_owner=None)
    ev = evaluate(RUN, insp, spec, "dcvuser", None)
    assert ev["health"] == "critical"
    assert any("No sessions available" in a["message"] for a in ev["alerts"])
    assert any("开机自动会话" in r for r in ev["compliance_reasons"])


def test_admin_user_and_low_disk_warn():
    from inspect_service import evaluate
    insp, spec = _insp(owner_is_admin=True, disk_free_gb=3.2)
    ev = evaluate(RUN, insp, spec, "dcvuser", None)
    assert ev["health"] == "warn"
    msgs = " ".join(a["message"] for a in ev["alerts"])
    assert "本地管理员" in msgs
    assert "剩余空间不足（3.2 GB）" in msgs


def test_outdated_template_is_drift():
    from inspect_service import evaluate
    insp, spec = _insp()
    ev = evaluate(RUN, insp, spec, "dcvuser", {"template_id": 1, "outdated": True})
    assert ev["compliance"] == "drift"
    assert "模板已更新，需重新应用" in ev["compliance_reasons"]


def test_stopped_and_unmanaged():
    from inspect_service import evaluate
    insp, _ = _insp()
    assert evaluate({"state": "stopped"}, None, None, "dcvuser", None)["compliance"] == "unknown"
    assert evaluate(RUN, insp, None, "dcvuser", None)["compliance"] == "unmanaged"
    ev = evaluate(RUN, {"error": "巡检超时"}, None, "dcvuser", None)
    assert ev["compliance"] == "unknown" and ev["health"] == "warn"


def test_busy_connected_host_not_idle():
    from inspect_service import evaluate
    insp, spec = _insp(connections=2)
    assert evaluate(RUN, insp, spec, "dcvuser", None)["idle_since"] is None


# ---------------- 其他 ----------------

@pytest.mark.parametrize("pw,ok", [
    ("short1A#", False),
    ("alllowercase123", False),
    ("MyDcvPass#2026", False),
    ("Remote#Pass2026", False),
    ("Xk7#mPq2Lr9vWz", True),
])
def test_windows_password_policy(pw, ok):
    from dcv_service import validate_windows_password
    assert (validate_windows_password(pw, "dcvuser") is None) == ok


def test_role_from_claims():
    os.environ.setdefault("COGNITO_USER_POOL_ID", "eu-central-1_test")
    os.environ.setdefault("COGNITO_CLIENT_ID", "test")
    import cognito_auth
    assert cognito_auth.role_from_claims({"cognito:groups": ["viewer", "admin"]}) == "admin"
    assert cognito_auth.role_from_claims({"cognito:groups": ["operator"]}) == "operator"
    assert cognito_auth.role_from_claims({}) == "viewer"


def test_cron_wrapping():
    import eb_scheduler
    assert eb_scheduler._wrap_cron("30 8 ? * MON-FRI *") == "cron(30 8 ? * MON-FRI *)"
    assert eb_scheduler._wrap_cron("rate(1 hour)") == "rate(1 hour)"
    assert eb_scheduler._unwrap_cron("cron(0 9 * * ? *)") == "0 9 * * ? *"


def test_every_permission_has_description():
    """权限编辑器依赖每个分组和每个权限项的说明文字。"""
    from dcv_features import FEATURE_GROUPS, RULE_DESC
    for g in FEATURE_GROUPS:
        assert g.get("desc"), g["group"]
        for f in g["features"]:
            assert f.get("desc"), f["key"]
    assert set(RULE_DESC) == {"allow", "disallow", "deny"}


def test_detect_owner_prefers_host_over_stale_record(monkeypatch):
    """主机属主被手工改过时，下发权限不能按平台旧记录把属主改回去。"""
    import dcv_service as D
    import db
    monkeypatch.setattr(db, "get_meta", lambda i: {"owner": "Administrator"})
    monkeypatch.setattr(D.aws_service, "run_powershell",
                        lambda *a, **k: {"status": "Success",
                                         "stdout": "Session: 'console' (owner:dcvuser type:console)",
                                         "stderr": ""})
    assert D._detect_owner.__wrapped__("i-1") == "dcvuser"


def test_detect_owner_falls_back_to_record_when_host_unreachable(monkeypatch):
    import dcv_service as D
    import db
    monkeypatch.setattr(db, "get_meta", lambda i: {"owner": "dcvuser"})

    def boom(*a, **k):
        raise RuntimeError("SSM 不可达")

    monkeypatch.setattr(D.aws_service, "run_powershell", boom)
    assert D._detect_owner.__wrapped__("i-1") == "dcvuser"
