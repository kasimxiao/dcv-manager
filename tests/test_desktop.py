"""桌面用户自助开关机：只能看到和操作分配给自己的服务器（不访问 AWS）。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("AWS_REGION", "eu-central-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")

INSTS = [
    {"instance_id": "i-a", "name": "alice-pc", "state": "stopped", "portal_user": "alice", "instance_type": "g6f.large"},
    {"instance_id": "i-b", "name": "bob-pc", "state": "running", "portal_user": "bob", "instance_type": "g6f.large"},
    {"instance_id": "i-c", "name": "spare", "state": "stopped", "portal_user": "", "instance_type": "g6f.large"},
]


@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    import app as appmod
    state = {"user": {"username": "alice", "role": "desktop"}, "tags": [], "power": [], "audit": []}
    insts = [dict(i) for i in INSTS]
    monkeypatch.setattr(appmod.aws_service, "list_instances", lambda use_cache=True: [dict(i) for i in insts])

    def set_tags(ids, vals):
        state["tags"].append((sorted(ids), vals))
        for i in insts:
            if i["instance_id"] in ids:
                i["portal_user"] = vals["portal_user"]
    monkeypatch.setattr(appmod.aws_service, "set_mgmt_tags", set_tags)
    monkeypatch.setattr(appmod.store, "running_jobs_for", lambda ids: set())
    monkeypatch.setattr(appmod.jobs, "start_power", lambda ids, action, op: state["power"].append((ids, action, op)) or 1)
    monkeypatch.setattr(appmod, "_audit", lambda *a, **k: state["audit"].append(a))
    appmod.app.dependency_overrides[appmod._auth] = lambda: state["user"]
    try:
        yield TestClient(appmod.app), state, appmod
    finally:
        appmod.app.dependency_overrides.clear()


def test_desktop_sees_only_own_servers(client):
    c, _, _ = client
    r = c.get("/api/my/instances")
    assert r.status_code == 200
    items = r.json()["instances"]
    assert [i["instance_id"] for i in items] == ["i-a"]
    # 不暴露运维信息（权限、巡检、标签等）
    assert "portal_user" not in items[0] and "inspection" not in items[0]


def test_desktop_can_power_own_server(client):
    c, st, _ = client
    for act in ("start", "stop", "reboot"):
        assert c.post("/api/my/instances/i-a/power", json={"action": act}).status_code == 200
    assert st["power"] == [(["i-a"], "start", "alice"), (["i-a"], "stop", "alice"), (["i-a"], "reboot", "alice")]


def test_desktop_cannot_power_others_or_unassigned(client):
    c, st, _ = client
    assert c.post("/api/my/instances/i-b/power", json={"action": "stop"}).status_code == 403
    assert c.post("/api/my/instances/i-c/power", json={"action": "start"}).status_code == 403
    assert c.post("/api/my/instances/i-a/power", json={"action": "terminate"}).status_code == 400
    assert st["power"] == []


def test_desktop_blocked_from_operator_and_viewer_apis(client):
    c, st, _ = client
    assert c.get("/api/instances").status_code == 403
    assert c.post("/api/instances/i-a/power", json={"action": "start"}).status_code == 403
    assert c.post("/api/jobs/power", json={"instance_ids": ["i-a"], "action": "start"}).status_code == 403
    assert c.get("/api/users").status_code == 403
    assert c.get("/api/me").status_code == 200
    assert st["power"] == []


def test_admin_assigns_and_revokes(client, monkeypatch):
    c, st, appmod = client
    st["user"] = {"username": "root", "role": "admin"}

    class FakeCog:
        def list_users(self):
            return [{"username": "alice", "role": "desktop", "enabled": True}]
    monkeypatch.setattr(appmod, "_cog", lambda: FakeCog())
    # alice 原有 i-a；改为 i-b、i-c：i-b 从 bob 转给 alice，i-a 收回
    r = c.put("/api/users/alice/instances", json={"instance_ids": ["i-b", "i-c"]})
    assert r.status_code == 200 and r.json()["added"] == 2 and r.json()["removed"] == 1
    assert (["i-b", "i-c"], {"portal_user": "alice"}) in st["tags"]
    assert (["i-a"], {"portal_user": ""}) in st["tags"]
    assert any("原属 bob" in a[3] for a in st["audit"])
    # 列表中带出分配结果
    users = c.get("/api/users").json()["users"]
    assert {i["instance_id"] for i in users[0]["instances"]} == {"i-b", "i-c"}
    # 不能分配平台未管理的服务器；不存在的用户 404
    assert c.put("/api/users/alice/instances", json={"instance_ids": ["i-zzz"]}).status_code == 400
    assert c.put("/api/users/nobody/instances", json={"instance_ids": []}).status_code == 404


def test_role_from_claims_desktop():
    os.environ.setdefault("COGNITO_USER_POOL_ID", "eu-central-1_test")
    os.environ.setdefault("COGNITO_CLIENT_ID", "test")
    import cognito_auth
    assert cognito_auth.role_from_claims({"cognito:groups": ["desktop"]}) == "desktop"
    assert cognito_auth.role_from_claims({"cognito:groups": ["desktop", "operator"]}) == "operator"


@pytest.mark.parametrize("pw,ok", [("Short#1a", False), ("longenough#123", False), ("LONGENOUGH#123", False),
                                   ("LongEnough1234", False), ("LongEnough#123", True)])
def test_password_policy_matches_pool(pw, ok):
    os.environ.setdefault("COGNITO_USER_POOL_ID", "eu-central-1_test")
    os.environ.setdefault("COGNITO_CLIENT_ID", "test")
    import cognito_auth
    if ok:
        cognito_auth.check_password(pw)
    else:
        with pytest.raises(ValueError, match="至少 12 位"):
            cognito_auth.check_password(pw)


def test_create_user_rolls_back_on_failure(monkeypatch):
    os.environ.setdefault("COGNITO_USER_POOL_ID", "eu-central-1_test")
    os.environ.setdefault("COGNITO_CLIENT_ID", "test")
    import cognito_auth
    calls = []

    class C:
        def admin_create_user(self, **k): calls.append("create")
        def admin_set_user_password(self, **k): raise RuntimeError("InvalidPasswordException")
        def admin_delete_user(self, **k): calls.append("delete")
    monkeypatch.setattr(cognito_auth, "_client", C())
    # 本地校验不通过：根本不调用 Cognito
    with pytest.raises(ValueError):
        cognito_auth.create_user("t", "short", role="desktop")
    assert calls == []
    # Cognito 侧失败：回滚删除已创建的用户
    with pytest.raises(RuntimeError):
        cognito_auth.create_user("t", "LongEnough#123", role="desktop")
    assert calls == ["create", "delete"]
