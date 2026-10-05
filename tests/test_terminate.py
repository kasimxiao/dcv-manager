"""删除服务器：前置检查、备份失败不删除、保留数据盘提示、平台数据清理、接口拦截正在连接的服务器。不访问 AWS。"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))


class E:
    def __init__(self, protected=False, image_state="available", kept=False):
        self.protected, self.image_state, self.kept, self.calls = protected, image_state, kept, []

    def describe_instances(self, InstanceIds):
        bdm = [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-root", "DeleteOnTermination": True}}]
        if self.kept:
            bdm.append({"DeviceName": "xvdf", "Ebs": {"VolumeId": "vol-data", "DeleteOnTermination": False}})
        return {"Reservations": [{"Instances": [{"InstanceId": InstanceIds[0], "State": {"Name": "stopped"}, "BlockDeviceMappings": bdm}]}]}

    def describe_instance_attribute(self, InstanceId, Attribute):
        return {"DisableApiTermination": {"Value": self.protected}}

    def create_image(self, **kw):
        self.calls.append("create_image"); return {"ImageId": "ami-bak"}

    def describe_images(self, ImageIds):
        return {"Images": [{"State": self.image_state}]}

    def terminate_instances(self, InstanceIds):
        self.calls.append("terminate")

    def describe_addresses(self, Filters):
        return {"Addresses": [{"PublicIp": "1.2.3.4", "AssociationId": "eipassoc-1"}]}

    def disassociate_address(self, AssociationId):
        self.calls.append("disassociate")


@pytest.fixture
def ts(monkeypatch):
    import terminate_service as t
    monkeypatch.setattr(t, "purge_platform", lambda iid, op: ["已清理"])
    monkeypatch.setattr(t.aws_service, "invalidate_cache", lambda: None)
    return t


def test_protected_instance_is_not_terminated(ts, monkeypatch):
    e = E(protected=True); monkeypatch.setattr(ts, "ec2", e)
    with pytest.raises(ts.TerminateError, match="终止保护"):
        ts.terminate_one({"instance_id": "i-1", "name": "a"}, False, "op")
    assert "terminate" not in e.calls


def test_backup_failure_keeps_server(ts, monkeypatch):
    e = E(image_state="failed"); monkeypatch.setattr(ts, "ec2", e)
    with pytest.raises(ts.TerminateError, match="未删除"):
        ts.terminate_one({"instance_id": "i-1", "name": "a"}, True, "op")
    assert e.calls == ["create_image"]


def test_backup_then_terminate_reports_kept_volume(ts, monkeypatch):
    e = E(kept=True); monkeypatch.setattr(ts, "ec2", e)
    r = ts.terminate_one({"instance_id": "i-1", "name": "a"}, True, "op")
    assert e.calls == ["create_image", "terminate"] and r["backup_image"] == "ami-bak" and r["kept_volumes"] == ["vol-data"]
    assert "vol-data" in r["message"] and "已清理" in r["message"]


def test_purge_platform(monkeypatch, tmp_path):
    import config, db, store
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    importlib.reload(db); importlib.reload(store)
    import terminate_service as t
    importlib.reload(t)
    try:
        db.init_db(); store.init()
        store.bind_template("i-x", store.list_templates()[0]["id"], 1, "op")
        db.save_meta("i-x", owner="dcvuser", note="n")
        sid = store.create_share("op", name="s", bucket="b", prefix="p", region="r", drive="S", mode="rw", scope="selected",
                                 cache_gb=5, kms_key="", policy_arn="[]")
        store.add_share_targets(sid, ["i-x", "i-y"], "op")
        e = E(); monkeypatch.setattr(t, "ec2", e)
        import share_service, eb_scheduler
        synced = []
        monkeypatch.setattr(share_service, "sync_iam", lambda s, ids: synced.append(sorted(ids)) or ["arn"])
        monkeypatch.setattr(eb_scheduler, "list_all", lambda: [
            {"name": "s-both", "region": "r", "instance_ids": ["i-x", "i-y"]},
            {"name": "s-only", "region": "r", "instance_ids": ["i-x"]},
            {"name": "s-other", "region": "r", "instance_ids": ["i-z"]}])
        upd, dele = [], []
        monkeypatch.setattr(eb_scheduler, "update", lambda n, instance_ids=None, region=None: upd.append((n, instance_ids)))
        monkeypatch.setattr(eb_scheduler, "delete", lambda n, region=None: dele.append(n))
        notes = t.purge_platform("i-x", "op")
        b = store.all_bindings(); b = {x["instance_id"]: x for x in b} if isinstance(b, list) else b
        assert "i-x" not in b and not db.get_meta("i-x")
        assert next(x for x in store.list_shares() if x["id"] == sid)["target_ids"] == ["i-y"] and synced == [["i-y"]]
        assert upd == [("s-both", ["i-y"])] and dele == ["s-only"] and "disassociate" in e.calls
        assert any("共享盘" in n for n in notes) and any("弹性 IP" in n for n in notes)
    finally:
        monkeypatch.undo()
        importlib.reload(db); importlib.reload(store); importlib.reload(t)


def test_api_blocks_connected_servers(monkeypatch):
    from fastapi.testclient import TestClient
    import app as appmod
    monkeypatch.setattr(appmod.aws_service, "list_instances", lambda use_cache=True: [
        {"instance_id": "i-1", "name": "a", "state": "running"}, {"instance_id": "i-2", "name": "b", "state": "stopped"}])
    monkeypatch.setattr(appmod.store, "all_inspections", lambda: {"i-1": {"connections": 2}})
    started = []
    monkeypatch.setattr(appmod.jobs, "start_terminate", lambda ids, op, backup: started.append((ids, backup)) or 7)
    monkeypatch.setattr(appmod, "_audit", lambda *a, **k: None)
    appmod.app.dependency_overrides[appmod.ADMIN] = lambda: {"username": "t", "role": "admin"}
    try:
        c = TestClient(appmod.app)
        r = c.post("/api/jobs/terminate", json={"instance_ids": ["i-1", "i-2"]})
        assert r.status_code == 409 and "正在连接" in r.json()["detail"] and not started
        r = c.post("/api/jobs/terminate", json={"instance_ids": ["i-1", "i-2"], "force_connected": True, "backup": True})
        assert r.status_code == 200 and started == [(["i-1", "i-2"], True)]
        assert c.post("/api/jobs/terminate", json={"instance_ids": ["i-9"]}).status_code == 400
    finally:
        appmod.app.dependency_overrides.clear()
