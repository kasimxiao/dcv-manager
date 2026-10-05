"""备选机型（托管开机函数 + 平台）与跨可用区迁移的单元测试，不访问 AWS。"""
import importlib
import json
import os
import sys

import pytest
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "backend"))


def cerr(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


# ---------------- 托管开机函数 ----------------

class FakeEC2:
    def __init__(self, inst, available):
        self.inst, self.available, self.calls = inst, available, []

    def describe_instances(self, InstanceIds):
        return {"Reservations": [{"Instances": [self.inst]}]}

    def start_instances(self, InstanceIds):
        self.calls.append(("start", self.inst["InstanceType"]))
        t = self.inst["InstanceType"]
        if t not in self.available:
            raise cerr(self.available.get("_err", "InsufficientInstanceCapacity") if t != "unsupported" else "Unsupported")
        self.inst["State"]["Name"] = "pending"

    def modify_instance_attribute(self, InstanceId, InstanceType):
        assert self.inst["State"]["Name"] == "stopped"
        self.calls.append(("modify", InstanceType["Value"]))
        self.inst["InstanceType"] = InstanceType["Value"]

    def _tagmap(self):
        return {t["Key"]: t["Value"] for t in self.inst.get("Tags", [])}

    def create_tags(self, Resources, Tags):
        m = self._tagmap(); m.update({t["Key"]: t["Value"] for t in Tags})
        self.inst["Tags"] = [{"Key": k, "Value": v} for k, v in m.items()]

    def delete_tags(self, Resources, Tags):
        drop = {t["Key"] for t in Tags}
        self.inst["Tags"] = [t for t in self.inst["Tags"] if t["Key"] not in drop]


@pytest.fixture
def fn(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")
    monkeypatch.setenv("ALLOWED_TYPES", "g6f.large,g6f.xlarge,g4dn.xlarge,g5.xlarge")
    monkeypatch.setenv("DEFAULT_FALLBACK", json.dumps({"g6f.xlarge": ["g4dn.xlarge", "g5.xlarge"]}))
    sys.path.insert(0, os.path.join(ROOT, "lambda", "dcv_power"))
    import handler
    importlib.reload(handler)
    return handler


def mk(itype="g6f.xlarge", tags=None):
    t = {"dcv": "true", **(tags or {})}
    return {"InstanceId": "i-1", "InstanceType": itype, "State": {"Name": "stopped"},
            "Placement": {"AvailabilityZone": "eu-central-1a"}, "Tags": [{"Key": k, "Value": v} for k, v in t.items()]}


def test_fn_uses_default_chain_and_marks(fn):
    e = FakeEC2(mk(), {"g5.xlarge": 1})
    fn.ec2 = e
    r = fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)
    assert r["results"][0]["type"] == "g5.xlarge"
    tags = e._tagmap()
    assert tags["dcv:fallback-from"] == "g6f.xlarge" and tags["dcv:original-type"] == "g6f.xlarge"


def test_fn_tag_overrides_default_and_none_disables(fn):
    e = FakeEC2(mk(tags={"dcv:fallback-types": "g6f.large"}), {"g6f.large": 1, "g4dn.xlarge": 1})
    fn.ec2 = e
    assert fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)["results"][0]["type"] == "g6f.large"
    e = FakeEC2(mk(tags={"dcv:fallback-types": "none"}), {"g4dn.xlarge": 1})
    fn.ec2 = e
    with pytest.raises(RuntimeError):
        fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)
    assert not any(c[0] == "modify" for c in e.calls)


def test_fn_all_fail_restores_type_and_raises_for_retry(fn):
    e = FakeEC2(mk(), {})
    fn.ec2 = e
    with pytest.raises(RuntimeError, match="1/1"):
        fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)
    assert e.inst["InstanceType"] == "g6f.xlarge" and "dcv:fallback-from" not in e._tagmap()


def test_fn_disallowed_types_ignored(fn):
    e = FakeEC2(mk(tags={"dcv:fallback-types": "p5.48xlarge,g4dn.xlarge"}), {"g4dn.xlarge": 1})
    fn.ec2 = e
    fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)
    assert ("modify", "p5.48xlarge") not in e.calls


def test_fn_non_capacity_error_not_switched(fn):
    e = FakeEC2(mk(), {"_err": "UnauthorizedOperation", "g4dn.xlarge": 1})
    fn.ec2 = e
    with pytest.raises(RuntimeError):
        fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)
    assert not any(c[0] == "modify" for c in e.calls)


def test_fn_skips_unmanaged_and_running(fn):
    inst = mk(); inst["Tags"] = []
    fn.ec2 = FakeEC2(inst, {})
    assert fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)["results"][0]["status"] == "skipped"
    inst = mk(); inst["State"]["Name"] = "running"
    fn.ec2 = FakeEC2(inst, {})
    assert fn.handler({"action": "start", "InstanceIds": ["i-1"]}, None)["results"][0]["status"] == "skipped"


def test_fn_revert_on_stop(fn):
    e = FakeEC2(mk("g4dn.xlarge", {"dcv:fallback-from": "g6f.xlarge", "dcv:original-type": "g6f.xlarge"}), {})
    fn.ec2 = e
    ev = {"detail-type": "EC2 Instance State-change Notification", "detail": {"instance-id": "i-1", "state": "stopped"}}
    assert fn.handler(ev, None)["status"] == "reverted"
    assert e.inst["InstanceType"] == "g6f.xlarge" and "dcv:fallback-from" not in e._tagmap() and "dcv:original-type" not in e._tagmap()
    # 没有临时机型标记（例如人工改的机型）不动
    e = FakeEC2(mk("g4dn.xlarge", {"dcv:original-type": "g6f.xlarge"}), {})
    fn.ec2 = e
    assert fn.handler(ev, None)["status"] == "skipped" and e.inst["InstanceType"] == "g4dn.xlarge"


# ---------------- 平台：备选机型 ----------------

def test_platform_chain_matches_function():
    import aws_service
    assert aws_service.fallback_chain({}, "g6f.xlarge") == ["g4dn.xlarge", "g5.xlarge"]
    assert aws_service.fallback_chain({"dcv:fallback-types": "none"}, "g6f.xlarge") == []
    assert aws_service.fallback_chain({"dcv:fallback-types": "g6f.xlarge,g6f.large,bad.type"}, "g6f.xlarge") == ["g6f.large"]
    assert aws_service.fallback_chain({}, "g6f.2xlarge") == []


def test_scheduler_start_targets_function(monkeypatch):
    import eb_scheduler
    monkeypatch.setattr(eb_scheduler, "power_function_arn", lambda r=None: "arn:aws:lambda:eu-central-1:1:function:dcv-power")
    monkeypatch.setattr(eb_scheduler, "_role_arn", lambda: "role")
    t = eb_scheduler._target("start", ["i-1"])
    assert t["Arn"].startswith("arn:aws:lambda") and json.loads(t["Input"]) == {"action": "start", "InstanceIds": ["i-1"]}
    assert eb_scheduler._target("stop", ["i-1"])["Arn"] == eb_scheduler.ACTION_ARN["stop"]
    p = eb_scheduler._parse({"Name": "x", "ScheduleExpression": "cron(0 8 * * ? *)", "Target": t})
    assert p["action"] == "start" and p["instance_ids"] == ["i-1"] and p["managed_start"]


def test_scheduler_falls_back_to_ec2_when_function_missing(monkeypatch):
    import eb_scheduler
    monkeypatch.setattr(eb_scheduler, "power_function_arn", lambda r=None: None)
    monkeypatch.setattr(eb_scheduler, "_role_arn", lambda: "role")
    assert eb_scheduler._target("start", ["i-1"])["Arn"] == eb_scheduler.ACTION_ARN["start"]


# ---------------- 迁移 ----------------

def test_plan_zones(monkeypatch):
    import migrate_service as m
    monkeypatch.setattr(m.capacity_service, "launch_subnets", lambda: {"a": "s-a", "b": "s-b"})
    monkeypatch.setattr(m.capacity_service, "best_zones", lambda t: [("a", "available"), ("c", "likely"), ("b", "likely")])
    assert m.plan_zones({"az": "a"}, "auto", "g6f.xlarge") == ["b"]
    assert m.plan_zones({"az": "a"}, "b", "g6f.xlarge") == ["b"]
    with pytest.raises(m.MigrateError):
        m.plan_zones({"az": "a"}, "a", "g6f.xlarge")
    monkeypatch.setattr(m.capacity_service, "best_zones", lambda t: [("a", "available")])
    with pytest.raises(m.MigrateError):
        m.plan_zones({"az": "a"}, "auto", "g6f.xlarge")


def test_migrate_aborts_without_capacity_and_touches_nothing(monkeypatch):
    import migrate_service as m
    calls = []

    class E:
        def describe_instances(self, InstanceIds):
            return {"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "g6f.xlarge", "State": {"Name": "stopped"}}]}]}

        def __getattr__(self, k):
            calls.append(k)
            raise AssertionError(f"不应调用 {k}")
    monkeypatch.setattr(m, "ec2", E())
    monkeypatch.setattr(m, "plan_zones", lambda *a: ["b"])
    monkeypatch.setattr(m.capacity_service, "probe", lambda az, t: {"ok": False})
    monkeypatch.setattr(m.capacity_service, "cleanup_probes", lambda: 0)
    with pytest.raises(m.MigrateError, match="未做任何改动"):
        m.migrate_one({"instance_id": "i-1", "az": "a"})
    assert calls == []


def test_launch_clone_copies_config_and_tries_next_zone(monkeypatch):
    import migrate_service as m
    import aws_service
    seen = []

    class E:
        def run_instances(self, **kw):
            seen.append(kw)
            if kw["NetworkInterfaces"][0]["SubnetId"] == "s-b":
                raise cerr("InsufficientInstanceCapacity")
            return {"Instances": [{"InstanceId": "i-new"}]}
    monkeypatch.setattr(m, "ec2", E())
    monkeypatch.setattr(m.capacity_service, "launch_subnets", lambda: {"b": "s-b", "c": "s-c"})
    monkeypatch.setattr(aws_service, "is_capacity_error", lambda e: "Insufficient" in str(e))
    d = {"InstanceId": "i-old", "InstanceType": "g6f.xlarge", "KeyName": "k", "IamInstanceProfile": {"Arn": "arn:p"},
         "SecurityGroups": [{"GroupId": "sg-1"}], "MetadataOptions": {"HttpTokens": "required"},
         "Tags": [{"Key": "Name", "Value": "王工"}, {"Key": "dcv", "Value": "true"}, {"Key": "dcv:group", "Value": "设计"},
                  {"Key": "aws:cloudformation:x", "Value": "y"}, {"Key": "dcv:pending-template", "Value": "1"},
                  {"Key": "dcv:fallback-from", "Value": "g6f.xlarge"}]}
    nid, az = m.launch_clone(d, "ami-1", ["b", "c"], "g6f.xlarge")
    assert (nid, az) == ("i-new", "c") and len(seen) == 2
    kw = seen[-1]
    tags = {t["Key"]: t["Value"] for t in kw["TagSpecifications"][0]["Tags"]}
    assert tags == {"Name": "王工", "dcv": "true", "dcv:group": "设计", "dcv:migrated-from": "i-old"}
    assert kw["KeyName"] == "k" and kw["IamInstanceProfile"] == {"Arn": "arn:p"}
    assert kw["NetworkInterfaces"][0]["Groups"] == ["sg-1"] and kw["MetadataOptions"] == {"HttpTokens": "required"}


def test_remap_platform_moves_records(monkeypatch, tmp_path):
    import config, db, store
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    import importlib as il
    il.reload(db); il.reload(store)
    import migrate_service as m
    il.reload(m)
    db.init_db(); store.init()
    tid = store.list_templates()[0]["id"]
    store.bind_template("i-old", tid, 1, "t")
    db.save_meta("i-old", owner="dcvuser", note="n")
    sid = store.create_share("t", name="s", bucket="b", prefix="p", region="r", drive="S", mode="rw", scope="selected",
                             cache_gb=5, kms_key="", policy_arn="[]")
    store.add_share_targets(sid, ["i-old", "i-x"], "t")
    monkeypatch.setattr(m, "ec2", type("E", (), {"describe_addresses": lambda self, **k: {"Addresses": []}})())
    import share_service, eb_scheduler
    synced = []
    monkeypatch.setattr(share_service, "sync_iam", lambda s, ids: synced.append(sorted(ids)) or ["arn:x"])
    monkeypatch.setattr(eb_scheduler, "list_all", lambda: [{"name": "dcv-start-1", "instance_ids": ["i-old", "i-y"]}])
    upd = []
    monkeypatch.setattr(eb_scheduler, "update", lambda n, instance_ids=None: upd.append((n, instance_ids)))
    notes = m.remap_platform("i-old", "i-new", "t")
    b = store.all_bindings()
    b = {x["instance_id"]: x for x in b} if isinstance(b, list) else b
    assert "i-new" in b and "i-old" not in b
    assert db.get_meta("i-new")["owner"] == "dcvuser"
    share = next(x for x in store.list_shares() if x["id"] == sid)
    assert sorted(share["target_ids"]) == ["i-new", "i-x"] and synced == [["i-new", "i-x"]]
    assert upd == [("dcv-start-1", ["i-new", "i-y"])]
    assert any("共享盘" in n for n in notes) and any("定时任务" in n for n in notes)
    monkeypatch.undo()
    il.reload(db); il.reload(store); il.reload(m)
