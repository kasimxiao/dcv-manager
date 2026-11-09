"""容量检测：结论判定、创建时的可用区回退、开机时的机型回退。"""
import datetime as dt
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("AWS_REGION", "eu-central-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")

import capacity_service as cs  # noqa: E402


def ago(minutes):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).isoformat()


def test_not_offered():
    assert cs._verdict(False, [], None, 9)[0] == "not_offered"


def test_recent_real_failure_beats_good_spot_score():
    st, why = cs._verdict(True, [{"time": ago(5)}, {"time": ago(9)}], None, 9)
    assert st == "unavailable" and "2 次" in why


def test_older_failure_is_limited():
    assert cs._verdict(True, [{"time": ago(45)}], None, 9)[0] == "limited"


def test_fresh_probe_overrides_older_failure():
    probe = {"ok": True, "at": time.time() - 30, "count": 3}
    st, why = cs._verdict(True, [{"time": ago(10)}], probe, 1)
    assert st == "available" and "3 台" in why


def test_failure_after_probe_wins():
    probe = {"ok": True, "at": time.time() - 600, "count": 1}
    assert cs._verdict(True, [{"time": ago(2)}], probe, 9)[0] == "unavailable"


def test_probe_capacity_error_and_other_error():
    assert cs._verdict(True, [], {"ok": False, "code": "InsufficientInstanceCapacity", "at": time.time(), "error": "容量不足"}, 9)[0] == "unavailable"
    assert cs._verdict(True, [], {"ok": False, "code": "ReservationCapacityExceeded", "at": time.time(), "error": "配额"}, 9)[0] == "unknown"


def test_stale_probe_ignored():
    assert cs._verdict(True, [], {"ok": False, "code": "InsufficientInstanceCapacity", "at": time.time() - 3600, "error": ""}, 9)[0] == "likely"


@pytest.mark.parametrize("score,st", [(9, "likely"), (5, "likely"), (2, "limited"), (None, "unknown")])
def test_spot_score_only(score, st):
    assert cs._verdict(True, [], None, score)[0] == st


# ---------------- 创建时可用区回退 ----------------

class CapErr(Exception):
    response = {"Error": {"Code": "InsufficientInstanceCapacity"}}


class OtherErr(Exception):
    response = {"Error": {"Code": "InvalidParameterValue"}}


def fake_ec2(monkeypatch, full_subnets, other_error=False):
    import aws_service
    calls = []

    class E:
        def describe_images(self, **kw):
            return {"Images": [{"RootDeviceName": "/dev/sda1",
                                "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 100}}]}]}

        def run_instances(self, **kw):
            sub = kw["NetworkInterfaces"][0]["SubnetId"]
            calls.append(sub)
            if other_error:
                raise OtherErr("bad")
            if sub in full_subnets:
                raise CapErr("no capacity")
            return {"Instances": [{"InstanceId": f"i-{len(calls)}", "Placement": {"AvailabilityZone": {"sa": "az-a", "sb": "az-b"}[sub]}}]}
    monkeypatch.setattr(aws_service, "ec2", E())
    monkeypatch.setattr(aws_service, "invalidate_cache", lambda: None)
    return aws_service, calls


@pytest.fixture(autouse=True)
def _region_cfg(monkeypatch):
    import config
    monkeypatch.setattr(config, "region_cfg", lambda r: {"vpc_id": "v", "subnet_ids": ["sa"], "security_group_id": "sg", "key_name": "k"})
    import aws_service
    monkeypatch.setattr(aws_service, "image_region", lambda i: "eu-central-1")


def test_launch_falls_back_to_next_zone(monkeypatch):
    a, calls = fake_ec2(monkeypatch, {"sa"})
    ids, placed, errs = a.launch_from_image("ami-1", "g6f.xlarge", "n", count=2, subnets=[["sa", "sb"], ["sa", "sb"]])
    assert placed == ["az-b", "az-b"] and len(ids) == 2 and errs == []
    assert calls == ["sa", "sb", "sa", "sb"]


def test_launch_spread_plan(monkeypatch):
    a, _ = fake_ec2(monkeypatch, set())
    _, placed, _ = a.launch_from_image("ami-1", "g6f.xlarge", "n", count=3, subnets=[["sa", "sb"], ["sb", "sa"], ["sa", "sb"]])
    assert placed == ["az-a", "az-b", "az-a"]


def test_launch_all_zones_full_raises(monkeypatch):
    a, _ = fake_ec2(monkeypatch, {"sa", "sb"})
    with pytest.raises(CapErr):
        a.launch_from_image("ami-1", "g6f.xlarge", "n", count=1, subnets=[["sa", "sb"]])


def test_launch_non_capacity_error_does_not_try_other_zones(monkeypatch):
    a, calls = fake_ec2(monkeypatch, set(), other_error=True)
    with pytest.raises(OtherErr):
        a.launch_from_image("ami-1", "g6f.xlarge", "n", count=3, subnets=[["sa", "sb"]] * 3)
    assert calls == ["sa"]


# ---------------- 开机时机型回退 ----------------

def run_power(monkeypatch, available_types, fallback):
    import jobs, aws_service, db
    state = {"type": "g6f.xlarge", "changes": []}

    def power(iid, action):
        if state["type"] not in available_types:
            raise CapErr("no")

    def change(iid, t, remember_original=True):
        state["changes"].append(t); old = state["type"]; state["type"] = t; return old
    monkeypatch.setattr(aws_service, "power_action", power)
    monkeypatch.setattr(aws_service, "change_instance_type", change)
    monkeypatch.setattr(aws_service, "mark_fallback", lambda iid, t: state.update(marked=t))
    monkeypatch.setattr(db, "add_audit", lambda *a, **k: None)
    captured = {}

    def fake_start(jtype, title, params, ids, op, worker):
        inst = {"instance_id": "i-1", "name": "n", "state": "stopped", "instance_type": "g6f.xlarge", "az": "az-a",
                "fallback_types": ["g4dn.xlarge"]}
        res = {}
        monkeypatch.setattr(jobs, "_pool", lambda jid, insts, fn, w: res.update(r=fn(insts[0])))
        worker(1, [inst])
        captured.update(res)
        return 1
    monkeypatch.setattr(jobs, "_start", fake_start)
    import capacity_service
    monkeypatch.setattr(capacity_service, "invalidate", lambda: None)
    jobs.start_power(["i-1"], "start", "t", fallback)
    return captured["r"], state


def test_power_fallback_to_alternative_type(monkeypatch):
    (st, msg), s = run_power(monkeypatch, {"g6f.2xlarge"}, ["g6f.large", "g6f.2xlarge"])
    assert st == "success" and "g6f.2xlarge" in msg and s["type"] == "g6f.2xlarge"
    assert s["marked"] == "g6f.xlarge"  # 关机后改回原机型


def test_power_uses_server_fallback_when_not_specified(monkeypatch):
    (st, msg), s = run_power(monkeypatch, {"g4dn.xlarge"}, None)
    assert st == "success" and s["type"] == "g4dn.xlarge" and s["marked"] == "g6f.xlarge"


def test_power_fallback_all_fail_restores_original(monkeypatch):
    (st, msg), s = run_power(monkeypatch, set(), ["g6f.large"])
    assert st == "failed" and "容量不足" in msg and s["type"] == "g6f.xlarge"


def test_power_without_fallback_reports_capacity(monkeypatch):
    (st, msg), s = run_power(monkeypatch, set(), [])
    assert st == "failed" and "容量检测" in msg and s["changes"] == []


# ---------------- 共享盘：忙碌服务器补同步 ----------------

def test_busy_server_gets_share_sync_after_job(monkeypatch):
    import jobs, store
    started = []
    monkeypatch.setattr(store, "running_jobs_for", lambda ids: set())
    monkeypatch.setattr(jobs, "start_share_sync", lambda ids, op, title=None: started.append(sorted(ids)) or 99)
    jobs.PENDING_SHARE_SYNC.clear()
    jobs.PENDING_SHARE_SYNC.update({"i-1", "i-2"})
    jobs._flush_pending_share_sync()
    assert started == [["i-1", "i-2"]] and not jobs.PENDING_SHARE_SYNC


def test_pending_sync_waits_while_still_busy(monkeypatch):
    import jobs, store
    started = []
    monkeypatch.setattr(store, "running_jobs_for", lambda ids: set(ids) & {"i-1"})
    monkeypatch.setattr(jobs, "start_share_sync", lambda ids, op, title=None: started.append(sorted(ids)) or 99)
    jobs.PENDING_SHARE_SYNC.clear()
    jobs.PENDING_SHARE_SYNC.update({"i-1", "i-2"})
    jobs._flush_pending_share_sync()
    assert started == [["i-2"]] and jobs.PENDING_SHARE_SYNC == {"i-1"}
    jobs.PENDING_SHARE_SYNC.clear()


def test_ami_name_is_aws_compliant():
    import re, aws_service
    n = aws_service.ami_safe_name("全功能测试快照 v2 (设计)", "i-09184731af230a0a7")
    assert re.fullmatch(r"[A-Za-z0-9()./_-]{3,128}", n), n
    assert aws_service.ami_safe_name("中文", "i-abc12345678").startswith("dcv-snapshot-")


def test_launch_volume_not_smaller_than_image_snapshot(monkeypatch):
    """镜像系统盘 100GB 时，不能按设置的 60GB 创建，否则 AWS 报 InvalidBlockDeviceMapping。"""
    a, _ = fake_ec2(monkeypatch, set())
    seen = {}

    orig = a.ec2.run_instances

    def spy(**kw):
        seen.update(kw)
        return orig(**kw)

    monkeypatch.setattr(a.ec2, "run_instances", spy)
    monkeypatch.setattr(a, "LAUNCH_VOLUME_GB", 60)
    a.launch_from_image("ami-1", "g6f.xlarge", "n")
    bdm = seen["BlockDeviceMappings"][0]
    assert bdm["DeviceName"] == "/dev/sda1" and bdm["Ebs"]["VolumeSize"] == 100
