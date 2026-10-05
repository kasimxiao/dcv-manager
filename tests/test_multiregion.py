"""多区域：配置兼容、区域路由、跨区域汇总、定时任务按区域拆分、移除区域。不访问 AWS。"""
import importlib
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    def load(data):
        f = tmp_path / "settings.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("DCV_SETTINGS_PATH", str(f))
        import config
        importlib.reload(config)
        return config
    yield load
    monkeypatch.undo()
    import config
    importlib.reload(config)


def test_legacy_single_region_settings_become_home_region(cfg):
    c = cfg({"region": "eu-central-1", "vpc_id": "vpc-1", "subnet_ids": ["s-a"], "security_group_id": "sg-1", "key_name": "k"})
    assert c.REGIONS == ["eu-central-1"] and c.HOME_REGION == "eu-central-1"
    assert c.region_cfg("eu-central-1") == {"vpc_id": "vpc-1", "subnet_ids": ["s-a"], "security_group_id": "sg-1", "key_name": "k"}
    assert c.LAUNCH_SG == "sg-1" and c.LAUNCH_SUBNET == "s-a"


def test_multi_region_settings(cfg):
    c = cfg({"region": "eu-west-2", "regions": {"eu-central-1": {"subnet_ids": ["s-f"], "security_group_id": "sg-f", "key_name": "kf"},
                                               "eu-west-2": {"subnet_ids": ["s-l"], "security_group_id": "sg-l", "key_name": "kl"}}})
    assert c.HOME_REGION == "eu-west-2" and c.REGIONS == ["eu-west-2", "eu-central-1"]
    assert c.region_cfg("eu-central-1")["security_group_id"] == "sg-f" and c.LAUNCH_SG == "sg-l"
    assert c.region_of_az("eu-west-2a") == "eu-west-2" and c.region_of_az("us-east-1-bos-1a") == "us-east-1-bos-1"


def test_home_falls_back_when_region_not_managed(cfg):
    c = cfg({"region": "us-east-1", "regions": {"eu-central-1": {"subnet_ids": ["s"]}}})
    assert c.HOME_REGION == "eu-central-1"


def test_proxy_routes_by_thread_context(monkeypatch):
    import aws_service as a
    seen = []

    class C:
        def __init__(self, r): self.r = r
        def describe_x(self): seen.append((threading.current_thread().name, self.r)); return self.r
    monkeypatch.setattr(a, "client", lambda svc, region=None: C(region or a.current_region()))
    with a.use_region("eu-west-2"):
        assert a.ec2.describe_x() == "eu-west-2"
        with a.use_region("ap-northeast-1"):
            assert a.ec2.describe_x() == "ap-northeast-1"
        assert a.ec2.describe_x() == "eu-west-2"
        out = []
        t = threading.Thread(target=lambda: out.append(a.ec2.describe_x()))
        t.start(); t.join()
        assert out == [a.config.HOME_REGION]  # 上下文不跨线程泄漏


def test_list_instances_merges_regions_and_keeps_failed_region(monkeypatch):
    import aws_service as a
    monkeypatch.setattr(a.config, "REGIONS", ["r1", "r2"])
    data = {"r1": [{"instance_id": "i-1", "group": "", "name": "a"}], "r2": [{"instance_id": "i-2", "group": "", "name": "b"}]}
    monkeypatch.setattr(a, "_list_region", lambda r: [dict(x, region=r) for x in data[r]])
    a.invalidate_cache()
    got = a.list_instances(use_cache=False)
    assert {(x["instance_id"], x["region"]) for x in got} == {("i-1", "r1"), ("i-2", "r2")}
    assert a.region_of("i-2") == "r2" and a.list_errors() == {}

    def boom(r):
        if r == "r2":
            raise RuntimeError("AccessDenied")
        return [dict(x, region=r) for x in data[r]]
    monkeypatch.setattr(a, "_list_region", boom)
    got = a.list_instances(use_cache=False)
    assert {x["instance_id"] for x in got} == {"i-1", "i-2"}  # 读取失败的区域保留上次结果
    assert "r2" in a.list_errors()
    a.invalidate_cache(); a._list_cache.pop("errors", None)


def test_in_instance_region_decorator(monkeypatch):
    import aws_service as a
    monkeypatch.setitem(a._region_map, "i-9", "sa-east-1")

    @a.in_instance_region
    def f(iid):
        return a.current_region()
    assert f("i-9") == "sa-east-1" and a.current_region() == a.config.HOME_REGION


def test_schedule_split_by_region(monkeypatch):
    import eb_scheduler as e, aws_service as a
    monkeypatch.setattr(a, "group_by_region", lambda ids: {"r1": [i for i in ids if i.startswith("i-1")], "r2": [i for i in ids if i.startswith("i-2")]})
    puts = []
    monkeypatch.setattr(e, "_ensure_group", lambda r: None)
    monkeypatch.setattr(e, "_put", lambda region, op, name, action, ids, *rest: puts.append((region, op, action, ids)))
    monkeypatch.setattr(e, "get", lambda name, region=None: {"name": name, "region": region})
    out = e.create_many("start", ["i-1a", "i-2a", "i-1b"], "0 8 ? * MON-FRI *")
    assert sorted(p[0] for p in puts) == ["r1", "r2"] and len(out) == 2
    assert next(p for p in puts if p[0] == "r1")[3] == ["i-1a", "i-1b"]


def test_schedule_update_rejects_other_region(monkeypatch):
    import eb_scheduler as e, aws_service as a
    monkeypatch.setattr(e, "get", lambda name, region=None: {"action": "start", "instance_ids": ["i-1"], "cron": "x", "timezone": "t", "note": "", "enabled": True})
    monkeypatch.setattr(a, "region_of", lambda i: "r2" if i == "i-2" else "r1")
    with pytest.raises(ValueError, match="只能包含本区域"):
        e.update("dcv-start-1", instance_ids=["i-1", "i-2"], region="r1")


def test_target_uses_region_function(monkeypatch):
    import eb_scheduler as e
    monkeypatch.setattr(e, "_role_arn", lambda: "role")
    monkeypatch.setattr(e, "power_function_arn", lambda r=None: f"arn:aws:lambda:{r}:1:function:dcv-power" if r == "r2" else None)
    assert e._target("start", ["i"], "r2")["Arn"].startswith("arn:aws:lambda:r2")
    assert e._target("start", ["i"], "r1")["Arn"] == e.ACTION_ARN["start"]


def test_remove_region_keeps_others(tmp_path, monkeypatch, cfg):
    c = cfg({"region": "r1", "regions": {"r1": {"subnet_ids": ["a"]}, "r2": {"subnet_ids": ["b"]}}})
    import setup_service as s
    importlib.reload(s)
    monkeypatch.setattr(s, "schedule_restart", lambda *a: None)
    home = s.remove_region("r1", "admin")
    data = json.loads(open(c.SETTINGS_PATH, encoding="utf-8").read())
    assert home == "r2" and list(data["regions"]) == ["r2"] and data["region"] == "r2"
    importlib.reload(c)
    with pytest.raises(ValueError, match="至少保留"):
        s.remove_region("r2", "admin")
