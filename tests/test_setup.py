"""初始化设置：配置优先级、计划校验、新建 VPC 子网划分、安全组规则。不访问 AWS。"""
import importlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))


def test_settings_file_overrides_env(tmp_path, monkeypatch):
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"region": "eu-west-1", "subnet_ids": ["subnet-a", "subnet-b"], "security_group_id": "sg-x",
                             "allowed_types": ["g6f.xlarge"], "volume_gb": 100}), encoding="utf-8")
    monkeypatch.setenv("DCV_SETTINGS_PATH", str(f))
    monkeypatch.setenv("DCV_LAUNCH_SG", "sg-env")
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "eu-central-1_abc")
    import config
    try:
        importlib.reload(config)
        assert config.AWS_REGION == "eu-west-1" and config.LAUNCH_SUBNET == "subnet-a" and config.LAUNCH_SUBNETS == ["subnet-a", "subnet-b"]
        assert config.LAUNCH_SG == "sg-x" and config.ALLOWED_INSTANCE_TYPES == ["g6f.xlarge"] and config.LAUNCH_VOLUME_GB == 100
        assert config.COGNITO_REGION == "eu-central-1"  # 登录不随服务器区域变化
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_missing_settings_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DCV_SETTINGS_PATH", str(tmp_path / "none.json"))
    monkeypatch.setenv("DCV_LAUNCH_SG", "sg-env")
    import config
    try:
        importlib.reload(config)
        assert config.LAUNCH_SG == "sg-env" and config.SETTINGS == {}
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def plan(**kw):
    p = {"region": "eu-central-1", "network": {"mode": "existing", "vpc_id": "vpc-1", "subnet_ids": ["s-1"]},
         "security_group": {"mode": "existing", "id": "sg-1"}, "access": {"profile_mode": "existing", "profile": "p", "key_name": "k"},
         "allowed_types": ["g6f.xlarge"]}
    p.update(kw)
    return p


def test_validate():
    import setup_service as s
    assert s.validate(plan()) == []
    e = s.validate(plan(network={"mode": "create", "cidr": "bad", "azs": []}, security_group={"mode": "create", "cidrs": [" "]},
                        access={"profile_mode": "existing", "profile": "", "key_name": ""}, allowed_types=[]))
    assert len(e) == 6


class FakeEC2:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def f(**kw):
            self.calls.append((name, kw))
            return {"create_vpc": {"Vpc": {"VpcId": "vpc-new"}}, "create_internet_gateway": {"InternetGateway": {"InternetGatewayId": "igw-1"}},
                    "create_route_table": {"RouteTable": {"RouteTableId": "rtb-1"}},
                    "create_subnet": {"Subnet": {"SubnetId": f"subnet-{len(self.calls)}"}},
                    "create_security_group": {"GroupId": "sg-new"}}.get(name, {})
        if name == "get_waiter":
            return lambda n: type("W", (), {"wait": lambda self, **k: None})()
        return f


def test_create_vpc_public_subnets(monkeypatch):
    import setup_service as s
    e = FakeEC2()
    monkeypatch.setattr(s, "c", lambda r, svc: e)
    vpc, subs = s.create_vpc("eu-central-1", "10.80.0.0/16", ["eu-central-1a", "eu-central-1b"], log=lambda m: None)
    assert vpc == "vpc-new" and len(subs) == 2
    cidrs = [kw["CidrBlock"] for n, kw in e.calls if n == "create_subnet"]
    assert cidrs == ["10.80.0.0/20", "10.80.16.0/20"]
    assert sum(1 for n, kw in e.calls if n == "modify_subnet_attribute" and kw["MapPublicIpOnLaunch"]["Value"]) == 2
    assert any(n == "create_route" and kw["GatewayId"] == "igw-1" and kw["DestinationCidrBlock"] == "0.0.0.0/0" for n, kw in e.calls)
    with pytest.raises(ValueError):
        s.create_vpc("r", "10.0.0.0/25", ["a"], log=lambda m: None)


def test_create_sg_default_rules(monkeypatch):
    import setup_service as s
    e = FakeEC2()
    monkeypatch.setattr(s, "c", lambda r, svc: e)
    gid = s.create_sg("r", "vpc-1", ["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"], log=lambda m: None)
    ing = next(kw for n, kw in e.calls if n == "authorize_security_group_ingress")["IpPermissions"]
    assert gid == "sg-new" and [(p["IpProtocol"], p["FromPort"]) for p in ing] == [("tcp", 8443), ("udp", 8443)]  # 默认不开 RDP
    assert [r["CidrIp"] for r in ing[0]["IpRanges"]] == ["203.0.113.10/32", "198.51.100.0/24"]
    assert ing[0]["Ipv6Ranges"][0]["CidrIpv6"] == "2001:db8::/32"
    eg = next(kw for n, kw in e.calls if n == "authorize_security_group_egress")["IpPermissions"]
    assert {(p["IpProtocol"], p["FromPort"]) for p in eg} == {("tcp", 443), ("tcp", 80), ("tcp", 1688), ("udp", 123)}
    act = next(p for p in eg if p["FromPort"] == 1688)
    assert [r["CidrIp"] for r in act["IpRanges"]] == ["169.254.169.250/32", "169.254.169.251/32"]
    rev = next(kw for n, kw in e.calls if n == "revoke_security_group_egress")["IpPermissions"]
    assert rev == [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]  # 去掉默认全放行
    with pytest.raises(ValueError):
        s.create_sg("r", "vpc-1", [], log=lambda m: None)


def test_create_sg_optional_rdp_and_all_egress(monkeypatch):
    import setup_service as s
    e = FakeEC2()
    monkeypatch.setattr(s, "c", lambda r, svc: e)
    s.create_sg("r", "vpc-1", ["0.0.0.0/0"], log=lambda m: None, egress="all", rdp_cidrs=["203.0.113.10"])
    ing = next(kw for n, kw in e.calls if n == "authorize_security_group_ingress")["IpPermissions"]
    assert ing[-1]["FromPort"] == 3389 and ing[-1]["IpRanges"][0]["CidrIp"] == "203.0.113.10/32"
    assert not any(n in ("authorize_security_group_egress", "revoke_security_group_egress") for n, _ in e.calls)
    with pytest.raises(ValueError, match="RDP"):
        s.create_sg("r", "vpc-1", ["10.0.0.0/8"], log=lambda m: None, rdp_cidrs=["0.0.0.0/0"])
    assert any("RDP" in x for x in s.validate(plan(security_group={"mode": "create", "cidrs": ["1.1.1.1"], "rdp_cidrs": ["0.0.0.0/0"]})))


def test_sg_summary_flags_world_open():
    import setup_service as s
    g = {"GroupId": "sg-1", "GroupName": "x", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "1.2.3.4/32"}]}]}
    r = s._sg_summary(g)
    assert r["dcv_tcp"] == ["0.0.0.0/0"] and r["dcv_udp"] == [] and r["open_world"]
    assert r["rdp"] == ["1.2.3.4/32"] and r["https_out"] is False  # 没有出站规则
    g["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    assert s._sg_summary(g)["https_out"] is True


def test_regions_query_all_candidate_types(monkeypatch):
    """回归：未查询的候选机型曾被误显示为「本区域不提供」。"""
    import setup_service as s, config
    asked = []

    class E:
        def describe_regions(self):
            return {"Regions": [{"RegionName": "r1"}]}

        def describe_instance_type_offerings(self, LocationType, Filters):
            asked.extend(Filters[0]["Values"])
            return {"InstanceTypeOfferings": [{"InstanceType": t, "Location": "r1a"} for t in Filters[0]["Values"]]}
    monkeypatch.setattr(s, "c", lambda r, svc: E())
    out = s.regions()
    assert set(config.CANDIDATE_TYPES) <= set(asked)
    assert set(out[0]["types"]) >= set(config.CANDIDATE_TYPES)


def test_role_policy_json_in_sync_with_template():
    """deploy/platform-role-policy.json 必须由模板生成且保持一致。"""
    import subprocess
    root = os.path.dirname(os.path.dirname(__file__))
    r = subprocess.run([sys.executable, os.path.join(root, "deploy", "render_policy.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout


def test_role_policy_is_least_privilege():
    import json as _j
    root = os.path.dirname(os.path.dirname(__file__))
    doc = _j.load(open(os.path.join(root, "deploy", "platform-role-policy.json"), encoding="utf-8"))
    acts = [a for st in doc["Statement"] for a in (st["Action"] if isinstance(st["Action"], list) else [st["Action"]])]
    assert not [a for a in acts if a.endswith(":*") or a == "*"], "不应有服务级通配权限"
    by = {st["Sid"]: st for st in doc["Statement"]}
    assert by["Ec2ManageDcvInstances"]["Condition"]["StringEquals"]["aws:ResourceTag/dcv"] == "true"
    assert by["SsmSendCommandToDcv"]["Condition"]["StringEquals"]["ssm:resourceTag/dcv"] == "true"
    assert all(r.endswith(("role/dcv-*", "instance-profile/dcv-*")) for r in by["IamManageDcvRoles"]["Resource"])
    assert by["IamPassDcvRoles"]["Resource"].endswith("role/dcv-*")
    assert len(_j.dumps(doc, separators=(",", ":"))) < 10240


def test_new_role_name_must_have_prefix():
    import setup_service as s
    e = s.validate(plan(access={"profile_mode": "create", "role_name": "my-role", "key_name": "k"}))
    assert any("dcv-" in x for x in e)
    assert s.validate(plan(access={"profile_mode": "create", "role_name": "dcv-instance-role", "key_name": "k"})) == []
