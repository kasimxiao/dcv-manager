"""S3 共享盘：IAM 策略生成、挂载参数、状态评估、存储层。"""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("AWS_REGION", "eu-central-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")

import share_service as ss  # noqa: E402

ROLE = "AROATESTROLEID"


@pytest.fixture(autouse=True)
def fake_role(monkeypatch):
    monkeypatch.setattr(ss, "role_id", lambda: ROLE)


def share(**kw):
    s = {"id": 7, "name": "设计素材", "bucket": "corp-design", "prefix": "", "region": "eu-central-1", "drive": "S",
         "mode": "rw", "scope": "selected", "cache_gb": 20, "kms_key": None, "target_ids": []}
    s.update(kw)
    return s


def stmt(doc, sid):
    return next(x for x in doc["Statement"] if x["Sid"] == sid)


# ---------------- IAM 策略 ----------------

def test_selected_scope_denies_everyone_not_listed():
    doc = ss.policy_documents(share(), ["i-b", "i-a"])[0]
    deny = stmt(doc, "OnlyAuthorizedServers")
    assert deny["Effect"] == "Deny"
    assert deny["Condition"]["StringNotEquals"]["aws:userid"] == [f"{ROLE}:i-a", f"{ROLE}:i-b"]
    assert {"s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"} <= set(deny["Action"])
    assert set(deny["Resource"]) == {"arn:aws:s3:::corp-design", "arn:aws:s3:::corp-design/*"}


def test_selected_scope_without_targets_grants_nothing():
    assert ss.policy_documents(share(), []) == []


def test_all_scope_has_no_deny():
    doc = ss.policy_documents(share(scope="all"), [])[0]
    assert not any(x["Effect"] == "Deny" for x in doc["Statement"])


def test_readonly_policy_cannot_write_or_delete():
    doc = ss.policy_documents(share(mode="ro"), ["i-a"])[0]
    acts = stmt(doc, "Objects")["Action"]
    assert "s3:GetObject" in acts
    assert not {"s3:PutObject", "s3:DeleteObject"} & set(acts)
    rw = stmt(ss.policy_documents(share(mode="rw"), ["i-a"])[0], "Objects")["Action"]
    assert {"s3:PutObject", "s3:DeleteObject"} <= set(rw)


def test_prefix_limits_objects_listing_and_deny():
    doc = ss.policy_documents(share(prefix="projects/2026"), ["i-a"])[0]
    objs = ["arn:aws:s3:::corp-design/projects/2026/*", "arn:aws:s3:::corp-design/projects/2026"]
    assert stmt(doc, "Objects")["Resource"] == objs
    like = ["projects/2026", "projects/2026/", "projects/2026/*"]
    assert stmt(doc, "List")["Condition"]["StringLike"]["s3:prefix"] == like
    deny = stmt(doc, "OnlyAuthorizedServers")
    # 拒绝只作用于本路径：对象资源限定在前缀内，列举按前缀匹配
    assert set(deny["Resource"]) == {"arn:aws:s3:::corp-design", *objs}
    assert deny["Condition"]["StringLikeIfExists"]["s3:prefix"] == like


def test_policy_fits_size_limit_at_max_servers():
    ids = [f"i-{n:017x}" for n in range(ss.MAX_TARGETS_PER_POLICY)]
    docs = ss.policy_documents(share(prefix="a/b", kms_key="arn:aws:kms:eu-central-1:111122223333:key/abcd"), ids)
    assert len(docs) == 1 and len(json.dumps(docs[0], separators=(",", ":"))) < 6144
    with pytest.raises(ValueError, match="全部服务器"):
        ss.policy_documents(share(), ids + ["i-extra"])


def test_kms_statement_only_when_key_set():
    assert not any(x["Sid"] == "Kms" for x in ss.policy_documents(share(), ["i-a"])[0]["Statement"])
    d = ss.policy_documents(share(kms_key="arn:aws:kms:eu-central-1:1:key/k"), ["i-a"])[0]
    assert stmt(d, "Kms")["Resource"] == "arn:aws:kms:eu-central-1:1:key/k"


# ---------------- 校验 ----------------

@pytest.mark.parametrize("p,ok", [("", True), ("/a/b/", True), ("a/../b", False), ("a\\b", False), ("a*", False)])
def test_clean_prefix(p, ok):
    if ok:
        assert ss.clean_prefix(p) == p.strip("/")
    else:
        with pytest.raises(ValueError):
            ss.clean_prefix(p)


def test_validate_rejects_conflicts():
    other = share(id=1, name="已有", drive="T", bucket="bkt1", prefix="x")
    ss.validate(share(drive="S"), [other])
    with pytest.raises(ValueError, match="盘符"):
        ss.validate(share(drive="T"), [other])
    for p in ("x", "x/sub", "", ):
        with pytest.raises(ValueError, match="重叠"):
            ss.validate(share(bucket="bkt1", prefix=p), [other])
    ss.validate(share(bucket="bkt1", prefix="xy"), [other])   # 仅名称前缀相同、不是子路径，允许
    ss.validate(share(bucket="bkt1", prefix="y"), [other])
    for bad in ({"drive": "C"}, {"bucket": "Bad_Name"}, {"mode": "x"}, {"cache_gb": 0}):
        with pytest.raises(ValueError):
            ss.validate(share(**bad), [])


# ---------------- 挂载参数 ----------------

def test_mount_args_readonly_and_permissions():
    ro = ss.mount_args(share(mode="ro"))
    assert "--read-only" in ro and "FileSecurity=D:P(A;;FRFX;;;WD)" in ro
    rw = ss.mount_args(share(mode="rw"))
    assert "--read-only" not in rw and "FileSecurity=D:P(A;;FA;;;WD)" in rw
    assert rw[1] == "share7:corp-design" and rw[2] == "S:"
    assert ss.mount_args(share(prefix="p/q"))[1] == "share7:corp-design/p/q"


def test_host_config_has_no_secrets_and_hash_tracks_changes():
    h = ss.host_spec(share())
    text = "\n".join(h["conf"])
    assert "env_auth = true" in text and "secret" not in text.lower() and "access_key" not in text
    assert ss.host_spec(share(cache_gb=50))["hash"] != h["hash"]
    assert ss.host_spec(share(name="改名"))["hash"] != h["hash"]  # 卷标变化需重新挂载
    assert ss.host_spec(share())["hash"] == h["hash"]


def test_sync_script_is_single_block_and_embeds_payload():
    cmds = ss.sync_commands([share()])
    assert len(cmds) == 1
    assert "__B64__" not in cmds[0] and "__ROOT__" not in cmds[0]
    assert ss.RCLONE_SHA256 in json.dumps(ss._host_payload([share()]))


# ---------------- 状态评估 ----------------

RUN = {"instance_id": "i-a", "state": "running", "ssm": "Online", "iam_profile": "dcv-instance-role"}


@pytest.fixture(autouse=True)
def _profile(monkeypatch):
    import share_service
    monkeypatch.setattr(share_service, "LAUNCH_PROFILE", "dcv-instance-role")


def insp_with(*shares):
    return {"dcv_service": "Running", "shares": list(shares)}


def test_evaluate_ok_missing_outdated_failed():
    s = share(target_ids=["i-a"])
    good = {"id": 7, "hash": ss.host_spec(s)["hash"], "drive": "S", "mounted": True, "pending": 0, "last_error": ""}
    rows, drift, alerts = ss.evaluate(RUN, insp_with(good), [s])
    assert rows[0]["status"] == "ok" and not drift and not alerts
    rows, drift, _ = ss.evaluate(RUN, insp_with(), [s])
    assert rows[0]["status"] == "missing" and drift
    rows, drift, _ = ss.evaluate(RUN, insp_with({**good, "hash": "old"}), [s])
    assert rows[0]["status"] == "outdated" and drift
    rows, drift, alerts = ss.evaluate(RUN, insp_with({**good, "mounted": False, "last_error": "AccessDenied"}), [s])
    assert rows[0]["status"] == "failed" and drift and "AccessDenied" in alerts[0][1]


def test_evaluate_unauthorized_mount_triggers_removal():
    rows, drift, alerts = ss.evaluate(RUN, insp_with({"id": 99, "hash": "x", "drive": "Q", "mounted": True}), [])
    assert rows == [] and drift and "未授权" in alerts[0][1]


def test_evaluate_not_targeted_and_stopped():
    s = share(target_ids=["i-other"])
    assert ss.evaluate(RUN, insp_with(), [s]) == ([], False, [])
    rows, drift, _ = ss.evaluate({**RUN, "state": "stopped"}, None, [share(scope="all")])
    assert rows[0]["status"] == "stopped" and not drift


def test_evaluate_old_inspection_without_share_data_is_unknown():
    rows, drift, _ = ss.evaluate(RUN, {"dcv_service": "Running"}, [share(scope="all")])
    assert rows[0]["status"] == "unknown" and not drift


def test_evaluate_warns_wrong_instance_role():
    _, _, alerts = ss.evaluate({**RUN, "iam_profile": "other-profile"}, insp_with(), [share(scope="all")])
    assert any("实例角色" in a[1] for a in alerts)


# ---------------- 存储层 ----------------

def test_share_store_roundtrip(monkeypatch):
    path = tempfile.mktemp(suffix=".db")
    import config
    import db
    monkeypatch.setattr(config, "DB_PATH", path)
    monkeypatch.setattr(db, "DB_PATH", path)
    import store
    db.init_db()
    store.init()
    sid = store.create_share("admin", name="n", bucket="b", prefix="", region="r", drive="S", mode="rw", scope="selected", cache_gb=20)
    store.add_share_targets(sid, ["i-1", "i-2", "i-1"], "admin")
    store.remove_share_targets(sid, ["i-2"])
    store.update_share(sid, "admin", mode="ro", policy_arn='["arn:x"]')
    s = store.list_shares()[0]
    assert s["target_ids"] == ["i-1"] and s["mode"] == "ro" and s["policy_arn"] == '["arn:x"]'
    store.delete_share(sid)
    assert store.list_shares() == []
    os.remove(path)
