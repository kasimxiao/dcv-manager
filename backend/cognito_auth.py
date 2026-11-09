"""AWS Cognito 认证与用户管理。

- 登录：USER_PASSWORD_AUTH，返回 IdToken
- 校验：用 Cognito JWKS 验签 IdToken（RS256），校验 iss / aud / token_use / exp
- 用户管理：基于 cognito-idp admin API（增删用户、重置口令、列表）
"""

import jwt
from jwt import PyJWKClient

import boto3
from config import COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, COGNITO_REGION

_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)

_ISS = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
_JWKS_URL = f"{_ISS}/.well-known/jwks.json"
_jwk_client = None


def _jwks():
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(_JWKS_URL)
    return _jwk_client


def login(username: str, password: str) -> dict:
    """返回 {token, username}；失败抛异常。"""
    resp = _client.initiate_auth(
        ClientId=COGNITO_CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    if resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
        return {"challenge": "NEW_PASSWORD_REQUIRED", "session": resp["Session"], "username": username}
    if "ChallengeName" in resp:
        raise ValueError(f"需要额外验证: {resp['ChallengeName']}")
    r = resp["AuthenticationResult"]
    claims = verify(r["IdToken"])
    return {"token": r["IdToken"], "username": username, "role": role_from_claims(claims)}


def complete_new_password(username: str, session: str, new_password: str) -> dict:
    resp = _client.respond_to_auth_challenge(
        ClientId=COGNITO_CLIENT_ID, ChallengeName="NEW_PASSWORD_REQUIRED", Session=session,
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_password})
    r = resp["AuthenticationResult"]
    claims = verify(r["IdToken"])
    return {"token": r["IdToken"], "username": username, "role": role_from_claims(claims)}


def verify(token: str) -> dict:
    """校验 IdToken，返回 claims；失败抛异常。"""
    signing_key = _jwks().get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=COGNITO_CLIENT_ID,
        issuer=_ISS,
        leeway=30,  # 容忍本机与 Cognito 之间的时钟偏差，避免刚签发的令牌因 iat 略超前被拒
        options={"require": ["exp", "iss", "aud"]},
    )
    if claims.get("token_use") != "id":
        raise ValueError("token_use 非法")
    return claims


# ---------------- 用户管理 ----------------
# 与 deploy/platform.yaml 中用户池的密码策略一致；先在本地校验，给出明确提示，
# 也避免「用户已建好、设置密码失败」留下半成品用户。
PASSWORD_HINT = "至少 12 位，需包含大写字母、小写字母、数字和符号"
_SYMBOLS = set("^$*.[]{}()?\"!@#%&/\\,><':;|_~`=+- ")


def check_password(pw: str):
    pw = pw or ""
    if (len(pw) < 12 or not any(c.isupper() for c in pw) or not any(c.islower() for c in pw)
            or not any(c.isdigit() for c in pw) or not any(c in _SYMBOLS for c in pw)):
        raise ValueError(f"密码不符合要求：{PASSWORD_HINT}")


ROLES = ["admin", "operator", "viewer", "desktop"]  # 对应 Cognito 用户组；权限从高到低（desktop：桌面用户，只能开关分配给自己的服务器）


def role_from_claims(claims: dict) -> str:
    groups = claims.get("cognito:groups") or []
    for r in ROLES:
        if r in groups:
            return r
    return "viewer"  # 未分组的用户默认只读


def _user_role(username):
    groups = [g["GroupName"] for g in _client.admin_list_groups_for_user(
        UserPoolId=COGNITO_USER_POOL_ID, Username=username).get("Groups", [])]
    for r in ROLES:
        if r in groups:
            return r
    return "viewer"


def set_role(username: str, role: str):
    if role not in ROLES:
        raise ValueError("角色不合法")
    for r in ROLES:
        if r != role:
            try:
                _client.admin_remove_user_from_group(UserPoolId=COGNITO_USER_POOL_ID, Username=username, GroupName=r)
            except Exception:  # noqa: BLE001
                pass
    _client.admin_add_user_to_group(UserPoolId=COGNITO_USER_POOL_ID, Username=username, GroupName=role)


def count_admins() -> int:
    n, token = 0, None
    while True:
        kw = {"UserPoolId": COGNITO_USER_POOL_ID, "GroupName": "admin", "Limit": 60}
        if token:
            kw["NextToken"] = token
        resp = _client.list_users_in_group(**kw)
        n += sum(1 for u in resp.get("Users", []) if u.get("Enabled", True))
        token = resp.get("NextToken")
        if not token:
            return n


def list_users() -> list:
    out = []
    paginator = _client.get_paginator("list_users")
    for page in paginator.paginate(UserPoolId=COGNITO_USER_POOL_ID):
        for u in page.get("Users", []):
            attrs = {a["Name"]: a["Value"] for a in u.get("Attributes", [])}
            out.append({
                "username": u.get("Username"),
                "status": u.get("UserStatus"),
                "enabled": u.get("Enabled", True),
                "email": attrs.get("email", ""),
                "created": u.get("UserCreateDate").isoformat() if u.get("UserCreateDate") else None,
                "role": _user_role(u.get("Username")),
            })
    out.sort(key=lambda x: x["username"])
    return out


def create_user(username: str, password: str, email: str = "", role: str = "viewer") -> dict:
    check_password(password)
    if role not in ROLES:
        raise ValueError("角色不合法")
    attrs = []
    if email:
        attrs = [{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}]
    _client.admin_create_user(
        UserPoolId=COGNITO_USER_POOL_ID,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    try:
        _client.admin_set_user_password(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username,
            Password=password,
            Permanent=True,
        )
        set_role(username, role)
    except Exception:
        # 回滚：不留下没有密码、没有角色的半成品用户（未分组用户会被当作只读）
        try:
            _client.admin_delete_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)
        except Exception:  # noqa: BLE001
            pass
        raise
    return {"username": username, "role": role}


def set_password(username: str, password: str):
    check_password(password)
    _client.admin_set_user_password(
        UserPoolId=COGNITO_USER_POOL_ID, Username=username, Password=password, Permanent=True
    )


def delete_user(username: str):
    _client.admin_delete_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)


def set_enabled(username: str, enabled: bool):
    if enabled:
        _client.admin_enable_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)
    else:
        _client.admin_disable_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)


def change_own_password(username: str, old_password: str, new_password: str):
    """用户自助改密：先用原密码换取 AccessToken，再调用 ChangePassword。"""
    try:
        resp = _client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": old_password},
        )
    except _client.exceptions.NotAuthorizedException:
        raise ValueError("原密码错误")
    check_password(new_password)
    access = resp["AuthenticationResult"]["AccessToken"]
    try:
        _client.change_password(PreviousPassword=old_password, ProposedPassword=new_password, AccessToken=access)
    except _client.exceptions.InvalidPasswordException:
        raise ValueError(f"新密码不符合要求：{PASSWORD_HINT}")
    except _client.exceptions.LimitExceededException:
        raise ValueError("尝试次数过多，请稍后再试")
