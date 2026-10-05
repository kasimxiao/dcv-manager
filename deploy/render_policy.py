"""从 platform.yaml 导出平台角色的最小权限策略，生成 deploy/platform-role-policy.json。

用于不使用本仓库 CloudFormation、手工创建平台角色的场景：把文件中的占位符替换为实际值后，
作为内联策略附加到平台服务器的实例角色上。
  ${AWS::AccountId}   AWS 账号 ID
  ${ArtifactBucket}   部署存储桶名称（仅用 deploy.sh 部署时需要）
  ${UserPool.Arn}     平台 Cognito 用户池 ARN
另需附加托管策略 arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore（平台服务器自身接受 SSM 管理）。

用法：python deploy/render_policy.py            # 生成 / 更新 JSON
      python deploy/render_policy.py --check    # 检查 JSON 是否与模板一致（CI / 单元测试用）
"""
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "platform.yaml")
OUT = os.path.join(HERE, "platform-role-policy.json")


class _Loader(yaml.SafeLoader):
    pass


def _tag(name):
    def ctor(loader, node):
        if isinstance(node, yaml.ScalarNode):
            v = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            v = loader.construct_sequence(node, deep=True)
        else:
            v = loader.construct_mapping(node, deep=True)
        if name == "Sub":
            return v if isinstance(v, str) else v[0]
        if name == "GetAtt":
            return "${" + (v if isinstance(v, str) else ".".join(v)) + "}"
        if name == "Ref":
            return "${" + v + "}"
        return {f"Fn::{name}": v}
    return ctor


for t in ("Sub", "GetAtt", "Ref", "If", "Join", "Select", "Cidr", "GetAZs", "Equals", "Base64"):
    _Loader.add_constructor(f"!{t}", _tag(t))


def render():
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = yaml.load(f, Loader=_Loader)
    pol = next(p for p in tpl["Resources"]["PlatformRole"]["Properties"]["Policies"] if p["PolicyName"] == "dcv-manager-platform")
    return pol["PolicyDocument"]


def dump(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


if __name__ == "__main__":
    text = dump(render())
    if "--check" in sys.argv:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != text:
            sys.exit("platform-role-policy.json 与 platform.yaml 不一致，请运行 python deploy/render_policy.py")
        print("一致")
    else:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write(text)
        size = len(json.dumps(render(), separators=(",", ":")))
        print(f"已生成 {OUT}（{len(render()['Statement'])} 条语句，压缩后 {size} 字符，IAM 内联策略上限 10240）")
