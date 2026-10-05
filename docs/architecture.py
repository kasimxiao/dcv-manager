"""生成 README 中的 AWS 架构图：docs/architecture.png

用法：.venv/bin/pip install diagrams==0.24.4 && .venv/bin/python docs/architecture.py
依赖 Graphviz（macOS：brew install graphviz）。
"""
import os

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import EC2, EC2Ami, Lambda
from diagrams.aws.general import Users
from diagrams.aws.integration import Eventbridge
from diagrams.aws.management import Cloudtrail, Cloudwatch, SystemsManager
from diagrams.aws.network import CloudFront, NATGateway
from diagrams.aws.security import Cognito
from diagrams.aws.storage import S3

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture")
FONT = "PingFang SC"


def box(color):
    return {"fontname": FONT, "fontsize": "14", "bgcolor": color, "pencolor": "#9aa7b4", "margin": "18"}


graph_attr = {"fontname": FONT, "fontsize": "22", "pad": "0.5", "nodesep": "0.7", "ranksep": "1.3",
              "splines": "spline", "labelloc": "t"}
node_attr = {"fontname": FONT, "fontsize": "12", "height": "2.3", "imagepos": "tc", "labelloc": "b"}
edge_attr = {"fontname": FONT, "fontsize": "12", "penwidth": "1.6"}

CTRL = dict(color="#1f6feb", fontcolor="#1f6feb")     # 管理控制面（蓝）
MANAGED = dict(color="#d4860b", fontcolor="#b36b00")  # AWS 托管执行（橙）
DATA = dict(color="#2da44e", fontcolor="#1a7f37")     # 用户数据面（绿）
AUX = dict(color="#8c959f", fontcolor="#6e7781", style="dashed")

with Diagram("DCV 企业管理平台 · AWS 架构", filename=OUT, show=False, direction="LR", outformat="png",
             graph_attr=graph_attr, node_attr=node_attr, edge_attr=edge_attr):

    with Cluster("用户", graph_attr=box("#ffffff")):
        admin = Users("管理员 / 运维\n浏览器")
        enduser = Users("云桌面用户\nDCV 客户端")

    with Cluster("平台所在区域（例如 eu-central-1）", graph_attr=box("#f3f7ff")):
        cf = CloudFront("CloudFront\nHTTPS 入口")
        cognito = Cognito("Cognito\n用户与角色")
        with Cluster("平台 VPC（新建或使用已有）", graph_attr=box("#e6efff")):
            platform = EC2("平台服务器 t4g.small\n私有子网 · 无公网 IP\nFastAPI + SQLite")
            NATGateway("NAT 网关\n访问 AWS API")
        deploy_bucket = S3("部署存储桶\n平台代码包")

    with Cluster("每个管理区域（可多个）", graph_attr=box("#f4fbf4")):
        ssm = SystemsManager("Systems Manager\n远程命令")
        with Cluster("托管组件（初始化向导部署）", graph_attr=box("#fff6e5")):
            scheduler = Eventbridge("EventBridge Scheduler\n定时开关机")
            power_fn = Lambda("Lambda dcv-power\n托管开机 · 备选机型")
            rules = Eventbridge("EventBridge 规则\n实例状态变化")
            logs = Cloudwatch("CloudWatch Logs\n运行历史")
        with Cluster("DCV VPC · 公有子网 × 多个可用区", graph_attr=box("#e3f6e3")):
            server = EC2("Windows GPU 服务器 × N\ng6f / g4dn / g5\nDCV · 标准用户 dcvuser")
        ami = EC2Ami("快照 AMI\n标准环境")
        trail = Cloudtrail("CloudTrail\n开机失败记录")

    share = S3("S3 共享盘\nrclone 挂载为盘符")

    # 管理控制面
    admin >> Edge(label="HTTPS", **CTRL) >> cf
    cf >> Edge(label="VPC 源站", **CTRL) >> platform
    platform >> Edge(label="登录校验", **CTRL) >> cognito
    deploy_bucket >> Edge(label="部署 / 更新", **AUX) >> platform
    platform >> Edge(label="下发权限 · 巡检 · 挂载 · 改密", **CTRL) >> ssm
    ssm >> Edge(label="以 SYSTEM 执行", **CTRL) >> server
    platform >> Edge(label="创建定时任务", **CTRL) >> scheduler
    platform >> Edge(label="容量判断", **AUX) >> trail
    ami >> Edge(label="批量创建", **AUX) >> server

    # AWS 托管执行（与平台是否在线无关）
    scheduler >> Edge(label="开机", **MANAGED) >> power_fn
    power_fn >> Edge(label="开机 / 换备选机型", **MANAGED) >> server
    server >> Edge(label="状态变化", **MANAGED) >> rules
    rules >> Edge(label="写入", **MANAGED) >> logs
    rules >> Edge(label="停止后改回机型", **MANAGED) >> power_fn

    # 用户数据面（不经过平台）
    enduser >> Edge(label="DCV 8443 TCP/UDP", **DATA) >> server
    server >> Edge(label="读写文件", **DATA) >> share
