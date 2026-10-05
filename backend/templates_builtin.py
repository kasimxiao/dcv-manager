"""内置企业级 DCV 权限模板。

每个模板只列出与"全部允许"不同的项；未列出的功能默认允许。
规则：allow 允许 / disallow 默认禁止 / deny 强制禁止（不可被其他规则放开）。
"""
from dcv_features import ALL_FEATURE_KEYS

# 基础交互能力：任何模板都保留，否则无法正常使用桌面
_BASE_INPUT = ["display", "keyboard", "keyboard-sas", "mouse", "pointer", "touch"]

# 外设类（高风险数据通道）
_PERIPHERALS = ["usb", "smartcard", "webcam", "gamepad", "stylus"]
_DATA_OUT = ["clipboard-copy", "file-download", "printer", "screenshot"]
_DATA_IN = ["clipboard-paste", "file-upload"]


def _spec(overrides: dict) -> dict:
    s = {k: "allow" for k in ALL_FEATURE_KEYS}
    s.update(overrides)
    return s


BUILTIN_TEMPLATES = [
    {
        "key": "standard-office",
        "name": "标准办公",
        "description": "日常办公场景：允许剪贴板、文件传输、打印和音频；禁止 USB 等外设重定向与无人值守访问。",
        "level": "低",
        "spec": _spec({
            **{k: "disallow" for k in ["usb", "smartcard", "gamepad", "stylus"]},
            "unsupervised-access": "deny",
        }),
    },
    {
        "key": "design-workstation",
        "name": "设计/图形工作站",
        "description": "3D 设计、视频剪辑：额外开放手写笔/数位板、手柄、摄像头与 USB 设备，满足专业外设需求。",
        "level": "低",
        "spec": _spec({"smartcard": "disallow", "unsupervised-access": "deny"}),
    },
    {
        "key": "dev-test",
        "name": "研发测试",
        "description": "研发人员：允许剪贴板与文件双向传输、USB 调试设备；禁止打印与摄像头。",
        "level": "中",
        "spec": _spec({
            "printer": "disallow", "webcam": "disallow", "smartcard": "disallow",
            "gamepad": "disallow", "stylus": "disallow", "unsupervised-access": "deny",
        }),
    },
    {
        "key": "outsourcing-restricted",
        "name": "外包/第三方受限",
        "description": "外包或临时人员：数据只进不出。允许向服务器粘贴和上传，禁止复制、下载、打印、截屏和全部外设。",
        "level": "高",
        "spec": _spec({
            **{k: "deny" for k in _DATA_OUT},
            **{k: "deny" for k in _PERIPHERALS},
            "unsupervised-access": "deny",
            "extensions-client": "disallow", "extensions-server": "disallow",
        }),
    },
    {
        "key": "high-security",
        "name": "高安全涉密",
        "description": "涉密/核心数据：仅保留画面、键鼠与音频输出。数据进出通道与全部外设均强制禁止，不可被其他规则放开。",
        "level": "最高",
        "spec": _spec({
            **{k: "deny" for k in _DATA_OUT + _DATA_IN + _PERIPHERALS},
            "audio-in": "deny",
            "unsupervised-access": "deny",
            "extensions-client": "deny", "extensions-server": "deny",
            "webauthn-redirection": "disallow",
        }),
    },
]

for _t in BUILTIN_TEMPLATES:
    for _k in _BASE_INPUT:
        _t["spec"][_k] = "allow"
