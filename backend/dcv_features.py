"""DCV 权限特性目录：用于前端渲染丰富的权限编辑器。

每个特性: key(DCV特性名), label(中文名), group(分组), default(默认规则), min_version(可选)
规则取值: allow / disallow / deny
"""

FEATURE_GROUPS = [
    {
        "group": "剪贴板",
        "features": [
            {"key": "clipboard-copy", "label": "复制（服务器→客户端）", "default": "allow"},
            {"key": "clipboard-paste", "label": "粘贴（客户端→服务器）", "default": "allow"},
        ],
    },
    {
        "group": "文件传输",
        "features": [
            {"key": "file-download", "label": "下载文件", "default": "allow"},
            {"key": "file-upload", "label": "上传文件", "default": "allow"},
        ],
    },
    {
        "group": "外设",
        "features": [
            {"key": "usb", "label": "USB 设备重定向", "default": "disallow"},
            {"key": "printer", "label": "打印机（PDF/XPS）", "default": "allow"},
            {"key": "smartcard", "label": "智能卡", "default": "disallow"},
            {"key": "webcam", "label": "摄像头", "default": "disallow", "min_version": "2021.0"},
            {"key": "gamepad", "label": "游戏手柄", "default": "disallow", "min_version": "2022.0"},
            {"key": "stylus", "label": "手写笔/3D指针设备", "default": "disallow"},
        ],
    },
    {
        "group": "音频",
        "features": [
            {"key": "audio-in", "label": "音频输入（麦克风）", "default": "allow"},
            {"key": "audio-out", "label": "音频输出（扬声器）", "default": "allow"},
        ],
    },
    {
        "group": "输入设备",
        "features": [
            {"key": "keyboard", "label": "键盘输入", "default": "allow"},
            {"key": "keyboard-sas", "label": "Ctrl+Alt+Del 序列", "default": "allow"},
            {"key": "mouse", "label": "鼠标输入", "default": "allow"},
            {"key": "pointer", "label": "指针位置/形状", "default": "allow"},
            {"key": "touch", "label": "原生触控", "default": "allow"},
        ],
    },
    {
        "group": "显示与截屏",
        "features": [
            {"key": "display", "label": "接收画面", "default": "allow"},
            {"key": "screenshot", "label": "截屏保存", "default": "allow", "min_version": "2021.2"},
        ],
    },
    {
        "group": "扩展与高级",
        "features": [
            {"key": "extensions-client", "label": "客户端扩展", "default": "allow"},
            {"key": "extensions-server", "label": "服务器扩展", "default": "allow"},
            {"key": "webauthn-redirection", "label": "WebAuthn 重定向", "default": "allow", "min_version": "2023.1"},
            {"key": "unsupervised-access", "label": "无人值守协作访问", "default": "disallow"},
        ],
    },
]

# 扁平化所有特性 key
ALL_FEATURE_KEYS = [f["key"] for g in FEATURE_GROUPS for f in g["features"]]

# 默认权限规格：{feature_key: rule}
DEFAULT_SPEC = {f["key"]: f["default"] for g in FEATURE_GROUPS for f in g["features"]}
