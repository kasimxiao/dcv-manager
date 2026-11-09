"""DCV 权限特性目录：用于前端渲染丰富的权限编辑器。

每个分组: group(分组名), desc(分组说明)
每个特性: key(DCV特性名), label(中文名), desc(用途与风险说明), default(默认规则), min_version(可选)
规则取值: allow / disallow / deny
"""

FEATURE_GROUPS = [
    {
        "group": "剪贴板",
        "desc": "控制云桌面与本地电脑之间的复制粘贴。",
        "features": [
            {"key": "clipboard-copy", "label": "复制（服务器→客户端）", "default": "allow", "desc": "在云桌面里复制的文字、图片可以粘贴到本地电脑。禁止后内容无法通过剪贴板带出云桌面，是防止数据外泄的常用设置。"},
            {"key": "clipboard-paste", "label": "粘贴（客户端→服务器）", "default": "allow", "desc": "在本地电脑复制的内容可以粘贴到云桌面里。禁止后只能在云桌面内部复制粘贴。"},
        ],
    },
    {
        "group": "文件传输",
        "desc": "控制 DCV 客户端文件传输面板的上传和下载。",
        "features": [
            {"key": "file-download", "label": "下载文件", "default": "allow", "desc": "通过 DCV 客户端的文件传输面板，把云桌面里的文件下载到本地。禁止可防止数据被直接带走。"},
            {"key": "file-upload", "label": "上传文件", "default": "allow", "desc": "通过 DCV 客户端的文件传输面板，把本地文件上传到云桌面。禁止可防止外部文件（含病毒）进入。"},
        ],
    },
    {
        "group": "外设",
        "desc": "控制本地外接设备能否在云桌面中使用。开放越多越方便，数据外泄风险也越高。",
        "features": [
            {"key": "usb", "label": "USB 设备重定向", "default": "disallow", "desc": "本地插入的 USB 设备（U 盘、加密狗、扫描仪、专业 3D 鼠标、调试设备等）会出现在云桌面上，就像直接插在服务器上。只有安装版客户端支持，浏览器访问不可用。开启后可用 U 盘拷走数据，风险最高，建议只对确实需要加密狗或专用设备的人开放。普通键盘、鼠标、耳机不需要此项。"},
            {"key": "printer", "label": "打印机（PDF/XPS）", "default": "allow", "desc": "在云桌面里打印时，生成 PDF/XPS 文件发送到本地电脑，再由本地打印机打印。也可借此把文档转存到本地，涉密场景建议禁止。"},
            {"key": "smartcard", "label": "智能卡", "default": "disallow", "desc": "把本地读卡器中的智能卡，或走智能卡协议的 USB 证书钥匙（部分网银 U 盾、企业 PKI 证书 Key），传到云桌面使用，用于证书登录、文档或代码签名、访问需要证书认证的内网系统。只传证书数据，不暴露整个 USB 设备，比 USB 设备重定向更安全。"},
            {"key": "webcam", "label": "摄像头", "default": "disallow", "min_version": "2021.0", "desc": "云桌面里的视频会议等软件可以使用本地摄像头。"},
            {"key": "gamepad", "label": "游戏手柄", "default": "disallow", "min_version": "2022.0", "desc": "把本地游戏手柄传到云桌面，常用于游戏开发测试、仿真和驾驶模拟类软件。"},
            {"key": "stylus", "label": "手写笔/3D指针设备", "default": "disallow", "desc": "支持数位板、手写笔的压感和倾斜，以及 3D 指针设备，适合绘画、设计、三维建模。"},
        ],
    },
    {
        "group": "音频",
        "desc": "控制声音的输入和输出。",
        "features": [
            {"key": "audio-in", "label": "音频输入（麦克风）", "default": "allow", "desc": "本地麦克风的声音传到云桌面，用于语音会议、录音。"},
            {"key": "audio-out", "label": "音频输出（扬声器）", "default": "allow", "desc": "云桌面播放的声音传回本地扬声器或耳机。"},
        ],
    },
    {
        "group": "输入设备",
        "desc": "控制用户能否操作云桌面。全部禁止相当于只读观看。",
        "features": [
            {"key": "keyboard", "label": "键盘输入", "default": "allow", "desc": "允许用键盘输入。禁止后只能观看，不能打字。"},
            {"key": "keyboard-sas", "label": "Ctrl+Alt+Del 序列", "default": "allow", "desc": "允许向云桌面发送 Ctrl+Alt+Del，用于锁屏、打开任务管理器、修改密码。"},
            {"key": "mouse", "label": "鼠标输入", "default": "allow", "desc": "鼠标移动、点击和滚轮。禁止后无法用鼠标操作。"},
            {"key": "pointer", "label": "指针位置/形状", "default": "allow", "desc": "把云桌面的光标位置和形状同步到本地显示。禁止后本地看到的光标可能不准确。"},
            {"key": "touch", "label": "原生触控", "default": "allow", "desc": "在触摸屏设备上使用多点触控、手势操作云桌面。"},
        ],
    },
    {
        "group": "显示与截屏",
        "desc": "控制画面的接收和截屏保存。",
        "features": [
            {"key": "display", "label": "接收画面", "default": "allow", "desc": "接收云桌面的画面。禁止后看不到桌面，正常使用必须允许。"},
            {"key": "screenshot", "label": "截屏保存", "default": "allow", "min_version": "2021.2", "desc": "使用 DCV 客户端自带的截图功能把画面保存到本地。注意：无法阻止本地系统截图工具或手机拍屏，涉密场景需配合水印等管理手段。"},
        ],
    },
    {
        "group": "扩展与高级",
        "desc": "插件、网页身份验证和多人协作相关的高级能力。",
        "features": [
            {"key": "extensions-client", "label": "客户端扩展", "default": "allow", "desc": "允许在客户端运行基于 DCV 扩展开发包的第三方插件，插件通过 DCV 连接与服务器通信。普通用户用不到，受限场景可禁止，减少一个不受控的数据通道。"},
            {"key": "extensions-server", "label": "服务器扩展", "default": "allow", "desc": "允许在云桌面上运行基于 DCV 扩展开发包的第三方插件，与客户端插件配合使用。普通用户用不到，受限场景可禁止。"},
            {"key": "webauthn-redirection", "label": "WebAuthn 重定向", "default": "allow", "min_version": "2023.1", "desc": "在云桌面的浏览器里登录网站时，可以用本地的安全密钥、Windows Hello 或 Touch ID 做身份验证。"},
            {"key": "unsupervised-access", "label": "无人值守协作访问", "default": "disallow", "desc": "DCV 支持多人共享同一个桌面，所有人看到同一画面、键盘鼠标同时生效（会互相抢操作）。通常他人加入时属主会收到确认提示；开启此项后，有权限的人可以不经属主同意直接加入。建议保持禁止。"},
        ],
    },
]

# 扁平化所有特性 key
ALL_FEATURE_KEYS = [f["key"] for g in FEATURE_GROUPS for f in g["features"]]

# 默认权限规格：{feature_key: rule}
DEFAULT_SPEC = {f["key"]: f["default"] for g in FEATURE_GROUPS for f in g["features"]}

# 规则取值说明（前端图例使用）
RULE_DESC = {
    "allow": "放行该功能。",
    "disallow": "默认不放行，但可被其他规则（如针对特定用户的允许规则）放开。",
    "deny": "强制禁止，任何其他规则都无法放开，适用于涉密场景。",
}
