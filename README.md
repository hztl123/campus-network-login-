# campus-network-login

深澜校园网自动登录脚本，支持开机自启、断网自动重连。

## 它能干什么

连上校园网 Wi-Fi 后自动帮你登录认证，不用每次打开浏览器手动输账号。两种运行模式：

- **一次性登录** — 运行一次，登完就退出
- **循环检测模式** — 一直在后台跑，检测到断网后自动重新登录

## 环境要求

- Windows（macOS/Linux 也能跑，只是没有 start.bat）
- Python 3.8+
- 连上校园网 Wi-Fi（不需要已经登录，连上信号就行）

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/hztl123/campus-network-login-.git
cd campus-network-login-
```

### 2. 安装依赖

```bash
pip install requests
```

就是这一个依赖，没有别的了。

### 3. 配置账号

```bash
# 复制配置模板
copy config.example.json config.json
```

然后打开 `config.json`，把 `username` 和 `password` 改成你自己的：

```json
{
    "username": "你的学号",
    "password": "你的密码",
    "domain": "@cmcc",
    ...
}
```

> **domain 说明：** `@cmcc` 是移动，`@unicom` 是联通，`@telecom` 是电信。看你办的哪个运营商的校园网套餐。

### 4. 运行

```bash
# 一次性登录
python login.py

# 循环检测模式（断网自动重连，每30秒检测一次）
python login.py --loop
```

## 开机自启

1. `Win + R`，输入 `shell:startup`，回车
2. 把 `start.bat` 创建快捷方式，拖进去
3. 搞定。下次开机自动开始循环检测

## 文件说明

```text
campus-network-login/
├── login.py              # 主脚本，登录逻辑
├── srun_encrypt.py       # 深澜 srun_bx1 加密算法
├── config.example.json   # 配置模板（提交到了仓库）
├── config.json           # 你的真实配置（已在 .gitignore 里忽略，不会上传）
├── start.bat             # 开机自启脚本
├── debug_js.js           # JS 版调试代码（供参考加密逻辑）
└── test_compare.js       # 对比测试脚本（校验 Python 加密结果和 JS 是否一致）
```

## 常见问题

### 运行后显示"无法获取本机 IP，是否连着校园网？"

检查 Wi-Fi 有没有连上校园网的信号。不需要已经登录，但必须连着 Wi-Fi。

### 登录失败，显示 "error=..."

常见原因：

- 账号或密码填错了
- `domain` 参数选错了（移动/联通/电信）
- 校园网套餐欠费了

### 密码是不是 base64 编码的？

脚本启动时会自动从 `config.json` 读取密码明文，然后 base64 编码后存回文件。所以你第一次填明文就行，脚本会自动处理。之后 `config.json` 里的密码会变成一串乱码，那是正常的。

### 我想改成每 60 秒检测一次

打开 `login.py`，找到 `loop_mode` 函数调用那行，把 `interval` 参数改成 60。
