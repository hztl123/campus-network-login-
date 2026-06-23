"""
login.py — 深澜校园网自动登录脚本

用法：
    python login.py           # 手动执行一次登录
    python login.py --loop    # 循环检测模式（断网自动重连）

开机自启：将 start.bat 放入 Windows 启动文件夹
    Win+R → shell:startup → 放入 start.bat 快捷方式
"""

import base64
import json
import socket
import sys
import time

import requests

from srun_encrypt import (
    get_md5,
    make_checksum,
    make_encrypted_info,
)


# ============================================================
# 配置加载
# ============================================================
def load_config(path: str = "config.json") -> dict:
    """加载配置文件，解码密码"""
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # 解码 base64 密码
    config["password"] = base64.b64decode(config["password"]).decode("utf-8")
    return config


# ============================================================
# 网络工具
# ============================================================
def _parse_jsonp(text: str) -> dict | None:
    """从 JSONP 响应中提取 JSON 对象"""
    start = text.find("(")
    end = text.rfind(")")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start + 1:end])
    except json.JSONDecodeError:
        return None


def get_local_ip(config: dict) -> str:
    """获取本机在校园网中的 IP 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((config["portal_host"], 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


def is_online(config: dict) -> tuple[bool, dict | None]:
    """
    检测是否已经登录校园网
    返回 (是否在线, 在线信息或None)
    """
    url = f"http://{config['portal_host']}/cgi-bin/rad_user_info"
    try:
        resp = requests.get(url, timeout=5)
        data = _parse_jsonp(resp.text)
        if data and data.get("error") == "ok":
            return True, data
    except Exception:
        pass
    return False, None


# ============================================================
# 登录核心
# ============================================================
def get_token(config: dict, username: str, ip: str) -> tuple[str, str]:
    """
    获取挑战码 token 和服务器看到的客户端 IP
    GET /cgi-bin/get_challenge?callback=...&username=...&ip=...

    返回 (token, client_ip)
    """
    url = f"http://{config['portal_host']}/cgi-bin/get_challenge"
    params = {
        "callback": "jsonp",
        "username": username,
        "ip": ip,
    }
    resp = requests.get(url, params=params, timeout=5)
    data = _parse_jsonp(resp.text)
    if not data:
        raise RuntimeError(f"获取 token 失败，响应：{resp.text[:200]}")

    token = data.get("challenge", "")
    if not token:
        raise RuntimeError(f"token 为空，响应：{data}")

    # ← 关键：用服务器看到的 client_ip，不要用自检 IP
    client_ip = data.get("client_ip", ip)
    return token, client_ip


def do_login(config: dict) -> bool:
    """
    执行一次完整的登录流程

    返回 True 表示登录成功
    """
    # 1. 组装用户名
    username = config["username"] + config["domain"]
    password = config["password"]
    ac_id = config["ac_id"]
    n = config["n"]
    type_ = config["type"]
    enc_ver = config["enc_ver"]

    print(f"[*] 用户名: {username}")

    # 2. 先检查是否已经在线
    online, info = is_online(config)
    if online:
        used = info.get("sum_bytes", 0)
        used_gb = used / 1024 / 1024 / 1024
        print(f"[OK] 已经在线，无需重复登录")
        print(f"    流量已用: {used_gb:.2f} GB")
        print(f"    在线 IP: {info.get('online_ip', '?')}")
        return True

    print("[*] 未登录，开始认证...")

    # 3. 获取 token 和真实 IP（两步：先用本地IP拿client_ip，再用client_ip拿有效token）
    local_ip = get_local_ip(config)
    if not local_ip:
        print("[!] 无法获取本机 IP，是否连着校园网？")
        return False

    try:
        # 第一步：用本地IP获取服务器看到的真实 client_ip
        _, real_ip = get_token(config, username, local_ip)
        print(f"[*] 服务器看到的 IP: {real_ip}")

        # 第二步：用真实 IP 重新获取有效 token
        token, _ = get_token(config, username, real_ip)
        print(f"[*] 获取 token 成功: {token[:10]}...")
    except Exception as e:
        print(f"[!] 获取 token 失败: {e}")
        return False

    ip = real_ip

    # 4. 加密
    #    hmd5 = MD5(token + password)
    hmd5 = get_md5(password, token)

    #    用户信息加密
    enc_info = make_encrypted_info(
        username=username,
        password=password,
        ip=ip,
        ac_id=ac_id,
        enc_ver=enc_ver,
        token=token,
    )

    #    校验和
    chksum = make_checksum(
        token=token,
        username=username,
        hmd5=hmd5,
        ac_id=ac_id,
        ip=ip,
        n=n,
        type_=type_,
        enc_info=enc_info,
    )

    # 5. 发送登录请求
    url = f"http://{config['portal_host']}/cgi-bin/srun_portal"
    params = {
        "callback": "jsonp",
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5,
        "os": config["os"],
        "name": config["name"],
        "double_stack": 0,
        "chksum": chksum,
        "info": enc_info,
        "ac_id": ac_id,
        "ip": ip,
        "n": n,
        "type": type_,
    }

    try:
        resp = requests.get(url, params=params, timeout=10)
        print(f"[*] 服务器响应: {resp.text[:300]}")
    except Exception as e:
        print(f"[!] 请求失败: {e}")
        return False

    # 6. 解析结果
    data = _parse_jsonp(resp.text)
    if data:
        error = data.get("error", "")
        if error == "ok":
            print("[OK] 登录成功！")
            return True
        else:
            suc_msg = data.get("suc_msg", "")
            print(f"[!] 登录失败: error={error}, suc_msg={suc_msg}")
            return False

    print(f"[!] 无法解析服务器响应: {resp.text[:200]}")
    return False


def loop_mode(config: dict, interval: int = 30):
    """
    循环检测模式：每隔 interval 秒检测一次，断网自动重连
    """
    print(f"[*] 进入循环检测模式，间隔 {interval} 秒")
    print("[*] 按 Ctrl+C 退出\n")

    while True:
        try:
            online, _ = is_online(config)
            if online:
                print(f"[{time.strftime('%H:%M:%S')}] 在线，无需操作")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] 断网了，尝试重新登录...")
                do_login(config)
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] 退出")
            break
        except Exception as e:
            print(f"[!] 出错: {e}，{interval}秒后重试")
            time.sleep(interval)


# ============================================================
# 主入口
# ============================================================
def main():
    # 工作目录切换到脚本所在目录（确保能找到 config.json）
    import os
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    config = load_config("config.json")
    loop = "--loop" in sys.argv

    if loop:
        loop_mode(config)
    else:
        success = do_login(config)
        if success:
            print("\n[*] 完成。")
        else:
            print("\n[!] 登录失败，请检查账号密码或网络连接。")
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
