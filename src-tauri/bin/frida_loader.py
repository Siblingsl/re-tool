import frida
import sys
import time
import signal
import threading
import os
import json

# =========================
# UTF-8 强制输出
# =========================
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# =========================
# Socket.IO 配置
# =========================
SESSION_ID = os.environ.get("SESSION_ID", "")
COMMAND_ID = os.environ.get("COMMAND_ID", "")
CLOUD_URL = os.environ.get("CLOUD_URL", "http://127.0.0.1:3000")

sio = None
try:
    import socketio
    sio = socketio.Client()
    sio.connect(f"{CLOUD_URL}?sessionId={SESSION_ID}")
except Exception as e:
    print(f"[Loader] ⚠️ Socket connect failed: {e}")

def emit_socket(event, payload):
    if sio:
        try:
            sio.emit(event, payload)
        except:
            pass

def emit_frida_log(text):
    emit_socket("frida_log", {
        "sessionId": SESSION_ID,
        "log": text
    })

def emit_command_result(status, data=None):
    emit_socket("command_result", {
        "id": COMMAND_ID,
        "status": status,
        "data": data or ""
    })

def print_flush(*args):
    msg = " ".join(str(a) for a in args)
    print(msg, flush=True)

    # 🔥 socket 通道（如果可用）
    emit_frida_log(msg)

# =========================
# 生命周期控制
# =========================
running = True

def handler(signum, frame):
    global running
    print_flush("[Loader] Stopping...")
    running = False
    emit_command_result("ERROR", "FRIDA_STOPPED")
    sys.exit(0)

signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

# =========================
# 主逻辑
# =========================
def main():
    global running

    if len(sys.argv) < 6:
        print_flush("[Loader] Usage: python frida_loader.py <device_id> <package> <script_path> <mode> <anti_detect>")
        sys.exit(1)

    device_id = sys.argv[1]
    package = sys.argv[2]
    script_path = sys.argv[3]
    mode = sys.argv[4]
    anti_detect = sys.argv[5].lower() == 'true'

    print_flush(f"[Loader] Starting: {package}, Mode: {mode}, AntiDetect: {anti_detect}")

    try:
        # =========================
        # 1. 连接设备
        # =========================
        if device_id and device_id not in ("", "null"):
            try:
                device = frida.get_device(device_id)
            except:
                device = frida.get_usb_device()
        else:
            device = frida.get_usb_device()

        print_flush(f"[Loader] Connected to device: {device.name}")

        # =========================
        # 2. 加载脚本
        # =========================
        with open(script_path, "r", encoding="utf-8") as f:
            user_script = f.read()

        session = None
        script = None

        # =========================
        # 3. Frida 消息处理
        # =========================
        def on_message(message, data):
            try:
                if message["type"] == "send":
                    payload = message.get("payload", "")
                    if isinstance(payload, dict):
                        payload = json.dumps(payload, ensure_ascii=False)
                    print_flush(payload)
                elif message["type"] == "log":
                    print_flush(message.get("payload", ""))
                elif message["type"] == "error":
                    print_flush(f"[Script Error] {message.get('description')}")
                    stack = message.get("stack")
                    if stack:
                        print_flush(stack)
            except Exception as e:
                print_flush(f"[Message Handler Error] {e}")

        def on_console(level, text):
            print_flush(f"[Frida] {text}")

        # =========================
        # 4. Spawn / Attach
        # =========================
        if mode == "spawn":
            print_flush(f"[Loader] Spawning {package}...")
            pid = device.spawn([package])
            print_flush(f"[Loader] Spawned PID: {pid}")

            session = device.attach(pid)
            print_flush("[Loader] Session attached")

            script = session.create_script(user_script)
            script.on("message", on_message)
            try:
                script.on("console", on_console)
            except:
                pass

            script.load()
            print_flush("[Loader] ✅ Script loaded (early)")

            print_flush("[Frida] ▶️ Resuming app")
            device.resume(pid)

        else:
            print_flush(f"[Loader] Attaching to {package}")
            session = device.attach(package)
            print_flush("[Loader] Session attached")

            script = session.create_script(user_script)
            script.on("message", on_message)
            try:
                script.on("console", on_console)
            except:
                pass

            script.load()
            print_flush("[Loader] ✅ Script loaded")

        # =========================
        # 5. 告诉 Cloud：Frida 已就绪
        # =========================
        print_flush("[Loader] 🚀 Frida hook active, waiting for app interaction")
        emit_command_result("SUCCESS", "FRIDA_RUNNING")

        # =========================
        # 6. 保持运行（等你点按钮）
        # =========================
        while running:
            time.sleep(0.1)

    except Exception as e:
        print_flush(f"[Loader] ❌ Exception: {e}")
        emit_command_result("ERROR", str(e))
        sys.exit(1)

# =========================
if __name__ == "__main__":
    main()
