import frida
import sys
import time
import signal
import threading

# Force UTF-8 for stdout/stderr
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

def print_flush(*args, **kwargs):
    print(*args, **kwargs, flush=True)

running = True

def handler(signum, frame):
    global running
    print_flush("[Loader] Stopping...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)


def main():
    global running
    
    if len(sys.argv) < 6:
        print_flush("[Loader] Usage: python loader.py <device_id> <package> <script_path> <mode> <anti_detect_bool>")
        sys.exit(1)

    device_id = sys.argv[1]
    package = sys.argv[2]
    script_path = sys.argv[3]
    mode = sys.argv[4]
    anti_detect = sys.argv[5].lower() == 'true'

    print_flush(f"[Loader] Starting: {package}, Mode: {mode}, AntiDetect: {anti_detect}")
    
    try:
        # 1. Connect to Device
        if device_id and device_id != "null" and device_id != "":
            try:
                device = frida.get_device(device_id)
            except:
                device = frida.get_usb_device()
        else:
            device = frida.get_usb_device()
        
        print_flush(f"[Loader] Connected to device: {device.name}")
        
        # 2. Load user script content
        with open(script_path, "r", encoding="utf-8") as f:
            user_script = f.read()
        
        session = None
        script = None
        
        # Message handler - MUST be defined before script creation
        def on_message(message, data):
            try:
                if message['type'] == 'send':
                    payload = message.get('payload', '')
                    print_flush(payload)
                elif message['type'] == 'log':
                    print_flush(message.get('payload', ''))
                elif message['type'] == 'error':
                    desc = message.get('description', 'Unknown error')
                    print_flush(f"[Script Error] {desc}")
                    stack = message.get('stack', '')
                    if stack:
                        print_flush(f"[Error Stack] {stack}")
            except Exception as e:
                print_flush(f"[Message Handler Error] {e}")
        
        # 3. Spawn or Attach
        if mode == "spawn":
            print_flush(f"[Loader] Spawning {package}...")
            pid = device.spawn([package])
            print_flush(f"[Loader] Spawned PID: {pid}")
            
            session = device.attach(pid)
            print_flush(f"[Loader] Session attached.")
            
            # 🔥 KEY FIX: Resume FIRST, then wait, then load script
            # This ensures Java VM is fully initialized before any Java.perform() calls
            print_flush("[Frida] ▶️ Resuming app FIRST...")
            device.resume(pid)
            
            # Wait for Java VM to initialize
            print_flush("[Loader] ⏳ Waiting 2s for Java VM initialization...")
            time.sleep(2)
            
            # Now load the script - Java should be ready
            print_flush("[Loader] 📜 Loading script (Java should be ready now)...")
            script = session.create_script(user_script)
            script.on('message', on_message)
            script.load()
            print_flush("[Loader] ✅ Script loaded and executed!")
            
        else:
            # Attach mode - app already running, Java is ready
            print_flush(f"[Loader] Attaching to {package}...")
            session = device.attach(package)
            print_flush(f"[Loader] Session attached.")
            
            script = session.create_script(user_script)
            script.on('message', on_message)
            script.load()
            print_flush("[Loader] ✅ Script loaded!")
        
        # 4. Keep Alive with proper message processing
        print_flush("[Loader] Hook active. Monitoring for output...")
        
        while running:
            time.sleep(0.1)
        
    except frida.ProcessNotFoundError:
        print_flush(f"[Loader] Process not found: {package}")
        sys.exit(1)
    except frida.TransportError as e:
        print_flush(f"[Loader] Transport error: {e}")
        sys.exit(1)
    except frida.InvalidOperationError as e:
        print_flush(f"[Loader] Invalid operation: {e}")
        sys.exit(1)
    except Exception as e:
        print_flush(f"[Loader] Exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
