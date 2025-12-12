use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader, Write};
use std::thread;
use tauri::{AppHandle, Emitter, State};
use serde_json::json;

use crate::state::WebLabState;

#[tauri::command]
pub async fn start_web_engine(app: AppHandle, state: State<'_, WebLabState>) -> Result<String, String> {
    let mut child_guard = state.child.lock().unwrap();
    if child_guard.is_some() {
        return Ok("Engine already running".to_string());
    }

    // 🔥🔥🔥 核心修复：手动构建路径，不再依赖 resolve (开发环境专用) 🔥🔥🔥
    #[cfg(debug_assertions)]
    let resource_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources/bin/browser-engine/index.js");

    #[cfg(not(debug_assertions))]
    let resource_path = app.path().resolve("resources/bin/browser-engine/index.js", tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("定位脚本失败: {}", e))?;

    // 打印路径方便调试
    println!(">>> Node Script Path: {:?}", resource_path);

    if !resource_path.exists() {
        return Err(format!("找不到 index.js，路径: {:?}", resource_path));
    }
    
    // 假设用户环境变量里有 node。为了更稳健，你可以像 maestro 那样打包一个 node.exe
    let mut child = Command::new("node")
        .arg(resource_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动 Node 引擎失败: {}", e))?;

    let stdin = child.stdin.take().ok_or("Failed to open stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to open stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to open stderr")?;

    // 创建发送通道
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let mut tx_guard = state.tx.lock().unwrap();
    *tx_guard = Some(tx);

    // 1. 开启线程监听 STDOUT (来自 Node 的事件)
    let app_clone = app.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                // 尝试解析 JSON
                if let Ok(json_msg) = serde_json::from_str::<serde_json::Value>(&l) {
                    let _ = app_clone.emit("weblab-event", json_msg);
                } else {
                    println!("[Node Raw] {}", l);
                }
            }
        }
        // 🔥🔥🔥 核心修复：循环结束意味着 Node 进程 stdout 关闭 (进程退出) 🔥🔥🔥
        // 此时强制通知前端：引擎已停止
        println!(">>> [Rust] Web Engine STDOUT closed (Process exited)");
        let _ = app_clone.emit("weblab-event", json!({
            "type": "status",
            "payload": "Stopped"
        }));
    });

    // 2. 开启线程监听 STDERR (错误日志)
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(l) = line {
                println!("[Node Error] {}", l);
            }
        }
    });

    // 3. 开启线程处理写入 STDIN
    thread::spawn(move || {
        let mut stdin = stdin;
        while let Ok(msg) = rx.recv() {
            let _ = stdin.write_all(msg.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }
    });

    *child_guard = Some(child);
    Ok("Web Engine Started".to_string())
}

#[tauri::command]
pub async fn send_web_command(state: State<'_, WebLabState>, action: String, data: serde_json::Value) -> Result<(), String> {
    let tx_guard = state.tx.lock().unwrap();
    if let Some(tx) = tx_guard.as_ref() {
        let cmd = json!({
            "action": action,
            "data": data
        });
        tx.send(cmd.to_string()).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Engine not running".to_string())
    }
}

#[tauri::command]
pub async fn stop_web_engine(state: State<'_, WebLabState>) -> Result<(), String> {
    let mut child_guard = state.child.lock().unwrap();
    
    if let Some(mut child) = child_guard.take() {
        // 获取进程 ID
        let pid = child.id();
        
        // 尝试标准 kill (Linux/macOS 有效，Windows 可能只杀父进程)
        let _ = child.kill();

        // 🔥🔥🔥 Windows 专属：使用 taskkill 强制杀全家 (Force Kill Tree) 🔥🔥🔥
        #[cfg(target_os = "windows")]
        {
            // /F = 强制, /T = 终止子进程(树), /PID = 指定进程ID

            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill")
                .args(&["/F", "/T", "/PID", &pid.to_string()])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW，隐藏黑框
                .output();
        }
        
        println!(">>> [Rust] 已强制终止 Web 引擎 (PID: {})", pid);
    }

    // 清理发送通道
    let mut tx_guard = state.tx.lock().unwrap();
    *tx_guard = None;
    
    Ok(())
}