use std::process::{Stdio, Child};
use std::fs::File;
use std::io::{BufRead, BufReader, Write, Cursor, Read};
use std::time::Duration;
use std::thread;
use reqwest;
use xz2::read::XzDecoder;
use tauri::Emitter;
use crate::models::FridaRelease;
use crate::utils::{cmd_exec, create_command};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

// =====================================================
// 🔥 全局状态：Frida 进程管理
// =====================================================
lazy_static! {
    /// 当前运行的 Frida 子进程句柄
    static ref FRIDA_PROCESS: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    
    /// 当前会话 ID（用于日志同步）
    static ref CURRENT_SESSION: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    
    /// 云端服务器地址
    static ref CLOUD_URL: String = std::env::var("CLOUD_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
}

async fn download_frida(version: &str, arch: &str) -> Result<String, String> {
    let filename = format!("frida-server-{}-android-{}.xz", version, arch);
    let url = format!("https://github.com/frida/frida/releases/download/{}/{}", version, filename);
    
    println!("正在下载: {}", url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client.get(&url).header("User-Agent", "tauri-app").send().await.map_err(|e| format!("下载请求失败: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("下载失败，状态码: {}", response.status()));
    }

    let bytes = response.bytes().await.map_err(|e| format!("读取流失败: {}", e))?;
    let cursor = Cursor::new(&bytes);
    let mut decompressor = XzDecoder::new(cursor);
    let mut buffer = Vec::new();
    decompressor.read_to_end(&mut buffer).map_err(|e| format!("解压失败: {}", e))?;

    let temp_dir = std::env::temp_dir();
    let target_path = temp_dir.join(format!("frida-server-{}", arch));
    let mut file = File::create(&target_path).map_err(|e| format!("创建文件失败: {}", e))?;
    file.write_all(&buffer).map_err(|e| format!("写入文件失败: {}", e))?;

    Ok(target_path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn get_frida_versions() -> Result<Vec<String>, String> {
    let url = "https://api.github.com/repos/frida/frida/releases";
    let client = reqwest::Client::new();
    let response = client.get(url).header("User-Agent", "tauri-app").send().await.map_err(|e| format!("请求失败: {}", e))?;
    if !response.status().is_success() { return Err(format!("API 错误: {}", response.status())); }
    let releases: Vec<FridaRelease> = response.json().await.map_err(|e| format!("解析失败: {}", e))?;
    let versions: Vec<String> = releases.into_iter().map(|r| r.tag_name.trim_start_matches('v').to_string()).take(10).collect();
    Ok(versions)
}

// 使用 'test -f' 检测文件是否存在，比 ls 更准确
#[tauri::command]
pub async fn check_frida_installed(device_id: String) -> Result<bool, String> {
    // test -f 返回 0 表示存在，返回 1 表示不存在
    let output = create_command("adb")
        .args(&["-s", &device_id, "shell", "test -f /data/local/tmp/frida-server"])
        .output()
        .map_err(|e| e.to_string())?;

    // 只有状态码为 0 (success) 才代表文件存在
    if output.status.success() {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub async fn deploy_tool(device_id: String, tool_id: String, version: String, arch: String) -> Result<String, String> {
    match tool_id.as_str() {
        "frida" => {
            let local_path = download_frida(&version, &arch).await?;
            let push_res = cmd_exec("adb", &["-s", &device_id, "push", &local_path, "/data/local/tmp/frida-server"])?;
            if push_res.to_lowercase().contains("error") || push_res.to_lowercase().contains("failed") {
                return Err(format!("推送失败: {}", push_res));
            }
            let chmod_res = cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", "chmod 755 /data/local/tmp/frida-server"])?;
            if chmod_res.to_lowercase().contains("denied") || chmod_res.to_lowercase().contains("not found") {
                 cmd_exec("adb", &["-s", &device_id, "shell", "chmod", "755", "/data/local/tmp/frida-server"])?;
            }
            Ok(format!("Frida ({}) 部署成功", version))
        },
        _ => Err("暂不支持".to_string())
    }
}


// 检查 Frida Server 是否正在运行
#[tauri::command]
pub async fn check_frida_running(device_id: String) -> Result<bool, String> {
    let output = create_command("adb")
        .args(&["-s", &device_id, "shell", "pidof", "frida-server"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            return Ok(true);
        }
    }

    let fallback_cmd = "ps -A | grep frida-server | grep -v grep";
    let output_fallback = create_command("adb")
        .args(&["-s", &device_id, "shell", fallback_cmd])
        .output()
        .map_err(|e| e.to_string())?;

    if output_fallback.status.success() {
        let stdout = String::from_utf8_lossy(&output_fallback.stdout);
        if !stdout.trim().is_empty() {
            return Ok(true);
        }
    }

    Ok(false)
}

// 🔥 检查魔改版 Frida Server 是否正在运行
#[tauri::command]
pub async fn check_modded_frida_running(device_id: String) -> Result<bool, String> {
    let output = create_command("adb")
        .args(&["-s", &device_id, "shell", "pidof", "modded-frida-server"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            return Ok(true);
        }
    }

    // 备用检测方式
    let fallback_cmd = "ps -A | grep modded-frida-server | grep -v grep";
    let output_fallback = create_command("adb")
        .args(&["-s", &device_id, "shell", fallback_cmd])
        .output()
        .map_err(|e| e.to_string())?;

    if output_fallback.status.success() {
        let stdout = String::from_utf8_lossy(&output_fallback.stdout);
        if !stdout.trim().is_empty() {
            return Ok(true);
        }
    }

    Ok(false)
}


// =====================================================
// 🔥 核心修复：增强版 Frida 脚本执行
// =====================================================
#[tauri::command]
pub async fn run_frida_script(
    app: tauri::AppHandle, 
    device_id: String, 
    package_name: String, 
    script_content: String,
    mode: Option<String>,       // 🔥 新增：spawn / attach
    session_id: Option<String>  // 🔥 新增：用于日志同步
) -> Result<String, String> {
    // 0. 先停止之前的 Frida 进程（如果有）
    stop_frida_internal();
    
    // 保存当前会话 ID
    if let Some(sid) = &session_id {
        let mut current = CURRENT_SESSION.lock().unwrap();
        *current = Some(sid.clone());
    }

    // 1. 将脚本保存到临时文件
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("frida_script.js");
    let mut file = File::create(&script_path).map_err(|e| e.to_string())?;
    file.write_all(script_content.as_bytes()).map_err(|e| e.to_string())?;

    // 2. 构造 Frida 参数
    let device_arg = if device_id.is_empty() {
        "-U".to_string() // 默认 USB
    } else if device_id.contains(":") || device_id.contains(".") {
        format!("-D{}", device_id) // 网络设备
    } else {
        "-U".to_string()
    };

    // 3. 🔥 根据 mode 决定注入方式
    let inject_mode = mode.unwrap_or_else(|| "spawn".to_string());
    
    let mut cmd = create_command("frida");
    cmd.arg(&device_arg);
    
    if inject_mode == "spawn" {
        cmd.arg("-f").arg(&package_name); // Spawn 模式：重启 App
    } else {
        cmd.arg("-n").arg(&package_name); // Attach 模式：附加到运行中的进程
    }
    
    cmd.arg("-l").arg(&script_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // 4. 启动子进程
    let mut child = cmd.spawn()
        .map_err(|e| format!("Frida 启动失败 (请确保已安装 frida-tools): {}", e))?;

    // 5. 获取管道句柄
    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    // 6. 🔥 保存进程句柄到全局状态
    {
        let mut process = FRIDA_PROCESS.lock().unwrap();
        *process = Some(child);
    }

    // 7. 克隆必要的引用
    let app_out = app.clone();
    let app_err = app.clone();
    let session_for_out = session_id.clone();
    let session_for_err = session_id.clone();

    // 8. 🔥 开启线程读取 STDOUT（正常日志）
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let client = reqwest::blocking::Client::new();
        
        for line in reader.lines() {
            if let Ok(l) = line {
                // 发送给前端 UI
                let _ = app_out.emit("frida-log", l.clone());
                
                // 🔥 检测就绪信号
                if l.contains("[FridaReady]") || l.contains("Spawned") {
                    let _ = app_out.emit("frida-ready", true);
                }
                
                // 🔥 同步到云端
                if let Some(ref sid) = session_for_out {
                    let _ = sync_log_to_cloud(&client, sid, &l);
                }
            }
        }
        
        // 进程结束时清理状态
        let mut process = FRIDA_PROCESS.lock().unwrap();
        *process = None;
    });

    // 9. 开启线程读取 STDERR（错误日志）
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let client = reqwest::blocking::Client::new();
        
        for line in reader.lines() {
            if let Ok(l) = line {
                let msg = format!("[ERROR] {}", l);
                let _ = app_err.emit("frida-log", msg.clone());
                
                // 同步错误日志到云端
                if let Some(ref sid) = session_for_err {
                    let _ = sync_log_to_cloud(&client, sid, &msg);
                }
            }
        }
    });

    let mode_desc = if inject_mode == "spawn" { "Spawn 模式" } else { "Attach 模式" };
    Ok(format!("Frida 进程已启动 ({})，请查看日志控制台", mode_desc))
}

// =====================================================
// 🔥 新增：停止 Frida 脚本
// =====================================================
#[tauri::command]
pub async fn stop_frida_script() -> Result<String, String> {
    stop_frida_internal();
    Ok("Frida 进程已停止".to_string())
}

/// 内部函数：停止 Frida 进程
fn stop_frida_internal() {
    let mut process = FRIDA_PROCESS.lock().unwrap();
    if let Some(ref mut child) = *process {
        let _ = child.kill();
        let _ = child.wait(); // 回收僵尸进程
        println!("[Frida] 🛑 进程已终止");
    }
    *process = None;
}

// =====================================================
// 🔥 新增：检查 Frida 进程是否存活
// =====================================================
#[tauri::command]
pub async fn is_frida_alive() -> Result<bool, String> {
    let process = FRIDA_PROCESS.lock().unwrap();
    Ok(process.is_some())
}

// =====================================================
// 🔥 新增：同步日志到云端
// =====================================================
fn sync_log_to_cloud(client: &reqwest::blocking::Client, session_id: &str, message: &str) -> Result<(), ()> {
    let url = format!("{}/api/frida-log", CLOUD_URL.as_str());
    
    let _ = client.post(&url)
        .json(&serde_json::json!({
            "sessionId": session_id,
            "message": message
        }))
        .timeout(Duration::from_millis(500)) // 快速超时，不阻塞主流程
        .send();
    
    Ok(())
}
