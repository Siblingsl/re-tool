use std::process::{Command, Stdio};
use std::fs::File;
use std::io::{BufRead, BufReader, Write, Cursor, Read};
use std::time::Duration;
use std::thread;
use reqwest;
use xz2::read::XzDecoder;
use tauri::{AppHandle, Emitter};
use crate::models::FridaRelease;
use crate::utils::cmd_exec;

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
    let output = Command::new("adb")
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
    // 方法 1: 使用 pidof (最准，Android 6+ 支持)
    // 如果 frida-server 在运行，它会输出 PID (如 "1234")
    // 如果没运行，输出为空，或者返回错误码
    let output = Command::new("adb")
        .args(&["-s", &device_id, "shell", "pidof", "frida-server"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 只要有数字输出，就是运行中
        if !stdout.trim().is_empty() {
            return Ok(true);
        }
    }

    // 方法 2: 如果 pidof 失败，回退到 ps 过滤 (增加 -v grep 排除自己)
    // 命令: ps -A | grep frida-server | grep -v grep
    let fallback_cmd = "ps -A | grep frida-server | grep -v grep";
    let output_fallback = Command::new("adb")
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

#[tauri::command]
pub async fn run_frida_script(app: tauri::AppHandle, device_id: String, package_name: String, script_content: String) -> Result<String, String> {
    // 1. 将脚本保存到临时文件
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("frida_script.js");
    let mut file = File::create(&script_path).map_err(|e| e.to_string())?;
    file.write_all(script_content.as_bytes()).map_err(|e| e.to_string())?;

    // 2. 构造 Frida 参数
    let device_arg = if device_id.contains(":") || device_id.contains(".") {
        format!("-D{}", device_id) // 网络设备需要 -D 192.168.x.x:5555
    } else {
        "-U".to_string() // USB 设备
    };

    // 3. 启动子进程，并劫持 stdout
    // 注意：这里不需要 spawn move，因为我们要拿到 child 的句柄
    let mut child = Command::new("frida")
        .arg(device_arg)
        .arg("-f") // Spawn 模式
        .arg(&package_name) // 包名
        .arg("-l")
        .arg(&script_path) // 脚本路径
        .stdout(Stdio::piped()) // 🔥 关键：把输出管道接管过来
        .stderr(Stdio::piped()) // 把错误输出也接管
        .spawn()
        .map_err(|e| format!("Frida 启动失败 (请确保已安装 frida-tools): {}", e))?;

    // 4. 获取管道句柄
    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    // 5. 克隆 app_handle 用于线程内发送
    let app_clone_out = app.clone();
    let app_clone_err = app.clone();

    // 6. 开启独立线程读取 STDOUT (正常日志)
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                // 🔥 发送事件：frida-log
                let _ = app_clone_out.emit("frida-log", l);
            }
        }
    });

    // 7. 开启独立线程读取 STDERR (错误日志)
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(l) = line {
                // 可以加个前缀区分错误
                let _ = app_clone_err.emit("frida-log", format!("[ERROR] {}", l));
            }
        }
    });

    Ok("Frida 进程已启动，请查看日志控制台".to_string())
}