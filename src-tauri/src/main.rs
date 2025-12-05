#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt; 

use serde::{Serialize, Deserialize};
use tauri::{Emitter, Manager, Listener};
use std::net::TcpStream;
use std::io::{Read, Write, Cursor};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::fs::File;
use xz2::read::XzDecoder; 
use std::io::{BufRead, BufReader};
use std::process::Stdio;
use directories::UserDirs;
use std::fs;

// --- 状态结构体 ---
struct AdbState {
    sockets: Arc<Mutex<HashMap<u32, std::net::TcpStream>>>,
}

// --- 数据结构 ---
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DeviceItem {
    id: String,
    name: String,
    status: String,
    os: String,
    type_: String, 
}

#[derive(Debug, Serialize, Deserialize)]
struct AppItem {
    id: String,
    name: String,
    pkg: String,
    ver: String,
    icon: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppDetail {
    versionName: String,
    versionCode: String,
    minSdk: String,
    targetSdk: String,
    dataDir: String,
    sourceDir: String,
    uid: String,
    firstInstallTime: String,
    lastUpdateTime: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FridaRelease {
    tag_name: String,
}

// 🔥 新增：文件信息结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileItem {
    name: String,
    is_dir: bool,
    size: String,
    permissions: String,
    date: String,
}

// --- 🔥 1. 重命名内部辅助函数 (原 run_command 改为 cmd_exec) ---
fn cmd_exec(cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(cmd);
    command.args(args);
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); 
    let output = command.output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- 🔥 2. 新增：暴露给前端的通用命令 ---
#[tauri::command]
async fn run_command(cmd: String, args: Vec<String>) -> Result<String, String> {
    // 将 Vec<String> 转为 Vec<&str> 以调用内部函数
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    cmd_exec(&cmd, &args_slice)
}

// --- 辅助函数：智能获取应用名 ---
fn get_android_label(pkg: &str) -> String {
    match pkg {
        // --- 常用 App 映射 ---
        "com.tencent.mm" => "微信".to_string(),
        "com.ss.android.ugc.aweme" => "抖音".to_string(),
        "com.eg.android.AlipayGphone" => "支付宝".to_string(),
        "tv.danmaku.bili" => "哔哩哔哩".to_string(),
        "com.sina.weibo" => "微博".to_string(),
        "com.xingin.xhs" => "小红书".to_string(),
        "com.jingdong.app.mall" => "京东".to_string(),
        "com.taobao.taobao" => "淘宝".to_string(),
        "com.coolapk.market" => "酷安".to_string(),
        "bin.mt.plus" => "MT管理器".to_string(),
        "com.netease.cloudmusic" => "网易云音乐".to_string(),
        
        // --- 截图里出现的 App ---
        "com.oneplus.calculator" => "一加计算器".to_string(),
        "net.oneplus.weather" => "一加天气".to_string(),
        "com.google.android.youtube" => "YouTube".to_string(),
        "com.che168.autotradercloud" => "二手车之家".to_string(), // 猜测
        "com.wuba.zhuanzhuan" => "转转".to_string(),
        "com.quark.browser" => "夸克浏览器".to_string(),
        "com.tencent.tmgp.sgame" => "王者荣耀".to_string(),
        "com.youku.phone" => "优酷视频".to_string(),
        "com.seetong.app.seetong" => "Seetong监控".to_string(),
        "com.mt.mtxx.mtxx" => "美图秀秀".to_string(),

        // --- 默认逻辑：取最后一段，首字母大写 ---
        _ => {
            // 例如 com.example.my_app -> MyApp
            let last_part = pkg.split('.').last().unwrap_or(pkg);
            let name = last_part.replace("_", " "); // 把下划线换成空格
            
            // 首字母大写
            let mut c = name.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        }
    }
}

// --- 辅助函数：下载并解压 Frida ---
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

// ==========================================
//  后台监听
// ==========================================
fn start_device_monitor(app: tauri::AppHandle) {
    thread::spawn(move || {
        let mut last_state = String::new();
        loop {
            // 🔥 这里全部改为调用 cmd_exec
            let adb_res = cmd_exec("adb", &["devices", "-l"]).unwrap_or_default();
            let ios_res = cmd_exec("tidevice", &["list"]).unwrap_or_default();
            let current_state = format!("{}{}", adb_res, ios_res);

            if !last_state.is_empty() && current_state != last_state {
                let _ = app.emit("device-changed", ());
            }
            last_state = current_state;
            thread::sleep(Duration::from_secs(2));
        }
    });
}

// ==========================================
//  Web Scrcpy (TCP Forwarding)
// ==========================================
#[tauri::command]
fn adb_connect(app_handle: tauri::AppHandle, connection_id: u32) -> Result<bool, String> {
    let stream = TcpStream::connect("127.0.0.1:5037").map_err(|e| e.to_string())?;
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut stream_clone = stream.try_clone().map_err(|e| e.to_string())?;
    let app_handle_clone = app_handle.clone(); 

    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match stream_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    let _ = app_handle_clone.emit(&format!("adb-data-{}", connection_id), data);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        let _ = app_handle_clone.emit(&format!("adb-close-{}", connection_id), ());
    });

    let state = app_handle.state::<AdbState>();
    state.sockets.lock().unwrap().insert(connection_id, stream);
    Ok(true)
}

#[tauri::command]
fn adb_write(connection_id: u32, data: Vec<u8>, state: tauri::State<'_, AdbState>) -> Result<(), String> {
    let mut sockets = state.sockets.lock().unwrap();
    if let Some(stream) = sockets.get_mut(&connection_id) {
        stream.write_all(&data).map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("Socket not found".to_string())
}

#[tauri::command]
fn adb_close(connection_id: u32, state: tauri::State<'_, AdbState>) -> Result<(), String> {
    let mut sockets = state.sockets.lock().unwrap();
    sockets.remove(&connection_id);
    Ok(())
}

// ==========================================
//  常规业务逻辑
// ==========================================

#[tauri::command]
async fn get_all_devices() -> Result<Vec<DeviceItem>, String> {
    let mut final_devices = Vec::new();
    let mut usb_devices = Vec::new();
    let mut wifi_candidates = Vec::new();
    let mut usb_serials = HashSet::new();

    // Android
    // 🔥 改用 cmd_exec
    if let Ok(adb_out) = cmd_exec("adb", &["devices", "-l"]) {
        for line in adb_out.lines().skip(1) {
            if line.trim().is_empty() { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let id = parts[0].to_string();
                let state = parts[1];
                let model = parts.iter().find(|&&p| p.starts_with("model:")).map(|s| s.replace("model:", "").replace("_", " ")).unwrap_or_else(|| "Android Device".to_string());
                let device = DeviceItem { id: id.clone(), name: model, status: if state == "device" { "online".to_string() } else { "offline".to_string() }, os: "Android".to_string(), type_: "android".to_string() };
                
                if id.contains('.') && id.contains(':') {
                    wifi_candidates.push(device);
                } else {
                    usb_devices.push(device);
                    usb_serials.insert(id);
                }
            }
        }
    }
    final_devices.append(&mut usb_devices);

    // 去重 WiFi 设备
    for wifi_dev in wifi_candidates {
        let mut is_duplicate = false;
        if wifi_dev.status == "online" {
            // 🔥 改用 cmd_exec
            if let Ok(output) = cmd_exec("adb", &["-s", &wifi_dev.id, "shell", "getprop", "ro.serialno"]) {
                let real_serial = output.trim();
                if !real_serial.is_empty() && usb_serials.contains(real_serial) {
                    is_duplicate = true;
                }
            }
        }
        if !is_duplicate { final_devices.push(wifi_dev); }
    }
    
    // iOS
    // 🔥 改用 cmd_exec
    if let Ok(ios_out) = cmd_exec("tidevice", &["list"]) {
        for line in ios_out.lines() {
            let trim_line = line.trim();
            if trim_line.is_empty() || trim_line.contains("List of apple devices") || trim_line.contains("SerialNumber") || trim_line.contains("MarketName") || trim_line.contains("ProductVersion") { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0].len() > 10 {
                let udid = parts[0].to_string();
                let name_parts: Vec<&str> = parts[1..].iter().filter(|&&p| !p.contains("ConnectionType") && !p.eq("USB") && !p.eq("Network") && !p.contains(".")).cloned().collect();
                let name = if name_parts.is_empty() { "iPhone".to_string() } else { name_parts.join(" ") };
                final_devices.push(DeviceItem { id: udid, name, status: "online".to_string(), os: "iOS".to_string(), type_: "ios".to_string() });
            }
        }
    }
    Ok(final_devices)
}

#[tauri::command]
async fn get_device_apps(device_id: String, device_type: String) -> Result<Vec<AppItem>, String> {
    let mut apps = Vec::new();
    if device_type == "android" {
        // 🔥 改用 cmd_exec (后续同理)
        let output = cmd_exec("adb", &["-s", &device_id, "shell", "pm", "list", "packages", "-3"])?;
        for (i, line) in output.lines().enumerate() {
            if let Some(pkg) = line.trim().strip_prefix("package:") {
                let name = get_android_label(pkg);
                apps.push(AppItem { id: i.to_string(), name, pkg: pkg.to_string(), ver: "".to_string(), icon: "#3ddc84".to_string() });
            }
        }
    } else if device_type == "ios" {
        let output = cmd_exec("tidevice", &["-u", &device_id, "applist"])?;
        for (i, line) in output.lines().enumerate() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                apps.push(AppItem { id: i.to_string(), pkg: parts[0].to_string(), name: parts[1].to_string(), ver: "".to_string(), icon: "#000000".to_string() });
            }
        }
    }
    Ok(apps)
}

#[tauri::command]
async fn start_scrcpy(serial: String, max_size: u32, bit_rate: u32) -> Result<(), String> {
    std::thread::spawn(move || {
        let _ = Command::new("scrcpy").arg("-s").arg(serial).arg("--max-size").arg(max_size.to_string()).arg("--video-bit-rate").arg(format!("{}M", bit_rate)).spawn();
    });
    Ok(())
}

#[tauri::command]
async fn enable_wireless_mode(device_id: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "tcpip", "5555"])?;
    if output.contains("restarting in TCP mode") {
        Ok("已开启无线模式 (端口 5555)".to_string())
    } else {
        Err(format!("开启失败: {}", output))
    }
}

#[tauri::command]
async fn get_device_ip(device_id: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "ip", "route"])?;
    for line in output.lines() {
        if line.contains("wlan0") && line.contains("src") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&x| x == "src") {
                if pos + 1 < parts.len() { return Ok(parts[pos + 1].to_string()); }
            }
        }
    }
    Err("无法获取 IP".to_string())
}

#[tauri::command]
async fn adb_pair(address: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["connect", &address])?;
    if output.contains("connected to") || output.contains("already connected") {
        Ok("连接成功".to_string())
    } else {
        Err(format!("连接失败: {}", output))
    }
}

#[tauri::command]
async fn install_apk(device_id: String, apk_path: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "install", "-r", &apk_path])?;
    if output.contains("Success") {
        Ok("安装成功".to_string())
    } else {
        Err(format!("安装失败: {}", output))
    }
}

#[tauri::command]
async fn get_app_detail(device_id: String, pkg: String) -> Result<AppDetail, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "dumpsys", "package", &pkg])?;
    let mut detail = AppDetail {
        versionName: "Unknown".to_string(), versionCode: "0".to_string(), minSdk: "Unknown".to_string(),
        targetSdk: "Unknown".to_string(), dataDir: format!("/data/data/{}", pkg), sourceDir: "".to_string(),
        uid: "Unknown".to_string(), firstInstallTime: "".to_string(), lastUpdateTime: "".to_string(),
    };
    for line in output.lines() {
        let trim_line = line.trim();
        if trim_line.starts_with("versionName=") { detail.versionName = trim_line.replace("versionName=", ""); }
        else if trim_line.starts_with("versionCode=") {
            let parts: Vec<&str> = trim_line.split_whitespace().collect();
            for part in parts {
                if part.starts_with("versionCode=") { detail.versionCode = part.replace("versionCode=", ""); }
                if part.starts_with("minSdk=") { detail.minSdk = part.replace("minSdk=", ""); }
                if part.starts_with("targetSdk=") { detail.targetSdk = part.replace("targetSdk=", ""); }
            }
        }
        else if trim_line.starts_with("dataDir=") { detail.dataDir = trim_line.replace("dataDir=", ""); }
        else if trim_line.starts_with("codePath=") { detail.sourceDir = trim_line.replace("codePath=", ""); }
        else if trim_line.starts_with("userId=") { detail.uid = trim_line.replace("userId=", ""); }
        else if trim_line.starts_with("firstInstallTime=") { detail.firstInstallTime = trim_line.replace("firstInstallTime=", ""); }
        else if trim_line.starts_with("lastUpdateTime=") { detail.lastUpdateTime = trim_line.replace("lastUpdateTime=", ""); }
    }
    Ok(detail)
}

#[tauri::command]
async fn get_device_abi(device_id: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "getprop", "ro.product.cpu.abi"])?;
    Ok(output.trim().to_string())
}

#[tauri::command]
async fn get_frida_versions() -> Result<Vec<String>, String> {
    let url = "https://api.github.com/repos/frida/frida/releases";
    let client = reqwest::Client::new();
    let response = client.get(url).header("User-Agent", "tauri-app").send().await.map_err(|e| format!("请求失败: {}", e))?;
    if !response.status().is_success() { return Err(format!("API 错误: {}", response.status())); }
    let releases: Vec<FridaRelease> = response.json().await.map_err(|e| format!("解析失败: {}", e))?;
    let versions: Vec<String> = releases.into_iter().map(|r| r.tag_name.trim_start_matches('v').to_string()).take(10).collect();
    Ok(versions)
}

// 🔥 优化：使用 'test -f' 检测文件是否存在，比 ls 更准确
#[tauri::command]
async fn check_frida_installed(device_id: String) -> Result<bool, String> {
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
async fn deploy_tool(device_id: String, tool_id: String, version: String, arch: String) -> Result<String, String> {
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

// 🔥 新增：检查 Frida Server 是否正在运行
#[tauri::command]
async fn check_frida_running(device_id: String) -> Result<bool, String> {
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

// 🔥 新增：检查设备是否 Root
#[tauri::command]
async fn check_is_rooted(device_id: String) -> Result<bool, String> {
    // 尝试执行 'su -c id'，如果成功且返回 uid=0，说明有 Root 权限
    let output = Command::new("adb")
        .args(&["-s", &device_id, "shell", "su -c id"])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 输出通常包含 "uid=0(root)"
        if stdout.contains("uid=0") {
            return Ok(true);
        }
    }

    // 备用检测：检查 su 二进制文件是否存在 (针对某些只装了 su 但没授权 shell 的情况)
    let check_bin = Command::new("adb")
        .args(&["-s", &device_id, "shell", "which su"])
        .output()
        .map_err(|e| e.to_string())?;
        
    if check_bin.status.success() {
        let stdout = String::from_utf8_lossy(&check_bin.stdout);
        if !stdout.trim().is_empty() && !stdout.contains("not found") {
            // 有 su 文件，虽然可能没切过去，但也标记为 Root 设备
            return Ok(true);
        }
    }

    Ok(false)
}

// 🔥 新增：启动 App (相当于 Spawn 的前置动作)
#[tauri::command]
async fn launch_app(device_id: String, pkg: String) -> Result<String, String> {
    // adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1
    // 或者用 am start (需要知道 Activity，monkey 更通用)
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "monkey", "-p", &pkg, "-c", "android.intent.category.LAUNCHER", "1"])?;
    
    if output.contains("Events injected") {
        Ok("应用已启动".to_string())
    } else {
        Err(format!("启动失败: {}", output))
    }
}

// 🔥 新增：强行停止 App
#[tauri::command]
async fn stop_app(device_id: String, pkg: String) -> Result<String, String> {
    cmd_exec("adb", &["-s", &device_id, "shell", "am", "force-stop", &pkg])?;
    Ok("应用已停止".to_string())
}

#[tauri::command]
async fn run_frida_script(app: tauri::AppHandle, device_id: String, package_name: String, script_content: String) -> Result<String, String> {
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

// 🔥 新增：获取当前前台应用包名
#[tauri::command]
async fn get_foreground_app(device_id: String) -> Result<String, String> {
    // Android 10+ 通用命令
    // adb shell dumpsys activity activities | grep mResumedActivity
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "dumpsys", "activity", "activities"])?;
    
    for line in output.lines() {
        if line.contains("mResumedActivity") {
            // 典型输出: mResumedActivity: ActivityRecord{... u0 com.example.app/.MainActivity ...}
            if let Some(start) = line.find("u0 ") {
                let rest = &line[start + 3..];
                if let Some(end) = rest.find('/') {
                    return Ok(rest[..end].to_string());
                }
            }
        }
    }
    
    // 备用方案 (针对旧版 Android)
    let output_old = cmd_exec("adb", &["-s", &device_id, "shell", "dumpsys", "window", "windows", "|", "grep", "-E", "'mCurrentFocus|mFocusedApp'"])?;
    if let Some(start) = output_old.find("u0 ") {
        let rest = &output_old[start + 3..];
        if let Some(end) = rest.find('/') {
            return Ok(rest[..end].to_string());
        }
    }

    Err("未找到前台应用，请确保手机屏幕已点亮并打开了 App".to_string())
}

// 🔥 修复版：提取 APK (包含详细错误日志)
#[tauri::command]
async fn extract_apk(device_id: String, pkg: String) -> Result<String, String> {
    // 1. 获取 APK 路径
    let path_output = Command::new("adb")
        .args(&["-s", &device_id, "shell", "pm", "path", &pkg])
        .output()
        .map_err(|e| format!("执行 pm path 失败: {}", e))?;

    let path_stdout = String::from_utf8_lossy(&path_output.stdout).to_string();
    
    // 解析路径：取第一行 (忽略 Split APKs)，去除 "package:" 前缀
    let remote_path = path_stdout.lines()
        .next()
        .ok_or(format!("未找到应用 {}，请确认已安装", pkg))?
        .replace("package:", "")
        .trim()
        .to_string();

    if remote_path.is_empty() {
        return Err("解析到的 APK 路径为空".to_string());
    }

    // 2. 确定本地保存路径 (用户下载目录)
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    
    // 文件名: com.example.app.apk
    let file_name = format!("{}.apk", pkg);
    let local_path = download_dir.join(&file_name);
    let local_path_str = local_path.to_string_lossy().to_string();

    // 3. 执行 adb pull (同时捕获 stderr)
    let pull_output = Command::new("adb")
        .args(&["-s", &device_id, "pull", &remote_path, &local_path_str])
        .output()
        .map_err(|e| format!("执行 adb pull 失败: {}", e))?;

    // 4. 检查结果
    if pull_output.status.success() {
        // 成功
        Ok(local_path_str)
    } else {
        // 失败：优先返回 stderr 里的错误信息
        let error_msg = String::from_utf8_lossy(&pull_output.stderr).to_string();
        // 如果 stderr 为空，再看 stdout
        let out_msg = String::from_utf8_lossy(&pull_output.stdout).to_string();
        
        Err(format!("ADB 报错: {} {}", error_msg, out_msg))
    }
}

// 🔥 新增：打开文件所在位置
#[tauri::command]
async fn open_file_explorer(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // Windows 特有：打开文件夹并选中文件
        Command::new("explorer")
            .args(["/select,", &path]) // 注意逗号
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Mac/Linux: 直接打开文件所在目录
        open::that(path).map_err(|e| e.to_string())?;
    }
    
    Ok(())
}

// 🔥 新增：获取文件列表命令
#[tauri::command]
async fn get_file_list(device_id: String, path: String) -> Result<Vec<FileItem>, String> {
    // 优先尝试使用 Root 权限读取，因为 /data/data 需要 Root
    // 命令：adb shell "su -c 'ls -l <path>'"
    // 如果失败（比如没Root），回退到普通 ls -l
    
    let cmd = format!("su -c 'ls -l \"{}\"'", path); // 尝试 Root
    let mut output = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;

    if output.contains("denied") || output.contains("not found") {
        // 回退到普通权限 (适合 /sdcard)
        output = cmd_exec("adb", &["-s", &device_id, "shell", "ls", "-l", &path])?;
    }

    let mut files = Vec::new();

    // 解析 ls -l 输出
    // 典型格式: drwxrwx--x 2 root root 4096 2023-01-01 12:00 foldername
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("total") { continue; }

        // 简单的空格分割解析
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; } // 格式不对跳过

        let permissions = parts[0];
        let is_dir = permissions.starts_with('d');
        
        // 处理文件名包含空格的情况：取第8个字段之后的所有内容
        // ls -l date format varies (some have time, some year). 
        // 这是一个简化的解析器，适配大多数 Android ls
        let name_start_index = if parts.len() > 7 { 7 } else { parts.len() - 1 };
        // 有些系统 ls -l 只有日期没有时间，这里做一个容错
        let name = parts[name_start_index..].join(" ");
        
        // 过滤掉 . 和 ..
        if name == "." || name == ".." { continue; }

        let size = if is_dir { "".to_string() } else { parts[4].to_string() }; // 第5列通常是大小
        let date = format!("{} {}", parts[5], parts[6]); // 日期时间

        files.push(FileItem {
            name,
            is_dir,
            size,
            permissions: permissions.to_string(),
            date,
        });
    }

    // 排序：文件夹在前
    files.sort_by(|a, b| {
        if a.is_dir == b.is_dir {
            a.name.cmp(&b.name)
        } else {
            b.is_dir.cmp(&a.is_dir)
        }
    });

    Ok(files)
}

// 🔥 新增：读取文件内容 (支持 Root)
#[tauri::command]
async fn read_file_content(device_id: String, path: String) -> Result<String, String> {
    // 尝试用 cat 命令读取
    // 如果文件是二进制或者太大，这里可能需要做限制，但作为 MVP 先读文本
    let cmd = format!("su -c 'cat \"{}\"'", path);
    let mut output = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;

    // 如果 su 失败，尝试普通 cat
    if output.contains("denied") || output.contains("not found") {
        output = cmd_exec("adb", &["-s", &device_id, "shell", "cat", &path])?;
    }

    // 简单的错误检查
    if output.contains("No such file") || output.contains("Is a directory") {
        return Err(format!("无法读取文件: {}", output));
    }

    // 限制返回大小，防止前端卡死 (比如最大 1MB)
    if output.len() > 1024 * 1024 {
        return Err("文件太大，请下载到电脑查看".to_string());
    }

    Ok(output)
}

// 🔥 新增：保存文件内容 (修改文件)
// 逻辑：写入本地临时文件 -> adb push 到手机临时目录 -> su mv 到目标目录 (为了绕过权限问题)
#[tauri::command]
async fn save_file_content(device_id: String, path: String, content: String) -> Result<String, String> {
    let temp_dir = std::env::temp_dir();
    // 生成随机文件名避免冲突
    let temp_name = format!("adb_edit_{}.tmp", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
    let local_temp_path = temp_dir.join(&temp_name);
    
    // 1. 写入本地临时文件
    fs::write(&local_temp_path, content).map_err(|e| format!("本地写入失败: {}", e))?;
    
    let local_path_str = local_temp_path.to_string_lossy().to_string();
    let remote_temp = format!("/data/local/tmp/{}", temp_name);

    // 2. 推送到手机临时目录
    let push_res = cmd_exec("adb", &["-s", &device_id, "push", &local_path_str, &remote_temp])?;
    if push_res.to_lowercase().contains("error") {
         return Err(format!("Push 失败: {}", push_res));
    }

    // 3. 使用 Root 权限移动到目标位置 (覆盖原文件)
    let mv_res = cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mv '{}' '{}'", remote_temp, path)])?;
    
    // 清理本地临时文件
    let _ = fs::remove_file(local_temp_path);

    if mv_res.trim().is_empty() {
        Ok("保存成功".to_string())
    } else {
        // mv 命令通常没有输出，如果有输出可能是报错
        Ok(format!("保存可能成功 (Log: {})", mv_res))
    }
}

// 🔥 新增：删除文件/文件夹
#[tauri::command]
async fn delete_file(device_id: String, path: String) -> Result<String, String> {
    // rm -rf <path>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("rm -rf '{}'", path)])?;
    Ok("删除成功".to_string())
}

// 🔥 新增：新建文件夹
#[tauri::command]
async fn create_dir(device_id: String, path: String) -> Result<String, String> {
    // mkdir -p <path>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mkdir -p '{}'", path)])?;
    Ok("创建成功".to_string())
}

// 🔥 新增：重命名
#[tauri::command]
async fn rename_file(device_id: String, old_path: String, new_path: String) -> Result<String, String> {
    // mv <old> <new>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mv '{}' '{}'", old_path, new_path)])?;
    Ok("重命名成功".to_string())
}

// ==========================================
//  主函数
// ==========================================

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AdbState { 
            sockets: Arc::new(Mutex::new(HashMap::new())) 
        })
        .setup(|app| {
            let handle = app.handle().clone();
            start_device_monitor(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_all_devices,
            get_device_apps,
            start_scrcpy,
            adb_pair,
            adb_connect,
            adb_write,
            adb_close,
            install_apk,
            enable_wireless_mode,
            get_device_ip,
            get_app_detail,
            get_device_abi,
            deploy_tool,
            get_frida_versions,
            check_frida_installed,
            // 🔥 注册这个新命令
            run_command,
            check_frida_running,
            check_is_rooted,
            launch_app,
            stop_app,
            run_frida_script,
            get_foreground_app,
            extract_apk,
            open_file_explorer,
            get_file_list,
            read_file_content,
            save_file_content, 
            delete_file, 
            create_dir, 
            rename_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}