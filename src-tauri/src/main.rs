#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt; 

use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter, Manager, State};
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
use std::path::Path;
use std::env; // 引入 env
use walkdir::WalkDir;
use rayon::prelude::*;
use zip::ZipArchive;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tauri_plugin_shell::process::{CommandEvent, CommandChild};
use tauri_plugin_shell::ShellExt;
use std::path::PathBuf;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose}; // 引入 base64


// --- 状态结构体 ---
struct AdbState {
    sockets: Arc<Mutex<HashMap<u32, std::net::TcpStream>>>,
}

// 用于在全局存储 mitmdump 的子进程，以便随时杀掉它
struct MitmState {
    child: Arc<Mutex<Option<CommandChild>>>,
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

// --- 数据结构：文件树节点 ---
#[derive(Debug, Serialize, Deserialize)]
struct FileNode {
    title: String,
    key: String, // 完整路径
    #[serde(rename = "isLeaf")]
    is_leaf: bool, 
    children: Option<Vec<FileNode>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SearchResult {
    file_path: String, // 文件完整路径
    line_num: usize,   // 行号 (如果是文件名匹配则为 0)
    content: String,   // 匹配行的内容 (或是文件名)
    match_type: String, // "file" | "code"
}

// 定义一个结构体来存储 mitmdump 的子进程
struct ProxyState {
    // 存储正在运行的子进程 (用 Arc<Mutex<>> 保证线程安全)
    // 这里我们存一个 flag 或者 channel 来控制它，或者简单点，存 PID
    // 由于 Tauri 的 Command API 比较特殊，我们这里用一个简单的 bool 标记状态
    // 实际控制通常是 spawn 后保留 handle，但在 Tauri Sidecar 中，
    // kill 比较麻烦，通常建议由前端控制 child.kill()，或者后端维护 Child
    child: Arc<Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
}

// --- 🔥 1. 重命名内部辅助函数 (原 run_command 改为 cmd_exec) ---
fn cmd_exec(cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(cmd);
    command.args(args);
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); 
    
    let output = command.output().map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    // 把两部分信息拼起来返回，这样你就能在前端看到完整日志了
    if stderr.is_empty() {
        Ok(stdout)
    } else {
        Ok(format!("{}\n[Stderr]: {}", stdout, stderr))
    }
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

// --- 辅助函数：递归扫描目录 ---
fn read_dir_recursive(path: &Path) -> Vec<FileNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // 正确判断目录
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let is_dir = file_type.is_dir();

            // 过滤隐藏文件与无用目录
            if name.starts_with(".") || name == "build" || name == "dist" {
                continue;
            }

            let node = FileNode {
                title: name.clone(),
                key: path.to_string_lossy().to_string(),
                #[cfg_attr(feature = "serde", serde(rename = "isLeaf"))] // 如果你用 serde attrs elsewhere, 否则用上面方案
                is_leaf: !is_dir,
                children: if is_dir { Some(read_dir_recursive(&path)) } else { None },
            };

            nodes.push(node);
        }
    }

    // 文件夹排在前
    nodes.sort_by(|a, b| {
        if a.is_leaf == b.is_leaf {
            a.title.cmp(&b.title)
        } else {
            a.is_leaf.cmp(&b.is_leaf)
        }
    });

    nodes
}

// 🔥 命令 1: 解包 APK
#[tauri::command]
async fn apk_decode(apk_path: String) -> Result<String, String> {
    // 输出目录: D:\Downloads\app.apk -> D:\Downloads\app_src
    let output_dir = format!("{}_src", apk_path.trim_end_matches(".apk"));
    
    // 先清理旧目录
    let _ = fs::remove_dir_all(&output_dir);

    // 执行: apktool d -f <apk> -o <out>
    let output = Command::new("cmd")
        .args(&["/C", "apktool", "d", "-f", &apk_path, "-o", &output_dir])
        .output() // 记得加 output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(output_dir)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// 🔥 命令 2: 扫描解包后的目录 (生成树)
#[tauri::command]
async fn scan_local_dir(path: String) -> Result<Vec<FileNode>, String> {
    let root = Path::new(&path);
    if !root.exists() {
        return Err("目录不存在".to_string());
    }
    Ok(read_dir_recursive(root))
}

// 🔥 命令 3: 读取本地文件内容
#[tauri::command]
async fn read_local_file(path: String) -> Result<String, String> {
    // 尝试读取文件为字符串
    // 注意：如果文件不是 UTF-8 编码（比如图片或二进制），这里会报错
    fs::read_to_string(&path).map_err(|e| format!("读取失败: {}", e))
}

// 🔥 命令 4: 保存本地文件内容
#[tauri::command]
async fn save_local_file(path: String, content: String) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn apk_build_sign_install(project_dir: String, device_id: String) -> Result<String, String> {
    // 1. 回编译 (Build)
    let dist_apk = format!("{}/dist/signed.apk", project_dir);
    let unsigned_apk = format!("{}_unsigned.apk", project_dir);
    
    let build_res = Command::new("cmd")
        .args(&["/C", "apktool", "b", &project_dir, "-o", &unsigned_apk])
        .creation_flags(0x08000000) 
        .output()
        .map_err(|e| format!("调用 apktool 失败: {}", e))?;

    if !build_res.status.success() {
        return Err(format!("回编译失败: {}", String::from_utf8_lossy(&build_res.stderr)));
    }

    // 2. 签名 (Sign)
    // 因为运行目录可能是项目根目录，也可能是 src-tauri 目录，我们挨个试
    let possible_paths = vec![
        "resources/uber-apk-signer.jar",           // 情况A: CWD 是 src-tauri
        "src-tauri/resources/uber-apk-signer.jar", // 情况B: CWD 是项目根目录
        "../resources/uber-apk-signer.jar",        // 情况C: 备用
    ];

    let mut signer_jar = "";
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            signer_jar = path;
            println!("✅ 找到签名工具: {}", path);
            break;
        }
    }

    if signer_jar.is_empty() {
        // 如果都没找到，打印详细调试信息
        let cwd = std::env::current_dir().unwrap_or_default();
        println!("❌ 错误: 找不到 uber-apk-signer.jar！");
        println!("当前工作目录: {:?}", cwd);
        println!("请确保文件存在于 src-tauri/resources/ 下");
        // 强行指定一个默认值，虽然大概率会失败
        signer_jar = "resources/uber-apk-signer.jar";
    }
    
    let sign_res = Command::new("java")
        .args(&["-jar", signer_jar, "-a", &unsigned_apk, "--allowResign"])
        .creation_flags(0x08000000)
        .output();
        
    let target_apk = if let Ok(res) = sign_res {
        if res.status.success() {
            // uber-apk-signer 默认生成 xxx-aligned-debugSigned.apk
            format!("{}_unsigned-aligned-debugSigned.apk", project_dir)
        } else {
            println!("签名警告: {}", String::from_utf8_lossy(&res.stderr));
            unsigned_apk // 签名失败回退到未签名
        }
    } else {
        unsigned_apk
    };

    // 3. 安装 (Install)
    // 使用 -r -t 强制安装测试包
    let install_res = cmd_exec("adb", &["-s", &device_id, "install", "-r", "-t", &target_apk])?;
    
    if install_res.contains("Success") {
        Ok("编译、签名并安装成功！".to_string())
    } else {
        Err(format!("安装失败: {}", install_res))
    }
}

// 🔥 新增：使用 JADX 反编译为 Java 源码
#[tauri::command]
async fn jadx_decompile(apk_path: String) -> Result<String, String> {
    // 输出目录: D:\Downloads\app.apk -> D:\Downloads\app_jadx_src
    let output_dir = format!("{}_jadx_src", apk_path.trim_end_matches(".apk"));
    
    // 先清理旧目录
    let _ = fs::remove_dir_all(&output_dir);

    // 命令: jadx -d <out> <apk>
    // 注意：Windows 下可能需要 cmd /C jadx ...
    let output = Command::new("cmd")
        .args(&["/C", "jadx", "-d", &output_dir, &apk_path])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("调用 jadx 失败 (请确保已安装 jadx 并配置环境变量): {}", e))?;

    if output.status.success() {
        // JADX 的源码通常在 output_dir/sources 目录下
        // 我们直接返回根目录，让前端自己点进去
        Ok(output_dir)
    } else {
        // JADX 有时候会有很多 warning 输出在 stderr，但不代表失败
        // 只要目录存在就算成功
        if std::path::Path::new(&output_dir).exists() {
            Ok(output_dir)
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}

// 辅助：判断文件是否是文本文件 (简单判断后缀)
fn is_text_file(path: &str) -> bool {
    let ext = std::path::Path::new(path).extension().and_then(|s| s.to_str()).unwrap_or("");
    matches!(ext, "java" | "xml" | "smali" | "json" | "gradle" | "properties" | "txt")
}

// 🔥 新增：项目全局搜索命令
#[tauri::command]
async fn search_project(project_dir: String, query: String) -> Result<Vec<SearchResult>, String> {
    let query = query.to_lowercase();
    
    // 1. 收集所有文件路径 (快速遍历)
    let entries: Vec<_> = WalkDir::new(&project_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // 2. 并行搜索 (利用所有 CPU 核心)
    // 使用 par_iter() 替代 iter()
    let results: Vec<SearchResult> = entries.par_iter()
        .flat_map(|entry| {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();
            let mut local_results = Vec::new();

            // A. 搜文件名
            if let Some(fname) = path.file_name() {
                if fname.to_string_lossy().to_lowercase().contains(&query) {
                     local_results.push(SearchResult {
                        file_path: path_str.clone(),
                        line_num: 0,
                        content: fname.to_string_lossy().to_string(),
                        match_type: "file".to_string(),
                    });
                }
            }

            // B. 搜内容 (只搜文本文件)
            if is_text_file(&path_str) {
                // 读取文件内容 (忽略读取错误)
                if let Ok(content) = std::fs::read_to_string(path) {
                    for (i, line) in content.lines().enumerate() {
                        if line.to_lowercase().contains(&query) {
                            local_results.push(SearchResult {
                                file_path: path_str.clone(),
                                line_num: i + 1,
                                content: line.trim().to_string(),
                                match_type: "code".to_string(),
                            });
                            // 单个文件限制匹配数，防止大文件刷屏
                            if local_results.len() > 20 { break; } 
                        }
                    }
                }
            }
            local_results
        })
        .collect();

    // 截取前 500 条，防止前端渲染卡顿
    let final_results = results.into_iter().take(500).collect();
    Ok(final_results)
}

// 🔥 查壳特征库
fn get_packer_name(filename: &str) -> Option<&'static str> {
    match filename {
        // --- 1. 360 加固 ---
        s if s.contains("libjiagu.so") 
          || s.contains("libjiagu_art.so") 
          || s.contains("libjiagu_x86.so") 
          || s.contains("libprotectClass.so") => Some("360加固 (360 Jiagu)"),

        // --- 2. 腾讯 (乐固 / 御安全) ---
        s if s.contains("libtupoke.so") 
          || s.contains("libshell.so") 
          || s.contains("libyunjiagu.so") 
          || s.contains("libtx.so") 
          || s.contains("libmyunjiagu.so") 
          || s.contains("mix.dex") // 腾讯有时候把 dex 藏在这里
          => Some("腾讯乐固 (Tencent Legu)"),

        // --- 3. 梆梆安全 ---
        s if s.contains("libsecexe.so") 
          || s.contains("libsecmain.so") 
          || s.contains("libSecShell.so") 
          || s.contains("libPenguin.so") => Some("梆梆安全 (Bangcle)"),

        // --- 4. 爱加密 ---
        s if s.contains("libexec.so") 
          || s.contains("libijiami.so") 
          || s.contains("isecmain.so") 
          || s.contains("ijiami.ajm") => Some("爱加密 (Ijiami)"),

        // --- 5. 网易易盾 (非常常见) ---
        s if s.contains("libnesec.so") 
          || s.contains("libnh.so") 
          || s.contains("libdata.so") // 易盾有时用这个名字
          => Some("网易易盾 (NetEase YiDun)"),

        // --- 6. 阿里聚安全 / 阿里无线 ---
        s if s.contains("libsgmain.so") 
          || s.contains("libsgsecuritybody.so") 
          || s.contains("libmobisec.so") 
          || s.contains("libfakejni.so") => Some("阿里聚安全 (Aliyun)"),

        // --- 7. 百度加固 ---
        s if s.contains("libbaiduprotect.so") => Some("百度加固 (Baidu)"),

        // --- 8. 顶象 ---
        s if s.contains("libx3g.so") 
          || s.contains("libdx-guard.so") => Some("顶象 (DingXiang)"),

        // --- 9. 纳迦 (Naga) / 海云安 ---
        s if s.contains("libddog.so") 
          || s.contains("libfdog.so") 
          || s.contains("libedog.so") => Some("纳迦 (Naga)"),

        // --- 10. 几维安全 ---
        s if s.contains("libkws.so") 
          || s.contains("libkwscmm.so") 
          || s.contains("libkwscr.so") => Some("几维安全 (KiwiSec)"),

        // --- 11. 其它较冷门的加固 ---
        s if s.contains("libapktool.so") => Some("Apktool Plus 加固"),
        s if s.contains("libprotectapis.so") => Some("不知名加固 (ProtectApis)"),
        s if s.contains("libu8_") => Some("U8SDK 聚合"),
        s if s.contains("libshfinal.so") => Some("瑞星加固"),
        s if s.contains("libapkshell.so") => Some("APKProtect"),
        s if s.contains("libinwp001.so") => Some("硕云科技"),

        // --- 12. 开发框架识别 (辅助判断) ---
        s if s.contains("libflutter.so") || s.contains("libapp.so") => Some("Flutter 框架 (非壳)"),
        s if s.contains("libreactnativejni.so") => Some("React Native (非壳)"),
        s if s.contains("libmonosgen-2.0.so") || s.contains("libunity.so") => Some("Unity3D 游戏 (非壳)"),
        s if s.contains("libxamarin") => Some("Xamarin (非壳)"),

        _ => None,
    }
}

// 🔥 命令 1: 查壳
#[tauri::command]
async fn detect_packer(apk_path: String) -> Result<String, String> {
    let file = File::open(&apk_path).map_err(|e| format!("无法打开文件: {}", e))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).map_err(|e| format!("APK 解析失败: {}", e))?;

    let mut detected = Vec::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        let name = file.name();
        if let Some(packer) = get_packer_name(name) {
            if !detected.contains(&packer.to_string()) {
                detected.push(packer.to_string());
            }
        }
    }

    if detected.is_empty() {
        Ok("未发现常见加固特征 (可能是原包或未知壳)".to_string())
    } else {
        Ok(detected.join(", "))
    }
}

// 🔥 命令 2: 拉取并整理 Dex 文件
#[tauri::command]
async fn pull_and_organize_dex(device_id: String, pkg: String) -> Result<String, String> {
    // 1. 定义手机端 Dump 目录
    let remote_dump_dir = format!("/data/data/{}/files/dump_dex", pkg);
    
    // 2. 定义电脑端保存目录 (Downloads/Dump_PkgName_Time)
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let local_folder_name = format!("{}_dump_{}", pkg, timestamp);
    let local_save_path = download_dir.join(&local_folder_name);
    
    // 创建本地目录
    fs::create_dir_all(&local_save_path).map_err(|e| e.to_string())?;
    let local_save_str = local_save_path.to_string_lossy().to_string();

    // 3. 执行 adb pull
    // 注意：因为 /data/data 需要 root 权限，普通 pull 可能失败。
    // 建议先用 su 把文件复制到 /data/local/tmp/ 再 pull，或者直接 su -c tar
    
    // 方案：先 cp 到 tmp (确保有读写权限)
    let remote_tmp = format!("/data/local/tmp/{}_dump", pkg);
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("rm -rf {}; cp -r {} {}", remote_tmp, remote_dump_dir, remote_tmp)])?;
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("chmod -R 777 {}", remote_tmp)])?;
    
    let pull_res = cmd_exec("adb", &["-s", &device_id, "pull", &remote_tmp, &local_save_str])?;
    
    // 清理手机临时文件
    cmd_exec("adb", &["-s", &device_id, "shell", "rm -rf", &remote_tmp])?;

    // 4. 整理文件名 (把莫名其妙的名字改成 classes.dex, classes2.dex)
    // 遍历下载下来的文件夹
    if let Ok(entries) = fs::read_dir(&local_save_path) {
        let mut index = 1;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("dex") {
                let new_name = if index == 1 { "classes.dex".to_string() } else { format!("classes{}.dex", index) };
                let new_path = local_save_path.join(new_name);
                let _ = fs::rename(path, new_path);
                index += 1;
            }
        }
    }

    if pull_res.contains("pulled") {
        Ok(local_save_str)
    } else {
        Err(format!("拉取失败 (请确认应用是否运行且脱壳脚本已执行): {}", pull_res))
    }
}


// 🔥 新增：启动局域网扫描服务
fn start_mdns_discovery(app: tauri::AppHandle) {
    thread::spawn(move || {
        // 创建 mDNS 守护进程
        let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");
        
        // 监听 _adb._tcp.local. 服务类型
        let service_type = "_adb._tcp.local.";
        let receiver = mdns.browse(service_type).expect("Failed to browse");

        println!("正在扫描局域网 ADB 设备...");

        while let Ok(event) = receiver.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    // 获取到设备 IP 和端口
                    // 格式通常是: device_id._adb._tcp.local.
                    // info.get_addresses() 返回 IP 列表
                    // info.get_port() 返回端口
                    
                    if let Some(addr) = info.get_addresses().iter().next() {
                        let port = info.get_port();
                        let connect_addr = format!("{}:{}", addr, port);
                        println!("发现设备: {} ({})", info.get_fullname(), connect_addr);

                        // 尝试自动连接
                        // 注意：这里可能会频繁触发，建议加个缓存判断是否已连接
                        let _ = cmd_exec("adb", &["connect", &connect_addr]);
                        
                        // 通知前端刷新列表
                        let _ = app.emit("device-changed", ());
                    }
                }
                _ => {}
            }
        }
    });
}

// 🔥 核心命令：启动 mitmdump
#[tauri::command]
async fn start_mitmproxy(
    app: tauri::AppHandle, 
    port: u16, 
    state: State<'_, MitmState>
) -> Result<String, String> {

    // 🔥 第一步：霸道清场 (直接调用 Windows 系统命令杀进程)
    // 无论之前是谁启动的 mitmdump，统统干掉
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(&["/F", "/IM", "mitmdump-x86_64-pc-windows-msvc.exe"])
            .creation_flags(0x08000000) // 隐藏窗口运行
            .output();
            
        // 如果你的文件名改短了，也要试着杀一下短名字的
        let _ = std::process::Command::new("taskkill")
            .args(&["/F", "/IM", "mitmdump.exe"])
            .creation_flags(0x08000000)
            .output();
            
        // 给系统一点时间回收端口
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // 🔥 第二步：清理内存状态 (为了逻辑闭环)
    let mut child_guard = state.child.lock().unwrap();
    if let Some(child) = child_guard.take() {
        let _ = child.kill(); 
    }

    // 3. 获取脚本路径
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    // 先找 bin 目录
    let mut script_path = cwd.join("bin").join("traffic_relay.py");
    // 找不到再找 src-tauri/bin
    if !script_path.exists() {
        script_path = cwd.join("src-tauri").join("bin").join("traffic_relay.py");
    }

    let script_path_str = script_path.to_string_lossy().to_string();
    println!("准备启动，脚本: {}", script_path_str);

    // 4. 启动 Sidecar
    let (mut rx, child) = app.shell().sidecar("mitmdump")
        .map_err(|e| format!("无法找到 Sidecar: {}", e))?
        .args(&[
            "-p", &port.to_string(), 
            "--set", "block_global=false", 
            "--set", "ssl_insecure=true",
            "-s", &script_path_str
        ])
        .spawn()
        .map_err(|e| format!("启动失败: {}", e))?;

    // 5. 保存句柄
    *child_guard = Some(child);

    // 6. 监听日志
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let log = String::from_utf8_lossy(&line).to_string();
                    // 过滤掉那些没用的 Info 日志，只看关键的
                    if log.contains("Loading script") || log.contains("listening") || log.contains("{") {
                         println!("[Mitm]: {}", log); 
                    }
                    let _ = app.emit("mitm-traffic", log);
                }
                CommandEvent::Stderr(line) => {
                    let log = String::from_utf8_lossy(&line).to_string();
                    println!("[Mitm Error]: {}", log);
                }
                _ => {}
            }
        }
    });

    Ok(format!("代理已启动 (端口: {})", port))
}

#[tauri::command]
async fn stop_mitmproxy(state: State<'_, MitmState>) -> Result<String, String> {
    // 1. 先清理 Rust 内部的状态 (把句柄拿出来丢掉)
    let mut child_guard = state.child.lock().unwrap();
    let _ = child_guard.take(); // 这里直接 take 出来，如果它还活着，下面的 taskkill 会送它一程

    // 2. 🔥 核心：调用系统命令强杀 (双重保险)
    // 不管 Rust 认为它死没死，我们在系统层面再杀一次，确保端口释放
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt; // 确保引入扩展 trait

        // 杀掉长文件名的
        let _ = std::process::Command::new("taskkill")
            .args(&["/F", "/IM", "mitmdump-x86_64-pc-windows-msvc.exe"])
            .creation_flags(0x08000000) // 0x08000000 = CREATE_NO_WINDOW (隐藏黑框)
            .output();

        // 杀掉短文件名的 (防止改过名字)
        let _ = std::process::Command::new("taskkill")
            .args(&["/F", "/IM", "mitmdump.exe"])
            .creation_flags(0x08000000)
            .output();
    }

    println!("已执行强制停止指令");
    Ok("服务已停止".to_string())
}

// 🔥 核心命令：获取 CA 证书并推送到手机
// mitmdump 启动一次后，会在用户目录生成证书
#[tauri::command]
async fn install_cert_to_phone(device_id: String) -> Result<String, String> {
    // 1. 获取用户目录下的 .mitmproxy 文件夹
    let home_dir = directories::UserDirs::new().ok_or("无法获取用户目录")?.home_dir().to_path_buf();
    let mitm_dir = home_dir.join(".mitmproxy");

    // 🔥 优化：自动查找证书，兼容 .cer 和 .pem
    // Windows 通常生成 .cer，Linux/Mac 通常是 .pem
    let mut local_cert_path = mitm_dir.join("mitmproxy-ca-cert.cer");
    
    if !local_cert_path.exists() {
        // 如果 .cer 不存在，尝试找 .pem
        local_cert_path = mitm_dir.join("mitmproxy-ca-cert.pem");
    }

    // 再次检查
    if !local_cert_path.exists() {
        return Err("未找到证书文件！\n\n请先点击主界面的 '开始抓包 (Start)' 按钮，等待几秒钟让系统自动生成证书，然后再重试。".to_string());
    }

    let local_path_str = local_cert_path.to_string_lossy().to_string();
    // 安卓系统识别 .crt 后缀兼容性最好
    let remote_path = "/sdcard/Download/mitmproxy-ca-cert.crt"; 

    println!("正在推送证书: {} -> {}", local_path_str, remote_path);

    // 2. 推送到手机
    // 如果 device_id 为空，尝试推送到第一个设备
    let args = if device_id.is_empty() {
        vec!["push", &local_path_str, remote_path]
    } else {
        vec!["-s", &device_id, "push", &local_path_str, remote_path]
    };

    let output = cmd_exec("adb", &args)?;

    if output.to_lowercase().contains("error") {
        return Err(format!("推送失败: {}", output));
    }

    Ok(format!("证书已保存到手机：{}\n\n请在手机上打开：\n设置 -> 安全 -> 加密与凭据 -> 安装证书 -> CA 证书\n然后选择 Download 目录下的证书文件。", remote_path))
}

#[tauri::command]
async fn install_cert_root(device_id: String) -> Result<String, String> {
    // 1. 确定本地 PEM 证书路径
    let home = directories::UserDirs::new().unwrap().home_dir().to_path_buf();
    let pem_path = home.join(".mitmproxy").join("mitmproxy-ca-cert.pem");
    
    // 2. 这里的 hash 需要你手动算一次填进去，或者引入 openssl 库动态算
    // 假设 hash 是 c8750f0d (示例)
    let cert_hash = "c8750f0d"; 
    let system_cert_name = format!("{}.0", cert_hash);
    let remote_tmp = format!("/data/local/tmp/{}", system_cert_name);

    // 3. 推送
    cmd_exec("adb", &["-s", &device_id, "push", &pem_path.to_string_lossy(), &remote_tmp])?;

    // 4. 挂载系统分区并移动 (这是最关键的一步，高版本 Android 需要 mount -o remount,rw /)
    // 注意：Android 10+ 可能需要由 Magisk 模块来做 system 挂载，普通 mount 可能失败
    // 这里演示标准 Root 操作
    let cmd = format!(
        "su -c 'mount -o remount,rw /system && mv {} /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/{} && chown root:root /system/etc/security/cacerts/{}'",
        remote_tmp, system_cert_name, system_cert_name
    );
    
    let res = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;
    
    // 5. 软重启生效 (不重启证书不加载)
    // run_command("adb", &["-s", &device_id, "shell", "stop && start"])?; 
    // 或者
    // run_command("adb", &["-s", &device_id, "reboot"])?;

    Ok("证书已通过 Root 权限写入系统目录，请重启手机生效！".to_string())
}

#[tauri::command]
fn get_local_ip() -> String {
    use std::net::UdpSocket;
    // 这是一个常用技巧：连接一个公网 IP (Google DNS)，不需要实际发包
    // 系统会自动分配当前正在使用的局域网网卡 IP 给这个 Socket
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    return addr.ip().to_string();
                }
            }
        }
        Err(_) => {}
    }
    "127.0.0.1".to_string()
}

// 🔥 新增：重发请求命令
#[tauri::command]
async fn replay_request(
    method: String,
    url: String,
    headers: std::collections::HashMap<String, String>,
    body: Option<String>,
    proxy_port: u16,
) -> Result<String, String> {
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("代理配置错误: {}", e))?;

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .danger_accept_invalid_certs(true) // 忽略 SSL 证书错误 (这对逆向很重要)
        .build()
        .map_err(|e| e.to_string())?;

    // 1. 构建 Method
    let req_method = reqwest::Method::from_str(&method.to_uppercase())
        .map_err(|_| "无效的 HTTP 方法".to_string())?;

    // 2. 构建 Headers
    let mut header_map = HeaderMap::new();
    for (k, v) in headers {
        let k_lower = k.to_lowercase();
        
        // 🔥🔥 关键修改：过滤掉 Accept-Encoding 🔥🔥
        // 让 reqwest 自动处理压缩和解压，不要手动干预
        if k_lower == "content-length" || k_lower == "host" || k_lower == "accept-encoding" {
            continue;
        }
        
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
            header_map.insert(hn, hv);
        }
    }
    // 3. 构建 Request Builder
    let mut builder = client.request(req_method, &url).headers(header_map);

    // 4. 处理 Body (支持文本和 Base64)
    if let Some(b) = body {
        if b.starts_with("base64:") {
            // 解码二进制 Body
            let clean_b = b.replace("base64:", "");
            let bytes = general_purpose::STANDARD.decode(clean_b).unwrap_or_default();
            builder = builder.body(bytes);
        } else {
            // 普通文本 Body
            builder = builder.body(b);
        }
    }

    // 5. 发送请求
    let resp = builder.send().await.map_err(|e| format!("发送失败: {}", e))?;
    let status = resp.status();

    // 获取 Content-Type 用来判断是不是二进制
    let content_type = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // 读取所有字节
    let bytes = resp.bytes().await.map_err(|e| format!("读取失败: {}", e))?;

    // 🔥 智能判断：如果是 JSON/HTML/Text，转字符串；否则转 Base64
    let body_str = if content_type.contains("json") || content_type.contains("text") || content_type.contains("xml") || content_type.contains("javascript") {
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        // 如果是 Protobuf 或图片，返回 Base64 并在前面加标记，方便前端识别
        // 你的前端 NetworkSniffer 已经支持识别 "base64:" 前缀了
        format!("base64:{}", general_purpose::STANDARD.encode(&bytes))
    };

    // 截取前 2000 个字符用于预览 (太长了弹窗会卡)
    let preview_len = body_str.len().min(2000); 
    let preview = &body_str[..preview_len];

    Ok(format!("状态码: {}\nContent-Type: {}\n\n响应内容 (预览):\n{}", status, content_type, preview))
}

// ==========================================
//  主函数
// ==========================================

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(MitmState {
            child: Arc::new(Mutex::new(None)),
        })
        .manage(AdbState { 
            sockets: Arc::new(Mutex::new(HashMap::new())) 
        })
        .setup(|app| {
            let handle = app.handle().clone();
            // 启动原本的设备状态监听
            start_device_monitor(handle.clone());
            // 启动 mDNS 自动发现
            start_mdns_discovery(handle);
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
            rename_file,
            apk_decode, 
            scan_local_dir, 
            read_local_file, 
            save_local_file, 
            apk_build_sign_install,
            jadx_decompile,
            search_project,
            detect_packer,
            pull_and_organize_dex,
            start_mitmproxy,
            stop_mitmproxy,
            install_cert_to_phone,
            install_cert_root,
            get_local_ip,
            replay_request
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}