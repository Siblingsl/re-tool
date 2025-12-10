use tauri::{Emitter, State};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};
use crate::state::MitmState;
use crate::utils::{cmd_exec, create_command};

// 启动 mitmdump
#[tauri::command]
pub async fn start_mitmproxy(
    app: tauri::AppHandle, 
    port: u16, 
    state: State<'_, MitmState>
) -> Result<String, String> {

    // 🔥 第一步：霸道清场 (直接调用 Windows 系统命令杀进程)
    // 无论之前是谁启动的 mitmdump，统统干掉
    #[cfg(target_os = "windows")]
    {
        let _ = create_command("taskkill")
            .args(&["/F", "/IM", "mitmdump-x86_64-pc-windows-msvc.exe"])
            .output();
            
        // 如果你的文件名改短了，也要试着杀一下短名字的
        let _ = create_command("taskkill")
            .args(&["/F", "/IM", "mitmdump.exe"])
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
pub async fn stop_mitmproxy(state: State<'_, MitmState>) -> Result<String, String> {
    // 1. 先清理 Rust 内部的状态 (把句柄拿出来丢掉)
    let mut child_guard = state.child.lock().unwrap();
    let _ = child_guard.take(); // 这里直接 take 出来，如果它还活着，下面的 taskkill 会送它一程

    // 2. 🔥 核心：调用系统命令强杀 (双重保险)
    // 不管 Rust 认为它死没死，我们在系统层面再杀一次，确保端口释放
    #[cfg(target_os = "windows")]
    {
        // 杀掉长文件名的
        let _ = create_command("taskkill")
            .args(&["/F", "/IM", "mitmdump-x86_64-pc-windows-msvc.exe"])
            .output();

        // 杀掉短文件名的 (防止改过名字)
        let _ = create_command("taskkill")
            .args(&["/F", "/IM", "mitmdump.exe"])
            .output();
    }

    println!("已执行强制停止指令");
    Ok("服务已停止".to_string())
}

// 获取 CA 证书并推送到手机
// mitmdump 启动一次后，会在用户目录生成证书
#[tauri::command]
pub async fn install_cert_to_phone(device_id: String) -> Result<String, String> {
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
pub async fn install_cert_root(device_id: String) -> Result<String, String> {
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
    
    let _res = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;
    
    // 5. 软重启生效 (不重启证书不加载)
    // run_command("adb", &["-s", &device_id, "shell", "stop && start"])?; 
    // 或者
    // run_command("adb", &["-s", &device_id, "reboot"])?;

    Ok("证书已通过 Root 权限写入系统目录，请重启手机生效！".to_string())
}

#[tauri::command]
pub fn get_local_ip() -> String {
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

// 重发请求命令
#[tauri::command]
pub async fn replay_request(
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