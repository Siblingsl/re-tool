use tauri::Emitter;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use crate::utils::{cmd_exec, create_command};
use crate::models::DeviceItem;
use mdns_sd::{ServiceDaemon, ServiceEvent};


#[tauri::command]
pub async fn get_all_devices() -> Result<Vec<DeviceItem>, String> {
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
pub async fn enable_wireless_mode(device_id: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "tcpip", "5555"])?;
    if output.contains("restarting in TCP mode") {
        Ok("已开启无线模式 (端口 5555)".to_string())
    } else {
        Err(format!("开启失败: {}", output))
    }
}

#[tauri::command]
pub async fn get_device_ip(device_id: String) -> Result<String, String> {
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
pub async fn adb_pair(address: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["connect", &address])?;
    if output.contains("connected to") || output.contains("already connected") {
        Ok("连接成功".to_string())
    } else {
        Err(format!("连接失败: {}", output))
    }
}

#[tauri::command]
pub async fn get_device_abi(device_id: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "getprop", "ro.product.cpu.abi"])?;
    Ok(output.trim().to_string())
}

// 检查设备是否 Root
#[tauri::command]
pub async fn check_is_rooted(device_id: String) -> Result<bool, String> {
    // 尝试执行 'su -c id'，如果成功且返回 uid=0，说明有 Root 权限
    let output = create_command("adb")
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
    let check_bin = create_command("adb")
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

// 两个后台监听任务
pub fn start_device_monitor(app: tauri::AppHandle) {
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

// 启动局域网扫描服务
pub fn start_mdns_discovery(app: tauri::AppHandle) {
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