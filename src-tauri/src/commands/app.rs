use crate::utils::{cmd_exec, get_android_label, create_command};
use crate::models::{AppItem, AppDetail};
use directories::UserDirs;

#[tauri::command]
pub async fn get_device_apps(device_id: String, device_type: String) -> Result<Vec<AppItem>, String> {
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

// 🔥 新增：获取运行中的应用列表
#[tauri::command]
pub async fn get_running_apps(device_id: String) -> Result<Vec<String>, String> {
    // 使用 ps -A 过滤 u0_a 开头的进程
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "ps", "-A", "-o", "USER,NAME"])?;
    let mut running_pkgs = Vec::new();
    
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let user = parts[0];
            let pkg = parts[parts.len()-1]; // 最后一部分通常是包名
            
            // 简单 heuristic: 包含点，且不是系统应用(简单判断)
            // 真实场景: 用户应用通常是 u0_aXXX
            if (user.starts_with("u0_a") || pkg.contains('.')) && !pkg.starts_with('[') && !pkg.contains('/') {
                 if !running_pkgs.contains(&pkg.to_string()) {
                     running_pkgs.push(pkg.to_string());
                 }
            }
        }
    }
    Ok(running_pkgs)
}

#[tauri::command]
pub async fn install_apk(device_id: String, apk_path: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "install", "-r", &apk_path])?;
    if output.contains("Success") {
        Ok("安装成功".to_string())
    } else {
        Err(format!("安装失败: {}", output))
    }
}

#[tauri::command]
pub async fn get_app_detail(device_id: String, pkg: String) -> Result<AppDetail, String> {
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

// 启动 App (相当于 Spawn 的前置动作)
#[tauri::command]
pub async fn launch_app(device_id: String, pkg: String) -> Result<String, String> {
    // adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1
    // 或者用 am start (需要知道 Activity，monkey 更通用)
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "monkey", "-p", &pkg, "-c", "android.intent.category.LAUNCHER", "1"])?;
    
    if output.contains("Events injected") {
        Ok("应用已启动".to_string())
    } else {
        Err(format!("启动失败: {}", output))
    }
}

// 强行停止 App
#[tauri::command]
pub async fn stop_app(device_id: String, pkg: String) -> Result<String, String> {
    cmd_exec("adb", &["-s", &device_id, "shell", "am", "force-stop", &pkg])?;
    Ok("应用已停止".to_string())
}

// 获取当前前台应用包名
#[tauri::command]
pub async fn get_foreground_app(device_id: String) -> Result<String, String> {
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

// 提取 APK (包含详细错误日志)
#[tauri::command]
pub async fn extract_apk(device_id: String, pkg: String) -> Result<String, String> {
    // 1. 获取 APK 路径
    let path_output = create_command("adb")
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
    let pull_output = create_command("adb")
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