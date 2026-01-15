use std::path::{Path, PathBuf}; // ✅ 引入 PathBuf
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use zip::ZipArchive;
use directories::UserDirs;
use walkdir::WalkDir;
use rayon::prelude::*;
use tauri::{AppHandle, Manager, Emitter};
use tauri::path::BaseDirectory;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use crate::models::{FileNode, SearchResult, SoFile};
use crate::utils::{cmd_exec, get_packer_name, is_text_file, create_command};

// ... (read_dir_recursive, apk_decode, scan_local_dir, read_local_file, save_local_file, apk_build_sign_install 保持不变) ...
// 为了节省篇幅，这里省略上面未修改的辅助函数，请保留你原有的代码

fn read_dir_recursive(path: &Path) -> Vec<FileNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let is_dir = file_type.is_dir();
            if name.starts_with(".") || name == "build" || name == "dist" { continue; }
            let node = FileNode {
                title: name.clone(),
                key: path.to_string_lossy().to_string(),
                is_leaf: !is_dir,
                children: if is_dir { Some(read_dir_recursive(&path)) } else { None },
            };
            nodes.push(node);
        }
    }
    nodes.sort_by(|a, b| {
        if a.is_leaf == b.is_leaf { a.title.cmp(&b.title) } else { a.is_leaf.cmp(&b.is_leaf) }
    });
    nodes
}

#[tauri::command]
pub async fn apk_decode(apk_path: String) -> Result<String, String> {
    let output_dir = format!("{}_src", apk_path.trim_end_matches(".apk"));
    let _ = fs::remove_dir_all(&output_dir);
    let output = create_command("apktool")
        .args(&["d", "-f", &apk_path, "-o", &output_dir])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() { Ok(output_dir) } else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
}

#[tauri::command]
pub async fn scan_local_dir(path: String) -> Result<Vec<FileNode>, String> {
    let root = Path::new(&path);
    if !root.exists() { return Err("目录不存在".to_string()); }
    Ok(read_dir_recursive(root))
}

#[tauri::command]
pub async fn read_local_file(path: String) -> Result<String, String> {
    fs::read_to_string(&path).map_err(|e| format!("读取失败: {}", e))
}

#[tauri::command]
pub async fn save_local_file(path: String, content: String) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn apk_build_sign_install(project_dir: String, device_id: String) -> Result<String, String> {
    let unsigned_apk = format!("{}_unsigned.apk", project_dir);
    let build_res = create_command("apktool")
        .args(&["b", &project_dir, "-o", &unsigned_apk])
        .output()
        .map_err(|e| format!("调用 apktool 失败: {}", e))?;
    if !build_res.status.success() { return Err(format!("回编译失败: {}", String::from_utf8_lossy(&build_res.stderr))); }
    
    let possible_paths = vec!["resources/uber-apk-signer.jar", "src-tauri/resources/uber-apk-signer.jar", "../resources/uber-apk-signer.jar"];
    let mut signer_jar = "";
    for path in &possible_paths { if std::path::Path::new(path).exists() { signer_jar = path; break; } }
    if signer_jar.is_empty() { signer_jar = "resources/uber-apk-signer.jar"; }
    
    let sign_res = create_command("java").args(&["-jar", signer_jar, "-a", &unsigned_apk, "--allowResign"]).output();
    let target_apk = if let Ok(res) = sign_res {
        if res.status.success() { format!("{}_unsigned-aligned-debugSigned.apk", project_dir) } else { unsigned_apk }
    } else { unsigned_apk };

    let install_res = cmd_exec("adb", &["-s", &device_id, "install", "-r", "-t", &target_apk])?;
    if install_res.contains("Success") { Ok("编译、签名并安装成功！".to_string()) } else { Err(format!("安装失败: {}", install_res)) }
}

// 🔥🔥 核心修改：支持绝对路径 & 自定义输出目录 🔥🔥
#[tauri::command]
pub async fn jadx_decompile(app: AppHandle, apk_path: String, output_dir: Option<String>) -> Result<String, String> {
    
    // 0. Java 环境检查
    if Command::new("java").arg("-version").output().is_err() {
        return Err("未检测到 Java 环境！\nJADX 需要 Java 才能运行。\n请安装 JDK 11+ 并配置环境变量。".to_string());
    }

    // 1. 动态解析内置 JADX 路径
    let resource_path = app.path()
        .resolve("resources/jadx/bin/jadx.bat", BaseDirectory::Resource)
        .map_err(|e| format!("无法定位内置 JADX: {}", e))?;
    
    let mut jadx_path_str = resource_path.to_string_lossy().to_string();
    if cfg!(target_os = "windows") {
        jadx_path_str = jadx_path_str.replace("\\\\?\\", "");
    }

    if !Path::new(&jadx_path_str).exists() {
        return Err(format!("内置 JADX 文件丢失: {}", jadx_path_str));
    }

    // 2. 确定输入 APK 路径 (处理绝对路径)
    let input_path = Path::new(&apk_path);
    if !input_path.exists() {
        return Err(format!("找不到 APK 文件: {}", apk_path));
    }
    
    // 获取文件名 (例如 com.example.app)
    let file_stem = input_path.file_stem()
        .and_then(|s| s.to_str())
        .ok_or("无效的文件名")?;

    // 3. 构造输出目录
    // 优先级: 前端传入的 output_dir > 系统下载目录 > 临时目录
    let base_dir = if let Some(custom_dir) = output_dir {
        if custom_dir.is_empty() {
            // 如果传了空字符串，回退到下载目录
            UserDirs::new().ok_or("无法获取用户目录")?.download_dir().ok_or("无法获取下载目录")?.to_path_buf()
        } else {
            PathBuf::from(custom_dir)
        }
    } else {
        // 默认放到下载目录的 ReTool_Workspace 文件夹下，防止乱放
        let download = UserDirs::new().ok_or("无法获取用户目录")?.download_dir().ok_or("无法获取下载目录")?.to_path_buf();
        download.join("ReTool_Workspace")
    };

    // 最终输出路径: /path/to/workspace/com.example.app_jadx_src
    let final_output_dir = base_dir.join(format!("{}_jadx_src", file_stem));
    let final_output_str = final_output_dir.to_string_lossy().to_string();

    // 确保父目录存在
    if let Some(parent) = final_output_dir.parent() {
        let _ = fs::create_dir_all(parent);
    }
    
    // 清理旧目录
    if final_output_dir.exists() {
        let _ = fs::remove_dir_all(&final_output_dir);
    }

    println!("[JADX] 启动: {} \n -> 输入: {} \n -> 输出: {}", jadx_path_str, apk_path, final_output_str);

    // 3. 构建命令
    let mut cmd_builder = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", &jadx_path_str, "-d", &final_output_str, &apk_path]);
        c.creation_flags(0x08000000); 
        c
    } else {
        let mut c = Command::new(&jadx_path_str);
        c.args(["-d", &final_output_str, &apk_path]);
        c
    };

    cmd_builder.stdout(Stdio::piped());
    cmd_builder.stderr(Stdio::piped());

    // 4. 启动进程
    let mut child = cmd_builder.spawn()
        .map_err(|e| format!("无法启动 JADX 进程: {}", e))?;

    let stderr = child.stderr.take().ok_or("无法获取 stderr")?;
    let stderr_thread = std::thread::spawn(move || {
        let mut err_msg = String::new();
        let mut reader = BufReader::new(stderr);
        let _ = reader.read_to_string(&mut err_msg);
        err_msg
    });

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(_l) = line {
                let _ = app.emit("jadx-progress-tick", ()); 
            }
        }
    }

    let status = child.wait().map_err(|e| format!("等待 JADX 结束失败: {}", e))?;
    let err_output = stderr_thread.join().unwrap_or_default();

    if status.success() {
        println!("[JADX] 成功！输出: {}", final_output_str);
        Ok(final_output_str) // 返回绝对路径
    } else {
        if final_output_dir.join("sources").exists() {
             println!("[JADX] 成功(带警告)！");
             Ok(final_output_str)
        } else {
            let error_msg = if err_output.trim().is_empty() { format!("退出码: {:?}", status.code()) } else { err_output };
            Err(format!("JADX 异常退出:\n{}", error_msg))
        }
    }
}

// ... (search_project, detect_packer, pull_and_organize_dex, get_apk_path, lists_so_files 保持不变) ...
#[tauri::command]
pub async fn search_project(project_dir: String, query: String) -> Result<Vec<SearchResult>, String> {
    let query = query.to_lowercase();
    let entries: Vec<_> = WalkDir::new(&project_dir).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).collect();
    let results: Vec<SearchResult> = entries.par_iter().flat_map(|entry| {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();
            let mut local_results = Vec::new();
            if let Some(fname) = path.file_name() {
                if fname.to_string_lossy().to_lowercase().contains(&query) {
                     local_results.push(SearchResult { file_path: path_str.clone(), line_num: 0, content: fname.to_string_lossy().to_string(), match_type: "file".to_string() });
                }
            }
            if is_text_file(&path_str) {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for (i, line) in content.lines().enumerate() {
                        if line.to_lowercase().contains(&query) {
                            local_results.push(SearchResult { file_path: path_str.clone(), line_num: i + 1, content: line.trim().to_string(), match_type: "code".to_string() });
                            if local_results.len() > 20 { break; } 
                        }
                    }
                }
            }
            local_results
        }).collect();
    let final_results = results.into_iter().take(500).collect();
    Ok(final_results)
}

#[tauri::command]
pub async fn detect_packer(apk_path: String) -> Result<String, String> {
    let file = File::open(&apk_path).map_err(|e| format!("无法打开文件: {}", e))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).map_err(|e| format!("APK 解析失败: {}", e))?;
    let mut detected = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        if let Some(packer) = get_packer_name(file.name()) {
            if !detected.contains(&packer.to_string()) { detected.push(packer.to_string()); }
        }
    }
    if detected.is_empty() { Ok("未发现常见加固特征".to_string()) } else { Ok(detected.join(", ")) }
}

#[tauri::command]
pub async fn pull_and_organize_dex(device_id: String, pkg: String) -> Result<String, String> {
    let remote_dump_dir = format!("/data/data/{}/files/dump_dex", pkg);
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let local_folder_name = format!("{}_dump_{}", pkg, timestamp);
    let local_save_path = download_dir.join(&local_folder_name);
    fs::create_dir_all(&local_save_path).map_err(|e| e.to_string())?;
    let local_save_str = local_save_path.to_string_lossy().to_string();
    let remote_tmp = format!("/data/local/tmp/{}_dump", pkg);
    
    // 1. 尝试直接拉取 remote_tmp (适配手动脚本 dump 到 /data/local/tmp 的情况)
    let check_tmp_res = cmd_exec("adb", &["-s", &device_id, "shell", &format!("ls {}", remote_tmp)]);
    let tmp_exists = check_tmp_res.is_ok() && !check_tmp_res.unwrap().contains("No such file");

    if !tmp_exists {
        // 2. 如果 tmp 不存在，尝试从 App 数据目录复制 (适配 frida-dexdump 默认行为)
        println!("Tmp dump not found, trying data directory...");
        cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("cp -r {} {}", remote_dump_dir, remote_tmp)])?;
        cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("chmod -R 777 {}", remote_tmp)])?;
    } else {
        // 确保权限
        cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("chmod -R 777 {}", remote_tmp)])?;
    }

    let pull_res = cmd_exec("adb", &["-s", &device_id, "pull", &remote_tmp, &local_save_str])?;
    
    // 只有在是我们自己复制出来的情况下才清理，或者始终保留？为了安全起见，可以选择不清理或者询问用户。
    // 这里保持清理逻辑，但只清理 tmp
    cmd_exec("adb", &["-s", &device_id, "shell", "rm -rf", &remote_tmp])?;

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
    if pull_res.contains("pulled") { Ok(local_save_str) } else { Err(format!("拉取失败: {}", pull_res)) }
}

#[tauri::command]
pub async fn get_apk_path(device_id: String, pkg: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "pm", "path", &pkg])?;
    for line in output.lines() {
        if let Some(path) = line.trim().strip_prefix("package:") {
            if path.ends_with("base.apk") || !output.contains("base.apk") { return Ok(path.to_string()); }
        }
    }
    Err("未找到 APK 路径".to_string())
}

#[tauri::command]
pub async fn lists_so_files(device_id: String, apk_path: String) -> Result<Vec<SoFile>, String> {
    println!(">>> 正在获取 SO 列表: {}", apk_path);
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let temp_filename = format!("temp_scan_{}.apk", timestamp);
    let temp_apk_path = download_dir.join(&temp_filename);
    let temp_apk_str = temp_apk_path.to_string_lossy().to_string();
    let pull_res = cmd_exec("adb", &["-s", &device_id, "pull", &apk_path, &temp_apk_str]);
    if let Err(e) = pull_res { return Err(format!("拉取 APK 失败: {}", e)); }
    std::thread::sleep(std::time::Duration::from_millis(200));
    let file = fs::File::open(&temp_apk_path).map_err(|e| format!("无法打开 APK: {}", e))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).map_err(|e| format!("APK 解析失败: {}", e))?;
    let mut so_list = Vec::new();
    let base_dir = apk_path.rsplitn(2, '/').nth(1).unwrap_or(""); 
    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        let name = file.name().to_string();
        if name.ends_with(".so") && name.contains("lib/") {
            let file_name = name.split('/').last().unwrap().to_string();
            let size = file.size().to_string();
            let arch = if name.contains("arm64") { "arm64-v8a" } else if name.contains("armeabi") { "armeabi-v7a" } else if name.contains("x86_64") { "x86_64" } else if name.contains("x86") { "x86" } else { "unknown" };
            let disk_arch = if arch == "arm64-v8a" { "arm64" } else { "arm" };
            let disk_path = format!("{}/lib/{}/{}", base_dir, disk_arch, file_name);
            so_list.push(SoFile { name: file_name, zip_path: name, disk_path, size, arch: arch.to_string() });
        }
    }
    let _ = fs::remove_file(temp_apk_path);
    so_list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(so_list)
}