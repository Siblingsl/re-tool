use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use base64::{Engine as _, engine::general_purpose};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

use crate::state::UnidbgState;


// ==========================================
// 2. 辅助函数
// ==========================================
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

// ==========================================
// 3. 核心命令 (Commands)
// ==========================================

// [A] 创建项目
#[tauri::command]
pub fn create_project(app: AppHandle, target_dir: String) -> Result<String, String> {
    let target_path = Path::new(&target_dir);
    
    // 检查非空
    if target_path.exists() && target_path.read_dir().map_err(|e| e.to_string())?.count() > 0 {
        return Err("目标文件夹不为空，请选择一个空文件夹".to_string());
    }

    // 获取内部模板 (必须在 tauri.conf.json 配置 resources)
    let template_path = app.path()
        .resolve("templates/unidbg-server", tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("无法定位内置模板: {}", e))?;

    // 复制
    copy_dir_all(&template_path, target_path)
        .map_err(|e| format!("创建项目失败: {}", e))?;

    Ok("项目创建成功".to_string())
}

// [B] 检查项目有效性
#[tauri::command]
pub fn check_project_valid(target_dir: String) -> bool {
    Path::new(&target_dir).join("pom.xml").exists()
}

// [C] 读取代码
#[tauri::command]
pub fn read_code(project_path: String) -> Result<String, String> {
    let file = Path::new(&project_path).join("src/main/java/com/retool/unidbg_server/service/UnidbgService.java");
    fs::read_to_string(file).map_err(|e| e.to_string())
}

// [D] 保存代码
#[tauri::command]
pub fn save_code(project_path: String, code: String) -> Result<String, String> {
    let file = Path::new(&project_path).join("src/main/java/com/retool/unidbg_server/service/UnidbgService.java");
    fs::write(file, code).map_err(|e| e.to_string())?;
    Ok("保存成功".to_string())
}

// [E] 获取 SO 列表
#[tauri::command]
pub fn list_so_files(project_path: String) -> Result<Vec<String>, String> {
    let dir = Path::new(&project_path).join("src/main/resources/natives");
    if !dir.exists() { return Ok(vec![]); }

    let mut files = vec![];
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().is_file() {
            files.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    Ok(files)
}

// [F] 导入 SO 文件
#[tauri::command]
pub fn import_so_file(project_path: String, file_name: String, base64_data: String) -> Result<String, String> {
    let dir = Path::new(&project_path).join("src/main/resources/natives");
    if !dir.exists() { fs::create_dir_all(&dir).map_err(|e| e.to_string())?; }

    let bytes = general_purpose::STANDARD.decode(base64_data).map_err(|e| format!("Base64 Error: {}", e))?;
    fs::write(dir.join(file_name), bytes).map_err(|e| e.to_string())?;
    Ok("导入成功".to_string())
}

// [G] 删除 SO 文件
#[tauri::command]
pub fn delete_so_file(project_path: String, file_name: String) -> Result<String, String> {
    let file = Path::new(&project_path).join("src/main/resources/natives").join(file_name);
    if file.exists() {
        fs::remove_file(file).map_err(|e| e.to_string())?;
    }
    Ok("删除成功".to_string())
}

// [H] 启动 Maven 服务
#[tauri::command]
pub async fn run_server(
    app: AppHandle, 
    state: State<'_, UnidbgState>, 
    project_path: String, 
    port: u16
) -> Result<String, String> {
    
    // 1. 获取锁
    let mut child_guard = state.server_child.lock().unwrap();

    // 🔥🔥 核心修复：如果检测到已存在进程，直接杀掉，而不是报错 🔥🔥
    if let Some(child) = child_guard.take() {
        println!(">>> 检测到残留服务进程，正在强制清理...");
        
        #[cfg(target_os = "windows")]
        {
            let pid = child.pid();
            // 使用 taskkill 杀掉进程树 (清理 java.exe)
            let _ = std::process::Command::new("taskkill")
                .args(&["/F", "/T", "/PID", &pid.to_string()])
                .output();
        }
        
        // 确保 Tauri 侧的句柄也关闭
        let _ = child.kill();
    }

    // 2. 准备启动命令
    #[cfg(target_os = "windows")] let cmd = "mvn.cmd";
    #[cfg(not(target_os = "windows"))] let cmd = "mvn";

    // 3. 启动新进程
    let (mut rx, child) = app.shell().command(cmd)
        .args(&["clean", "spring-boot:run", "-e", &format!("-Dspring-boot.run.arguments=--server.port={}", port)])
        .current_dir(PathBuf::from(&project_path))
        .spawn()
        .map_err(|e| format!("启动失败 (请确保已安装Maven): {}", e))?;

    // 4. 保存新句柄
    *child_guard = Some(child);

    // 5. 监听日志
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let log = String::from_utf8_lossy(&line).to_string();
                    if !log.starts_with("Download") && !log.starts_with("Progress") {
                        let _ = app_handle.emit("unidbg-log", log);
                    }
                }
                CommandEvent::Stderr(line) => {
                    let log = String::from_utf8_lossy(&line).to_string();
                    let _ = app_handle.emit("unidbg-error", log);
                }
                _ => {}
            }
        }
    });

    Ok("服务正在启动...".to_string())
}

// [I] 停止 Maven 服务
#[tauri::command]
pub fn stop_server(state: State<'_, UnidbgState>) -> Result<String, String> {
    let mut child_guard = state.server_child.lock().unwrap();

    if let Some(child) = child_guard.take() {
        // Windows 强力杀进程 (解决文件占用)
        #[cfg(target_os = "windows")]
        {
            let pid = child.pid(); 
            let _ = std::process::Command::new("taskkill")
                .args(&["/F", "/T", "/PID", &pid.to_string()])
                .output();
        }
        
        // 常规杀进程
        let _ = child.kill();
        return Ok("服务已停止".to_string());
    }
    Ok("服务未运行".to_string())
}

// [J] 接口转发
#[tauri::command]
pub async fn unidbg_request(path: String, payload: serde_json::Value) -> Result<String, String> {
    let client = reqwest::Client::new();
    // 假设端口是 9090 (如果要动态端口，可以从前端传或者存 State)
    let url = format!("http://127.0.0.1:9090/api/unidbg/{}", path);
    
    let res = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
        
    let text = res.text().await.map_err(|e| e.to_string())?;
    Ok(text)
}