use crate::commands;
use crate::models::FileNode;
use rust_socketio::{ClientBuilder, Payload, RawClient, TransportType};
use serde_json::{json, Value};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use capstone::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use goblin::elf::Elf;

// ⚠️ 生产环境请改为云服务器 IP
const CLOUD_URL: &str = "http://127.0.0.1:3000"; 

// 静态变量：防止 React 的 StrictMode 导致重复连接
static IS_CONNECTED: AtomicBool = AtomicBool::new(false);

// 使用标准库 Mutex 记录当前的 SessionID
static CURRENT_SESSION_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn init(_app_handle: AppHandle) {
    // 这里的 init 不再自动连接，改为等待前端指令
    println!("[Agent] Init: Waiting for frontend to provide Session ID...");
}

#[tauri::command]
pub async fn connect_agent(app: AppHandle, session_id: String) -> Result<String, String> {
    println!("[Agent] 🔄 Frontend requested connection for Session ID: {}", session_id);

    let handle = app.clone();
    let sid = session_id.clone();

    // 直接启动新线程去连接，不判断旧状态
    // 注意：rust_socketio 的 client.connect() 是阻塞的，所以必须放在 thread 里
    thread::spawn(move || {
        start_socket_client(handle, sid);
    });

    Ok(format!("Agent connecting with Session ID: {}", session_id))
}

// 🔥 修改：接收 session_id 参数，而不是用常量
fn start_socket_client(app_handle: AppHandle, session_id: String) {
    let url = format!("{}?sessionId={}", CLOUD_URL, session_id);
    println!("[Agent] Connecting to Cloud Brain: {}", url);

    let open_handle = app_handle.clone();
    let callback_handle = app_handle.clone();
    
    let socket_result = ClientBuilder::new(url)
        .transport_type(TransportType::Websocket)
        .on("open", move |_, _| {
            println!("[Agent] ✅ Socket Connection Established!");
            // 发送事件给前端：告诉它“我连上了，你可以去通知云端了”
            let _ = open_handle.emit("agent-connected-success", true);
        })
        .on("close", |_, _| println!("[Agent] ❌ Socket Connection Closed"))
        .on("error", |err, _| eprintln!("[Agent] ❌ Connection Error: {:#?}", err))
        .on("agent_command", move |payload: Payload, socket: RawClient| {
            let handle = callback_handle.clone();
            let socket_clone = socket.clone();

            println!("[Agent] 📦 Payload Received: {:?}", payload);

            let data_str = match payload {
                Payload::String(s) => s,
                Payload::Binary(_) => return,
                Payload::Text(values) => serde_json::to_string(&values).unwrap_or_default(),
            };

            match serde_json::from_str::<Value>(&data_str) {
                Ok(json_val) => {
                    // 兼容 Array 和 Object
                    let cmd_obj_opt = if json_val.is_array() {
                        json_val.as_array().unwrap().iter().find(|v| v.is_object() && v.get("id").is_some())
                    } else if json_val.is_object() {
                        Some(&json_val)
                    } else {
                        None
                    };

                    if let Some(cmd_obj) = cmd_obj_opt {
                        let cmd_id = cmd_obj["id"].as_str().unwrap_or("").to_string();
                        let action = cmd_obj["action"].as_str().unwrap_or("").to_string();
                        let params = cmd_obj["params"].clone();

                        println!("[Agent] 🤖 Executing: {} (ID: {})", action, cmd_id);

                        thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            let result = rt.block_on(async {
                                dispatch_command(&handle, &action, params).await
                            });

                            let response = match result {
                                Ok(data) => json!({ "id": cmd_id, "status": "SUCCESS", "data": data }),
                                Err(err) => json!({ "id": cmd_id, "status": "ERROR", "data": err }),
                            };

                            let _ = socket_clone.emit("command_result", response);
                        });
                    }
                },
                Err(e) => eprintln!("[Agent] JSON Parse Error: {}", e),
            }
        })
        .connect();

    match socket_result {
        Ok(_) => loop { thread::sleep(Duration::from_secs(10)); },
        Err(e) => eprintln!("[Agent] Failed to start socket client: {}", e),
    }
}

// 指令分发器保持不变
async fn dispatch_command(app: &AppHandle, action: &str, params: Value) -> Result<Value, String> {
    match action {
        "GET_FILE_TREE" => {
            let raw_path = params["path"].as_str().ok_or("Missing path")?;
             
             // 🔥🔥🔥 关键修复：调用递归扫描，返回 FileNode 结构，而不是 String 列表
             // 我们复用 apk.rs 中的逻辑，或者在这里重新实现一个干净的版本
             let tree = generate_file_tree(raw_path)?;
             
             println!("[Agent] Tree generated. Root items: {}", tree.len());
             Ok(json!(tree))
        }
        "READ_FILE" => {
            let path = params["path"].as_str().ok_or("Missing path")?;
            println!("[Agent] Reading file: {}", path);
            let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
            Ok(json!(content))
        }
        "GET_ASM" => {
            let lib_path = params["libPath"].as_str().ok_or("Missing libPath")?;
            let symbol = params["symbol"].as_str().ok_or("Missing symbol")?;
            let asm_code = perform_capstone_disassembly(lib_path, symbol)?;
            Ok(json!(asm_code))
        }
        "EXEC_FRIDA" => {
            let script = params["script"].as_str().ok_or("Missing script")?;
            let package = params["package"].as_str().ok_or("Missing package")?;
            let device_id = params["deviceId"].as_str().unwrap_or("").to_string();
            
            let result = commands::frida::run_frida_script(
                app.clone(), 
                device_id, 
                package.to_string(), 
                script.to_string()
            ).await.map_err(|e| e.to_string())?;
            
            Ok(json!(result)) 
        }
        "DUMP_DEX" => {
            let package = params["package"].as_str().ok_or("Missing package")?;
            let result = commands::apk::detect_packer(package.to_string())
                .await.map_err(|e| e.to_string())?;
            Ok(json!(result))
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

#[tauri::command]
pub async fn notify_cloud_job_start(session_id: String, file_path: String) -> Result<String, String> {
    println!("[Agent] 🚀 Local processing finished. Notifying Cloud Brain...");
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "sessionId": session_id, "filePath": file_path });

    let res = client.post(format!("{}/api/client-ready", CLOUD_URL))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to contact cloud: {}", e))?;

    if res.status().is_success() {
        println!("[Agent] ✅ Cloud Brain activated!");
        Ok("Cloud task started".to_string())
    } else {
        Err(format!("Cloud returned error: {}", res.status()))
    }
}

// 辅助函数

// ✅ 新增：专门用于生成标准 FileNode 树的函数
fn generate_file_tree(path_str: &str) -> Result<Vec<FileNode>, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("Path not found: {}", path_str));
    }
    // 调用递归辅助函数
    Ok(read_dir_recursive(path))
}

// 递归扫描目录，返回 FileNode 结构体
fn read_dir_recursive(path: &Path) -> Vec<FileNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // 过滤隐藏文件
            if name.starts_with(".") { continue; }

            let is_dir = path.is_dir();
            
            // 🔥 修复路径：去掉 Windows 的 \\?\ 前缀，云端看着更舒服
            let mut key_path = path.to_string_lossy().to_string();
            if cfg!(target_os = "windows") {
                key_path = key_path.replace("\\\\?\\", "");
            }

            let node = FileNode {
                title: name.clone(),
                key: key_path,
                is_leaf: !is_dir,
                // 如果是目录，递归扫描；如果是文件，children 为 None
                children: if is_dir { Some(read_dir_recursive(&path)) } else { None },
            };

            nodes.push(node);
        }
    }
    // 排序：文件夹在前
    nodes.sort_by(|a, b| {
        if a.is_leaf == b.is_leaf { a.title.cmp(&b.title) } else { a.is_leaf.cmp(&b.is_leaf) }
    });
    nodes
}

fn list_files_safe(dir: &str, depth: usize) -> std::io::Result<Vec<String>> {
    if depth > 5 { return Ok(vec![]); } 

    let mut files = Vec::new();
    let path = Path::new(dir);

    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        // 🔥 严格过滤，防止卡死
        if name_str == "node_modules" || name_str == "target" || name_str == ".git" || name_str == "AppData" || name_str.starts_with('.') {
            return Ok(files);
        }
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    files.push(path.to_string_lossy().to_string());
                } else if path.is_dir() {
                    if let Ok(sub_files) = list_files_safe(&path.to_string_lossy(), depth + 1) {
                        files.extend(sub_files);
                    }
                }
            }
        }
    }
    Ok(files)
}

fn perform_capstone_disassembly(so_path: &str, target_symbol: &str) -> Result<String, String> {
    println!("[Capstone] Analyzing: {} for symbol: {}", so_path, target_symbol);
    let buffer = fs::read(so_path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&buffer).map_err(|e| e.to_string())?;
    let sym = elf.dynsyms.iter().find(|s| {
        if let Some(name) = elf.dynstrtab.get_at(s.st_name) { return name.contains(target_symbol); }
        false
    }).ok_or("Symbol not found")?;
    
    let offset = sym.st_value as usize;
    if offset >= buffer.len() { return Err("Offset out of bounds".into()); }
    let size = if sym.st_size > 0 { sym.st_size as usize } else { 200 };
    let end = std::cmp::min(offset + size, buffer.len());
    
    let cs = Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build().map_err(|e| e.to_string())?;
    let insns = cs.disasm_all(&buffer[offset..end], offset as u64).map_err(|e| e.to_string())?;
    
    let mut asm = String::new();
    for i in insns.iter() {
        asm.push_str(&format!("0x{:x}:  {} {}\n", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")));
    }
    Ok(asm)
}