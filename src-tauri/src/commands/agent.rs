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

static IS_CONNECTED: AtomicBool = AtomicBool::new(false);
static CURRENT_SESSION_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn init(_app_handle: AppHandle) {
    println!("[Agent] Init: Waiting for frontend to provide Session ID...");
}

#[tauri::command]
pub async fn connect_agent(app: AppHandle, session_id: String) -> Result<String, String> {
    println!("[Agent] 🔄 Frontend requested connection for Session ID: {}", session_id);

    let mut current_session = CURRENT_SESSION_ID.lock().unwrap();
    
    if let Some(existing_id) = current_session.as_ref() {
        if existing_id == &session_id && IS_CONNECTED.load(Ordering::SeqCst) {
            println!("[Agent] ⚠️ Already connected to Session: {}. Skipping.", session_id);
            return Ok("Already connected".to_string());
        }
    }

    *current_session = Some(session_id.clone());
    
    let handle = app.clone();
    let sid = session_id.clone();

    thread::spawn(move || {
        start_socket_client(handle, sid);
    });

    Ok(format!("Agent connecting with Session ID: {}", session_id))
}

fn start_socket_client(app_handle: AppHandle, session_id: String) {
    let url = format!("{}?sessionId={}", CLOUD_URL, session_id);
    println!("[Agent] Connecting to Cloud Brain: {}", url);

    // 克隆多个 handle 给不同的闭包使用
    let open_handle = app_handle.clone();
    let cmd_handle = app_handle.clone();
    let stream_handle = app_handle.clone();     // 给 AI 流使用
    let stream_end_handle = app_handle.clone(); // 给 AI 流结束使用
    let plan_handle = app_handle.clone();       // ✅ 新增：给任务计划更新使用

    IS_CONNECTED.store(true, Ordering::SeqCst);

    let socket_result = ClientBuilder::new(url)
        .transport_type(TransportType::Websocket)
        .on("open", move |_, _| {
            println!("[Agent] ✅ Socket Connection Established!");
            IS_CONNECTED.store(true, Ordering::SeqCst);
            let _ = open_handle.emit("agent-connected-success", true);
        })
        .on("close", |_, _| {
            println!("[Agent] ❌ Socket Connection Closed");
            IS_CONNECTED.store(false, Ordering::SeqCst);
        })
        .on("error", |err, _| {
            eprintln!("[Agent] ❌ Connection Error: {:#?}", err);
        })
        // ========================================================
        // 监听 AI 流式数据并转发给前端
        // ========================================================
        .on("ai_stream_chunk", move |payload: Payload, _| {
            let chunk_text = match payload {
                Payload::String(s) => s,
                Payload::Text(values) => {
                    if let Some(first_val) = values.first() {
                        if let Some(s) = first_val.as_str() {
                            s.to_string()
                        } else {
                            first_val.to_string()
                        }
                    } else {
                        String::new()
                    }
                },
                Payload::Binary(b) => String::from_utf8_lossy(&b).to_string(),
            };

            if !chunk_text.is_empty() {
                let _ = stream_handle.emit("ai_stream_chunk", chunk_text);
            }
        })
        .on("ai_stream_end", move |_, _| {
            println!("[Agent] 🏁 AI Stream Finished");
            let _ = stream_end_handle.emit("ai_stream_end", ()); 
        })
        // ========================================================
        // ✅ 新增：监听动态任务计划并转发给前端
        // ========================================================
        .on("agent_task_update", move |payload: Payload, _| {
            // 解析 Payload
            let json_str = match payload {
                Payload::String(s) => s,
                Payload::Text(values) => {
                    // 通常是 JSON 数组 [{"id":...}]
                    if let Some(v) = values.first() { v.to_string() } else { "[]".to_string() }
                },
                Payload::Binary(_) => "[]".to_string(),
            };
            
            // 尝试解析为 JSON Value 并转发
            if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
                 println!("[Agent] 📅 Received Task Update");
                 let _ = plan_handle.emit("agent_task_update", val);
            }
        })
        // ========================================================
        .on("agent_command", move |payload: Payload, socket: RawClient| {
            let handle = cmd_handle.clone();
            let socket_clone = socket.clone();

            println!("[Agent] 📦 Payload Received: {:?}", payload);

            let data_str = match payload {
                Payload::String(s) => s,
                Payload::Binary(_) => return,
                Payload::Text(values) => serde_json::to_string(&values).unwrap_or_default(),
            };

            match serde_json::from_str::<Value>(&data_str) {
                Ok(json_val) => {
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
        Ok(_) => {
            println!("[Agent] Socket client finished.");
            IS_CONNECTED.store(false, Ordering::SeqCst);
        }
        Err(e) => {
            eprintln!("[Agent] Failed to start socket client: {}", e);
            IS_CONNECTED.store(false, Ordering::SeqCst);
        }
    }
}

#[tauri::command]
pub async fn send_chat_message(session_id: String, message: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({ 
        "sessionId": session_id, 
        "message": message 
    });

    let res = client.post(format!("{}/api/chat", CLOUD_URL))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        Ok("Sent".to_string())
    } else {
        Err(format!("Cloud Error: {}", res.status()))
    }
}

async fn dispatch_command(app: &AppHandle, action: &str, params: Value) -> Result<Value, String> {
    match action {
        "GET_FILE_TREE" => {
            let raw_path = params["path"].as_str().ok_or("Missing path")?;
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
pub async fn notify_cloud_job_start(
    session_id: String, 
    file_path: String, 
    instruction: String 
) -> Result<String, String> {
    println!("[Agent] 🚀 Notifying Cloud. Instruction: {}", instruction);
    
    let client = reqwest::Client::new();
    let body = serde_json::json!({ 
        "sessionId": session_id, 
        "filePath": file_path,
        "instruction": instruction 
    });

    let res = client.post(format!("{}/api/client-ready", CLOUD_URL))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        Ok("Started".to_string())
    } else {
        Err(format!("Cloud Error: {}", res.status()))
    }
}

fn generate_file_tree(path_str: &str) -> Result<Vec<FileNode>, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("Path not found: {}", path_str));
    }
    Ok(read_dir_recursive(path))
}

fn read_dir_recursive(path: &Path) -> Vec<FileNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with(".") { continue; }

            let is_dir = path.is_dir();
            
            let mut key_path = path.to_string_lossy().to_string();
            if cfg!(target_os = "windows") {
                key_path = key_path.replace("\\\\?\\", "");
            }

            let node = FileNode {
                title: name.clone(),
                key: key_path,
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