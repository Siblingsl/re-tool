use crate::commands;
use crate::models::FileNode;
use regex::Regex;
use rust_socketio::{ClientBuilder, Payload, RawClient, TransportType};
use serde_json::{json, Value};
use walkdir::WalkDir;
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use capstone::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use goblin::elf::Elf;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use rayon::prelude::*; // 引入并行迭代器

// ⚠️ 生产环境请改为云服务器 IP
const CLOUD_URL: &str = "http://127.0.0.1:3000"; 

static IS_CONNECTED: AtomicBool = AtomicBool::new(false);
static CURRENT_SESSION_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn init(_app_handle: AppHandle) {
    println!("[Agent] Init: Waiting for frontend to provide Session ID...");
}

#[derive(serde::Serialize, Clone)]
struct SearchResult {
    file: String,
    line: usize,
    content: String,
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
        // ✅ [新增] 全局代码搜索能力
        "SEARCH_CODE" => {
            let root_path = params["rootPath"].as_str().ok_or("Missing rootPath")?;
            let keyword = params["keyword"].as_str().ok_or("Missing keyword")?;
            let max_results = params["maxResults"].as_u64().unwrap_or(50) as usize;
            
            println!("[Agent] 🔍 Searching for '{}' in {}", keyword, root_path);
            
            // 🔥 核心修复：将繁重的搜索任务放入阻塞线程池
            // 这样主线程依然能响应心跳，不会导致 Timeout
            let root_path_owned = root_path.to_string();
            let keyword_owned = keyword.to_string();
            
            let results = tokio::task::spawn_blocking(move || {
                search_files(&root_path_owned, &keyword_owned, max_results)
            }).await
            .map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Search error: {}", e))?; // 处理 search_files 的 Result

            println!("[Agent] ✅ Found {} matches", results.len());
            Ok(json!(results))
        }
        // ✅ [新增] 精准切片能力
        "GET_METHOD" => {
            let file_path = params["path"].as_str().ok_or("Missing path")?;
            let method_name = params["method"].as_str().ok_or("Missing method")?;
            
            println!("[Agent] ✂️ Slicing method '{}' from {}", method_name, file_path);
            
            // 同样放入 blocking 线程防止卡死
            let f_path = file_path.to_string();
            let m_name = method_name.to_string();
            
            let code_block = tokio::task::spawn_blocking(move || {
                extract_method_body(&f_path, &m_name)
            }).await.map_err(|e| e.to_string())??;
            
            println!("[Agent] ✅ Extracted {} chars", code_block.len());
            Ok(json!(code_block))
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

fn search_files(root_dir: &str, keyword: &str, max_limit: usize) -> Result<Vec<SearchResult>, String> {
    let path = Path::new(root_dir);
    if !path.exists() {
        return Err(format!("Path not found: {}", root_dir));
    }

    let keyword_lower = keyword.to_lowercase();
    
    // 1. 快速收集所有待搜索的文件路径
    // WalkDir 是惰性的，我们先把它 collect 成一个 Vec，方便后面并行处理
    let entries: Vec<_> = WalkDir::new(root_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        // 简单过滤：只看小于 1MB 的文件，且后缀名匹配
        .filter(|e| {
            let p = e.path();
            if let Ok(meta) = p.metadata() {
                if meta.len() > 1024 * 1024 { return false; }
            }
            is_searchable_ext(p)
        })
        .collect();

    println!("[Agent] 🚀 Found {} candidate files. Starting parallel search...", entries.len());

    // 2. 使用 Rayon 进行并行搜索
    // par_iter() 会自动把任务分发给所有 CPU 核心
    let results = Arc::new(Mutex::new(Vec::new())); // 线程安全的容器
    
    entries.par_iter().for_each(|entry| {
        // 如果结果已经够了，尽早退出 (Rayon 比较难强行中断，这里是软中断)
        if let Ok(guard) = results.lock() {
            if guard.len() >= max_limit { return; }
        }

        let path = entry.path();
        if let Ok(content) = fs::read_to_string(path) {
            // 快速预检
            if !content.to_lowercase().contains(&keyword_lower) {
                return;
            }

            // 逐行匹配
            for (idx, line) in content.lines().enumerate() {
                if line.to_lowercase().contains(&keyword_lower) {
                    let preview = if line.len() > 200 { 
                        format!("{}...", &line[..200]) 
                    } else { 
                        line.to_string() 
                    };
                    
                    // Windows 路径修正
                    let display_path = path.to_string_lossy().replace("\\", "/");

                    // 写入结果
                    if let Ok(mut guard) = results.lock() {
                        if guard.len() < max_limit {
                            guard.push(SearchResult {
                                file: display_path,
                                line: idx + 1,
                                content: preview.trim().to_string(),
                            });
                        }
                    }
                    // 只要找到一行就可以跳出当前文件（或者你想找所有行也行）
                    // 这里为了性能，找到一个文件有匹配就记录（或者记录所有行，看你需求）
                    // 你的原逻辑是记录所有行，这里保持一致
                }
            }
        }
    });

    let mut final_results = results.lock().unwrap().to_vec();
    // 按路径长度排序（通常用户源码路径短，生成的缓存路径长）或者按字母排序
    final_results.sort_by(|a, b| a.file.cmp(&b.file)); 

    println!("[Agent] ✅ Parallel search finished. Found {} matches.", final_results.len());
    
    Ok(final_results)
}

fn is_searchable_ext(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        match ext_str.as_str() {
            "java" | "xml" | "smali" | "c" | "cpp" | "h" | "kt" | "js" | "json" | "gradle" | "properties" | "txt" => true,
            _ => false,
        }
    } else {
        false
    }
}


// 🔥🔥🔥 核心：基于花括号计数的代码切片器 🔥🔥🔥
fn extract_method_body(file_path: &str, method_name: &str) -> Result<String, String> {
    let content = fs::read_to_string(file_path).map_err(|e| format!("Read error: {}", e))?;
    let lines: Vec<&str> = content.lines().collect();

    // 1. 构建宽松的正则来匹配方法签名
    // 匹配规则：空白 + (public/private/...) + 空白 + 返回值 + 空白 + 方法名 + 空白 + (
    // 这种正则能覆盖大多数 Java/Kotlin 定义
    let pattern = format!(r"(?i)\b{}\s*\(", regex::escape(method_name));
    let re = Regex::new(&pattern).map_err(|e| e.to_string())?;

    let mut start_line_idx = None;

    // 2. 找到方法定义的起始行
    for (i, line) in lines.iter().enumerate() {
        if re.is_match(line) {
            start_line_idx = Some(i);
            break;
        }
    }

    let start_idx = match start_line_idx {
        Some(idx) => idx,
        None => return Err(format!("Method '{}' not found in file", method_name)),
    };

    // 3. 开始花括号计数 (Brace Counting Algorithm)
    let mut brace_balance = 0;
    let mut found_start_brace = false;
    let mut extracted_lines = Vec::new();

    // 从签名行开始往下读
    for i in start_idx..lines.len() {
        let line = lines[i];
        extracted_lines.push(line);

        // 简单的字符遍历计数
        for char in line.chars() {
            match char {
                '{' => {
                    brace_balance += 1;
                    found_start_brace = true;
                }
                '}' => {
                    brace_balance -= 1;
                }
                _ => {}
            }
        }

        // 终止条件：已经找到了开始的 {，并且计数器回到了 0
        // 这意味着我们刚好闭合了该方法
        if found_start_brace && brace_balance == 0 {
            break;
        }
    }

    // 4. 返回结果
    Ok(extracted_lines.join("\n"))
}