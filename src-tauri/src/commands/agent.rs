use crate::commands::{self, frida};
use crate::models::FileNode;
use std::path::PathBuf;
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
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: Option<String>,
    pub apiKey: Option<String>,
    pub baseURL: Option<String>,
    pub model: Option<String>,
    pub temperature: Option<f64>,
    pub maxTokens: Option<i32>,
}

// ⚠️ 生产环境请改为云服务器 IP
const CLOUD_URL: &str = "http://127.0.0.1:3000"; 

static IS_CONNECTED: AtomicBool = AtomicBool::new(false);
static CURRENT_SESSION_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static CURRENT_PROJECT_ROOT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

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
    let plan_handle = app_handle.clone();       // 给任务计划更新使用
    let log_handle = app_handle.clone();        // 🔥 新增：给日志转发使用

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
        // 🔥 新增：监听云端日志并转发给前端 UI
        // ========================================================
        .on("log_message", move |payload: Payload, _| {
            let json_str = match payload {
                Payload::String(s) => s,
                Payload::Text(values) => {
                    if let Some(v) = values.first() { v.to_string() } else { return; }
                },
                Payload::Binary(_) => return,
            };
            
            // 解析日志并转发给前端
            if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
                // 日志格式: { source: "Cloud", msg: "...", type: "info" }
                let source = val.get("source").and_then(|v| v.as_str()).unwrap_or("Cloud");
                let msg = val.get("msg").and_then(|v| v.as_str()).unwrap_or("");
                let log_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("info");
                
                println!("[{}] {}", source, msg);
                
                // 🔥 转发给前端 - 使用 cloud-log 事件
                let _ = log_handle.emit("cloud-log", serde_json::json!({
                    "source": source,
                    "msg": msg,
                    "type": log_type
                }));
            }
        })
        // ========================================================
        .on("agent_command", move |payload: Payload, socket: RawClient| {
            let handle = cmd_handle.clone();
            let socket_clone = socket.clone();

            // println!("[Agent] 📦 Payload Received: {:?}", payload);

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
pub async fn send_chat_message(
    session_id: String, 
    message: String,
    model_config: Option<ModelConfig>
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({ 
        "sessionId": session_id, 
        "message": message,
        "modelConfig": model_config
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

// 🔥 新增：上传抓包数据
#[tauri::command]
pub async fn upload_traffic(
    session_id: String,
    traffic: Value
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({ 
        "sessionId": session_id, 
        "traffic": traffic
    });

    // 异步发送，不等待详细结果，只关心成功失败
    let _ = client.post(format!("{}/api/agent/traffic", CLOUD_URL))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok("Uploaded".to_string())
}

async fn dispatch_command(app: &AppHandle, action: &str, params: Value) -> Result<Value, String> {
    let project_root = CURRENT_PROJECT_ROOT.lock().unwrap().clone()
        .ok_or("No active project loaded. Please start a task first.")?;
    
    // 辅助函数：将相对路径转为绝对路径
    let resolve_path = |rel_path: &str| -> String {
        let p = std::path::Path::new(&project_root).join(rel_path);
        p.to_string_lossy().to_string()
    };
    match action {
        "GET_FILE_TREE" => {
            let raw_path = params["path"].as_str().ok_or("Missing path")?;
             let tree = generate_file_tree(raw_path)?;
             println!("[Agent] Tree generated. Root items: {}", tree.len());
             Ok(json!(tree))
        }
        "READ_FILE" => {
            let rel_path = params["path"].as_str().ok_or("Missing path")?;
            // ✅ 修正：拼接绝对路径
            let full_path = resolve_path(rel_path); 
            println!("[Agent] Reading file: {}", full_path);
            let content = fs::read_to_string(full_path).map_err(|e| e.to_string())?;
            Ok(json!(content))
        }
        // ✅ [新增] 获取文件大纲 (节省 Token)
        "GET_FILE_STRUCTURE" => {
            // 1. 从 params 获取相对路径 (这里是 &str，借用的)
            let rel_path = params["path"].as_str().ok_or("Missing path")?;
            
            // 2. 解析为绝对路径 (这里返回的是 String，拥有的！)
            let full_path = resolve_path(rel_path);
            
            println!("[Agent] 🦴 Generating outline for: {}", full_path);
            
            // 3. 【关键】将 full_path 的所有权转移给新变量 f_path
            // 这样 f_path 就是一个独立的 String，和 params 彻底脱钩
            let f_path = full_path;
            
            let outline = tokio::task::spawn_blocking(move || {
                // 4. 在闭包内部使用 f_path
                // move 关键字已经把 f_path 移进来了，它现在归这个线程所有
                generate_source_outline(&f_path)
            }).await.map_err(|e| e.to_string())??;
            
            Ok(json!(outline))
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
            let mode = params["mode"].as_str().map(|s| s.to_string());
            let session_id = CURRENT_SESSION_ID.lock().unwrap().clone();
            
            let result = commands::frida::run_frida_script(
                app.clone(), 
                device_id, 
                package.to_string(), 
                script.to_string(),
                mode,           // 🔥 spawn/attach 模式
                session_id,     // 🔥 用于日志同步
                None,           // 🔥 target_pid - 多进程注入时使用
                params["antiDetection"].as_bool() // 🔥 反检测模式
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
            let req_root = params["rootPath"].as_str().ok_or("Missing rootPath")?;
            let search_root = if req_root == "." {
                project_root.clone()
            } else {
                resolve_path(req_root)
            };
            let keyword = params["keyword"].as_str().ok_or("Missing keyword")?;
            let max_results = params["maxResults"].as_u64().unwrap_or(50) as usize;
            
            println!("[Agent] 🔍 Searching for '{}' in {}", keyword, search_root);
            
            // 🔥 核心修复：将繁重的搜索任务放入阻塞线程池
            // 这样主线程依然能响应心跳，不会导致 Timeout
            let root_path_owned = search_root;
            let keyword_owned = keyword.to_string();
            
            let results = tokio::task::spawn_blocking(move || {
                search_files(&root_path_owned, &keyword_owned, max_results)
            }).await
            .map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Search error: {}", e))?; // 处理 search_files 的 Result

            println!("[Agent] ✅ Found {} matches", results.len());
            Ok(json!(results))
        }
        // ✅ [新增] 按文件名查找 (相当于 find /dir -name "*keyword*")
        "FIND_FILES" => {
            let root_path = params["rootPath"].as_str().ok_or("Missing rootPath")?;
            let keyword = params["keyword"].as_str().ok_or("Missing keyword")?;
            
            println!("[Agent] 🔍 Finding files with name containing '{}'", keyword);
            
            let root_path_owned = root_path.to_string();
            let keyword_owned = keyword.to_string();

            let files = tokio::task::spawn_blocking(move || {
                let mut matches = Vec::new();
                for entry in WalkDir::new(&root_path_owned).into_iter().filter_map(|e| e.ok()) {
                    let file_name = entry.file_name().to_string_lossy();
                    // 忽略大小写匹配文件名
                    if file_name.to_lowercase().contains(&keyword_owned.to_lowercase()) {
                        let full_path = entry.path().to_string_lossy().replace("\\", "/");
                        matches.push(full_path);
                    }
                }
                matches
            }).await.map_err(|e| e.to_string())?;

            println!("[Agent] ✅ Found {} files", files.len());
            Ok(json!(files))
        },
        // ✅ [新增] 精准切片能力
        "GET_METHOD" => {
            let rel_path = params["path"].as_str().ok_or("Missing path")?;
            // 1. 获取绝对路径 (String)
            let full_path = resolve_path(rel_path); 
            // 2. 获取方法名 (借用的 &str)
            let method_name = params["method"].as_str().ok_or("Missing method")?;
            
            // 这里打印依然可以用 full_path，因为它还没有被 move
            println!("[Agent] ✂️ Slicing method '{}' from {}", method_name, full_path);
            
            // 3. 准备所有权数据 (Owned Data) 以便 Move 进线程
            // f_path 直接拿走 full_path 的所有权
            let f_path = full_path;
            // m_name 必须从引用转为拥有所有权的 String
            let m_name = method_name.to_string();
            
            let code_block = tokio::task::spawn_blocking(move || {
                // 🔥 关键修改：这里必须使用移进来后的新变量名 (f_path, m_name)
                // 绝对不能再用外面的 full_path 或 method_name
                extract_method_body(&f_path, &m_name)
            }).await.map_err(|e| e.to_string())??;
            
            Ok(json!(code_block))
        }
        // ✅ [新增] 列出 Native 导出函数
        "LIST_NATIVE_EXPORTS" => {
            let path = params["path"].as_str().ok_or("Missing path")?;
            println!("[Agent] 🧱 Analyzing Native Library: {}", path);

            let path_owned = path.to_string();
            let exports = tokio::task::spawn_blocking(move || {
                get_native_exports(&path_owned)
            }).await.map_err(|e| e.to_string())??;

            println!("[Agent] ✅ Found {} exported symbols", exports.len());
            Ok(json!(exports))
        },
        // ✅ [新增] 拉取脱壳文件
        "PULL_APP_DUMPS" => {
            let package = params["package"].as_str().ok_or("Missing package")?;
            let device_id = params["deviceId"].as_str().unwrap_or("").to_string();
            
            println!("[Agent] 📥 Pulling dumps for package: {}", package);
            
            // 确保 device_id 存在，如果为空则尝试获取第一个连接的设备
            let target_device = if device_id.is_empty() {
                // 这里简化处理，如果为空则报错，因为 Agent 应该知道 deviceId
                return Err("Missing deviceId".to_string());
            } else {
                device_id
            };

            let result = commands::apk::pull_and_organize_dex(target_device, package.to_string())
                .await.map_err(|e| e.to_string())?;
                
            Ok(json!({ "path": result, "message": "Dump files pulled successfully" }))
        },
        // ✅ [新增] JADX 反编译
        "JADX_DECOMPILE" => {
            let path = params["path"].as_str().ok_or("Missing path")?;
            let output_dir = params["outputDir"].as_str().map(|s| s.to_string());
            
            println!("[Agent] 🔧 JADX Decompile Request: {}", path);
            
            let result = commands::apk::jadx_decompile(app.clone(), path.to_string(), output_dir)
                .await.map_err(|e| e.to_string())?;
            
            Ok(json!({ "outputDir": result, "message": "Decompilation successful" }))
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

#[tauri::command]
pub async fn notify_cloud_job_start(
    session_id: String, 
    file_path: String, 
    instruction: String,
    model_config: Option<ModelConfig>,
    manifest: Option<String>,
    file_tree: Option<Vec<FileNode>>,
    network_captures: Option<Vec<serde_json::Value>>,
    frida_mode: Option<String>,
    use_stealth_mode: Option<bool> // 🔥 新增：隐身模式
) -> Result<String, String> {
    println!("[Agent] 🚀 Notifying Cloud. Instruction: {}", instruction);

    let package_name = manifest.as_ref()
        .and_then(|xml| {
            let re = Regex::new(r#"package=["']([^"']+)["']"#).ok()?;
            re.captures(xml).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        })
        .unwrap_or_else(|| "unknown.package".to_string());

    {
        let mut root = CURRENT_PROJECT_ROOT.lock().unwrap();
        *root = Some(file_path.clone());
        println!("[Agent] 📂 Project Root set to: {}", file_path);
    }

    // 2. 🔥 核心修改：拍平文件树
    let flat_file_list: Vec<String> = if let Some(nodes) = file_tree {
        let list = flatten_file_tree(&nodes);
        println!("[Agent] 🌲 Flattened file tree: {} files -> {} paths", nodes.len(), list.len());
        list
    } else {
        Vec::new()
    };

    let root_prefix = file_path.clone(); // file_path 是解包后的根目录

    let refined_list: Vec<String> = flat_file_list.into_iter().map(|path| {
        // 移除根路径前缀，并将反斜杠转为斜杠 (AI 更喜欢 Unix 风格)
        path.replace(&root_prefix, "")
            .replace("\\", "/")
            .trim_start_matches('/')
            .to_string()
    }).collect();
    
    let client = reqwest::Client::new();
    let body = serde_json::json!({ 
        "sessionId": session_id, 
        "filePath": file_path,
        "instruction": instruction,
        "modelConfig": model_config,
        "projectInfo": {
            "packageName": package_name,
            "manifestXml": manifest.unwrap_or_default(),
            "fileTree": refined_list
        },
        "networkCaptures": network_captures.unwrap_or_default(),
        "fridaMode": frida_mode.unwrap_or_else(|| "spawn".to_string()),
        "useStealthMode": use_stealth_mode.unwrap_or(false) // 🔥 新增：隐身模式
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

            // 基础过滤：隐藏文件
            if name.starts_with(".") { continue; }

            // 🔥 [新增] 智能过滤：跳过垃圾目录
            if is_ignored_entry(&name, &path) {
                // println!("Skipping ignored path: {:?}", path); // 调试时可开启
                continue;
            }

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

            // 优化：如果是空目录（被过滤完了），就不添加了
            if is_dir {
                if let Some(children) = &node.children {
                    if children.is_empty() {
                        continue;
                    }
                }
            }

            nodes.push(node);
        }
    }
    // 排序
    nodes.sort_by(|a, b| {
        if a.is_leaf == b.is_leaf { a.title.cmp(&b.title) } else { a.is_leaf.cmp(&b.is_leaf) }
    });
    nodes
}

fn is_ignored_entry(name: &str, path: &Path) -> bool {
    // 1. 忽略常见的非代码资源目录
    let ignore_dirs = [
        "res", "assets", "resources", "build", "dist", "release", "debug", 
        "kotlin", "kotlinx", "javax", "org", "net", "io" // 视情况过滤顶级包名
    ];
    if ignore_dirs.contains(&name) {
        return true;
    }

    // 2. 忽略常见的第三方 SDK 包名 (路径匹配)
    // 转换路径为字符串，注意 Windows 的反斜杠问题
    let path_str = path.to_string_lossy().replace("\\", "/");
    
    // 常见的垃圾代码路径特征
    let junk_patterns = [
        // === Android & Google 系统级 ===
        "/androidx/",
        "/android/support/",
        "/android/arch/",
        "/com/google/",          // Google GMS, Firebase, Gson, Guava
        "/com/android/",
        
        // === 语言与核心库 ===
        "/kotlin/",              // Kotlin 标准库
        "/kotlinx/",             // Kotlin 协程等
        "/org/jetbrains/",       // JetBrains 内部库
        "/org/intellij/",
        "/org/apache/",          // Apache Commons (IO, Http, etc.)
        "/io/reactivex/",        // RxJava
        "/javax/",               // Java 标准扩展
        "/org/json/",            // 标准 JSON 库

        // === 常见网络与工具库 ===
        "/okhttp3/",             // OkHttp
        "/okio/",                // Okio
        "/retrofit2/",           // Retrofit
        "/com/squareup/",        // Square (OkHttp, Retrofit, LeakCanary, Picasso)
        "/com/bumptech/",        // Glide 图片加载
        "/com/fasterxml/",       // Jackson JSON
        "/com/gson/",            // Gson (有时会有变体)
        "/org/jsoup/",           // Jsoup HTML 解析
        "/com/airbnb/",          // Lottie 动画
        "/dagger/",              // Dagger 依赖注入
        "/org/greenrobot/",      // EventBus, GreenDao

        // === 国内大厂与常见 SDK (重点) ===
        "/com/alibaba/",         // 阿里系 (支付宝, ARouter, FastJson)
        "/com/alipay/",          // 支付宝 SDK
        "/com/taobao/",          // 淘宝 SDK
        "/com/tencent/",         // 腾讯系 (微信, Bugly, X5内核, Taker)
        "/com/mm/",              // 微信相关
        "/com/baidu/",           // 百度 (地图, 定位, 统计)
        "/com/amap/",            // 高德地图
        "/com/autonavi/",        // 高德导航
        "/com/sina/",            // 新浪微博 SDK
        "/com/meizu/",           // 魅族 Push
        "/com/xiaomi/",          // 小米 Push
        "/com/huawei/",          // 华为 HMS/Push
        "/com/vivo/",            // Vivo Push
        "/com/oppo/",            // Oppo Push
        "/com/heytap/",          // ColorOS (Oppo) Push
        "/com/umeng/",           // 友盟统计 (非常常见)
        "/com/igexin/",          // 个推 Push
        "/cn/jpush/",            // 极光推送
        "/cn/jiguang/",          // 极光核心
        "/com/bytedance/",       // 字节跳动 (穿山甲广告, TikTok SDK)
        "/com/ss/android/",      // 字节跳动 (今日头条 SDK)
        "/com/unionpay/",        // 银联支付
        "/com/jd/",              // 京东 SDK
        "/com/kuaishou/",        // 快手 SDK

        // === 跨平台框架 ===
        "/com/facebook/",        // Facebook (React Native, Fresco, Soloader)
        "/io/flutter/",          // Flutter 引擎
        "/com/unity3d/",         // Unity 引擎
        "/org/cocos2dx/",        // Cocos 引擎
        
        // === 生成文件与资源 ===
        "/R.java",               // 资源索引 (垃圾中的战斗机)
        "/R$.java",              // R 的内部类
        "/BuildConfig.java",     // 编译配置
        "/Manifest.java",        // 有时会生成的 Manifest 索引
        "/DebugMetadata.java",   // 调试元数据
    ];

    for pattern in junk_patterns.iter() {
        if path_str.contains(pattern) {
            return true;
        }
    }

    false
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
    if file_path.ends_with(".smali") {
        return extract_smali_method(&content, method_name);
    }
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

// 新增 Smali 提取逻辑
fn extract_smali_method(content: &str, method_name: &str) -> Result<String, String> {
    let mut in_method = false;
    let mut extracted_lines = Vec::new();
    
    // 简单的 Smali 匹配： .method ... methodName(
    let start_pattern = format!(" {}(", method_name); 

    for line in content.lines() {
        if line.contains(".method") && line.contains(&start_pattern) {
            in_method = true;
        }

        if in_method {
            extracted_lines.push(line);
            if line.trim().starts_with(".end method") {
                break;
            }
        }
    }

    if extracted_lines.is_empty() {
        return Err(format!("Smali method '{}' not found", method_name));
    }

    Ok(extracted_lines.join("\n"))
}

// 🔥🔥🔥 核心：解析 ELF (.so) 导出表 🔥🔥🔥
fn get_native_exports(file_path: &str) -> Result<Vec<String>, String> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    let buffer = fs::read(path).map_err(|e| format!("Read error: {}", e))?;

    // 解析 ELF
    match Elf::parse(&buffer) {
        Ok(binary) => {
            let mut exports = Vec::new();

            // 遍历动态符号表 (dynsyms)
            for sym in binary.dynsyms.iter() {
                // st_value > 0 通常意味着它是定义的函数/变量，而不是引用的外部符号
                // st_info 包含了类型信息，我们主要关注函数 (STT_FUNC) 和 GNU_IFUNC
                // 但为了通用性，只要是有名字且有地址的导出符号，我们都列出来
                if sym.st_value == 0 || sym.st_shndx == 0 { continue; }

                if let Some(name) = binary.dynstrtab.get_at(sym.st_name) {
                    // 过滤掉一些系统符号，只保留看起来像业务逻辑的
                    if !name.is_empty() && !name.starts_with("_") {
                        exports.push(name.to_string());
                    }
                    // 特别保留 JNI 函数 (Java_...)
                    else if name.starts_with("Java_") {
                        exports.push(name.to_string());
                    }
                }
            }

            // 排序，方便查看
            exports.sort();
            Ok(exports)
        },
        Err(e) => Err(format!("Failed to parse ELF: {}", e))
    }
}


fn flatten_file_tree(nodes: &[FileNode]) -> Vec<String> {
    let mut paths = Vec::new();
    
    for node in nodes {
        if node.is_leaf {
            // 这里直接使用 node.key (通常是完整路径)
            // 💡 进阶优化：如果 key 是绝对路径，建议在这里转成相对路径 (相对于项目根目录)
            // 比如: "C:\\Users\\...\\src\\main.java" -> "src/main.java"
            // 但为了保险起见，先传完整路径，云端也能处理
            paths.push(node.key.clone());
        }
        
        if let Some(children) = &node.children {
            let child_paths = flatten_file_tree(children);
            paths.extend(child_paths);
        }
    }
    
    paths
}

// 🔥🔥🔥 核心：代码大纲生成器 (Outline Generator) 🔥🔥🔥
// 改进版：支持“透视”模式，保留方法体内的字符串和敏感 API 调用
fn generate_source_outline(file_path: &str) -> Result<String, String> {
    let content = fs::read_to_string(file_path).map_err(|e| format!("Read error: {}", e))?;
    let mut outline_lines = Vec::new();
    let mut brace_level = 0;
    
    // 敏感关键词列表 (即使在方法体内，遇到这些词也要保留)
    let sensitive_keywords = [
        "\"", "'", // 字符串常量
        "SecretKey", "Cipher", "MessageDigest", "Mac", "Signature", // 加密相关
        "Http", "Retrofit", "OkHttp", "Socket", // 网络
        "loadLibrary", "native", // JNI
        "SharedPreferences", "SQLite", // 存储
        "Log.", "System.out", // 日志
        "Base64", "MD5", "SHA", "AES", "DES", "RSA" // 常见算法字符串
    ];

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let open_count = line.chars().filter(|c| *c == '{').count();
        let close_count = line.chars().filter(|c| *c == '}').count();
        
        // 判定规则 1: 结构行 (类定义、方法签名、闭合括号)
        let is_structure = brace_level <= 1 || (brace_level == 2 && close_count > 0);
        
        // 判定规则 2: 特征行 (包含敏感信息)
        // 只有当这一行看起来像代码 (不是纯注释) 时才检查
        let is_feature = !trimmed.starts_with("//") && sensitive_keywords.iter().any(|&kw| line.contains(kw));

        if is_structure || is_feature {
            // 如果是结构行，且后面紧跟了内容，我们手动截断视觉效果
            if is_structure && open_count > 0 && brace_level >= 1 && !is_feature {
                 outline_lines.push(line.to_string());
                 // 只有当没有被认定为 feature 时，才加 ... 提示
                 // 如果这一行本身就是 feature (比如定义时就有字符串)，则不需要 ...
                 if brace_level >= 1 {
                     let indent = &line[0..line.len() - line.trim_start().len()];
                     outline_lines.push(format!("{}    // ...", indent)); 
                 }
            } else {
                outline_lines.push(line.to_string());
            }
        }

        // 更新层级
        brace_level = brace_level + open_count;
        if brace_level >= close_count {
            brace_level -= close_count;
        } else {
            brace_level = 0; 
        }
    }

    Ok(outline_lines.join("\n"))
}