use tauri::command;
use serde_json::json;
use regex::Regex;
use std::time::Duration;
use tokio::time::sleep;

use crate::models::AiRequest;

// 这里建议把 Key 放在环境变量或者编译时常量，不要硬编码
const GEMINI_API_KEY: &str = "AIzaSyBetYOlS_KNJV-TH4YoQLdbtzlIR8S8q54"; 
const MODEL_NAME: &str = "gemini-2.5-flash"; // Flash 速度快，适合补环境

// 带有 429 重试机制的调用函数
async fn call_gemini_with_retry(payload: serde_json::Value) -> Result<String, String> {
    let client = reqwest::Client::new();
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        MODEL_NAME, GEMINI_API_KEY
    );

    let mut retries = 3; // 最大重试 3 次
    let mut wait_time = 2; // 初始等待 2 秒

    while retries > 0 {
        let res = client.post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("网络请求失败: {}", e))?;

        if res.status().is_success() {
            let body: serde_json::Value = res.json().await.map_err(|e| format!("解析失败: {}", e))?;
            let content = body["candidates"][0]["content"]["parts"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string();
            // 清理 markdown
            return Ok(content.replace("```java", "").replace("```", "").trim().to_string());
        } else if res.status().as_u16() == 429 {
            // 🔥 触发限流，进行退避等待
            println!("Gemini 限流 (429)，等待 {} 秒后重试...", wait_time);
            sleep(Duration::from_secs(wait_time)).await;
            retries -= 1;
            wait_time *= 2; // 指数退避: 2s -> 4s -> 8s
        } else {
            return Err(format!("API 错误: Status {}", res.status()));
        }
    }

    Err("API 请求频繁 (429)，重试多次失败，请稍后再试。".to_string())
}

// 智能代码替换算法 (简易 AST)
// 作用：找到旧的方法并替换，或者追加到末尾
fn smart_inject_code(original_code: &str, new_method_code: &str) -> String {
    // 1. 从新代码中提取方法名 (例如 callStaticObjectMethodV)
    // 这是一个简化的正则，匹配 public DvmObject name(...)
    let re_name = Regex::new(r"public\s+\w+(?:<\?>)?\s+(\w+)\s*\(").unwrap();
    
    let method_name = if let Some(caps) = re_name.captures(new_method_code) {
        caps.get(1).unwrap().as_str()
    } else {
        // 如果提取不到方法名，直接追加到末尾（保底策略）
        return insert_before_last_brace(original_code, new_method_code);
    };

    println!("AI 生成了方法: {}", method_name);

    // 2. 在源代码中查找这个方法是否存在
    // 我们构建一个正则来寻找方法的头部
    let pattern = format!(r"public\s+.*\s+{}\s*\(", method_name);
    let re_find = Regex::new(&pattern).unwrap();

    if let Some(mat) = re_find.find(original_code) {
        // === 分支 A: 方法已存在，执行替换 ===
        println!("检测到方法 {} 已存在，执行智能替换...", method_name);
        
        let start_index = mat.start();
        // 开始花括号计数算法，找到该方法的结束位置
        let chars: Vec<char> = original_code.chars().collect();
        let mut brace_count = 0;
        let mut found_start_brace = false;
        let mut end_index = 0;

        for i in start_index..chars.len() {
            if chars[i] == '{' {
                brace_count += 1;
                found_start_brace = true;
            } else if chars[i] == '}' {
                brace_count -= 1;
            }

            if found_start_brace && brace_count == 0 {
                end_index = i + 1; // 找到了方法的闭合括号
                break;
            }
        }

        if end_index > start_index {
            // 拼接：[头部] + [新方法] + [尾部]
            let mut new_full_code = String::new();
            new_full_code.push_str(&original_code[..start_index]);
            new_full_code.push_str("\n    // [AI Updated] Method replaced automatically\n    ");
            new_full_code.push_str(new_method_code);
            new_full_code.push_str(&original_code[end_index..]);
            return new_full_code;
        }
    }

    // === 分支 B: 方法不存在，追加到类末尾 ===
    println!("方法 {} 不存在，追加到末尾...", method_name);
    insert_before_last_brace(original_code, new_method_code)
}

fn insert_before_last_brace(code: &str, snippet: &str) -> String {
    let trimmed = code.trim_end();
    if let Some(idx) = trimmed.rfind('}') {
    let mut s = String::from(&trimmed[..idx]);
    s.push_str("\n\n    // [AI Auto-Generated]\n    ");
    s.push_str(snippet);
    s.push_str("\n");
    s.push_str(&trimmed[idx..]);
    return s;
}
    // 极其罕见的情况：找不到类的结尾，直接追加
    format!("{}\n{}", code, snippet)
}

// 供前端调用的主接口
#[command]
pub async fn call_gemini_service(request: AiRequest) -> Result<String, String> {
    // 1. 构建 Prompt
    let system_instruction = "Role: Unidbg JNI Expert. \
    Task: You are essentially a code patcher. \
    Input: Current Java Code + Error Log. \
    Output: Return the **COMPLETE JAVA METHOD** that fixes the error. \
    IMPORTANT Strategy: \
    1. Check if the relevant JNI method (e.g., callStaticObjectMethodV) ALREADY EXISTS in the Input Code. \
    2. If it EXISTS: You must return the **WHOLE** method, keeping the existing logic (switch/if cases) and ADDING the new case for the error. \
    3. If it DOES NOT EXIST: Return the new method definition. \
    4. Do not return the class wrapper, only the method.";

    let user_prompt = format!(
        "Code Context:\n```java\n{}\n```\n\nError Log:\n{}\n\nPlease generate the fixed method.",
        // 修改点 1: 使用 as_deref() 来借用，而不是拿走所有权
        request.context_code.as_deref().unwrap_or_default(),
        // 修改点 2: error_log 同理（虽然下面没用到，但为了避免所有权问题建议统一写法）
        request.error_log.as_deref().unwrap_or_default()
    );

    let payload = json!({
        "system_instruction": { "parts": [{ "text": system_instruction }] },
        "contents": [{ "parts": [{ "text": user_prompt }] }],
        "generationConfig": { "temperature": 0.1 }
    });

    // 2. 调用 AI (含重试)
    let new_method_code = call_gemini_with_retry(payload).await?;

    // 3. 智能合并代码 (在后端完成合并，前端直接拿结果)
    // 如果 request 里包含了 code，我们就帮忙合并；否则只返回片段
    if let Some(ctx_code) = request.context_code {
        let final_code = smart_inject_code(&ctx_code, &new_method_code);
        Ok(final_code)
    } else {
        Ok(new_method_code)
    }
}