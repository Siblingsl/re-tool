use crate::utils::cmd_exec;
use crate::models::FileItem;
use std::fs;

// 获取文件列表命令
#[tauri::command]
pub async fn get_file_list(device_id: String, path: String) -> Result<Vec<FileItem>, String> {
    // 优先尝试使用 Root 权限读取，因为 /data/data 需要 Root
    // 命令：adb shell "su -c 'ls -l <path>'"
    // 如果失败（比如没Root），回退到普通 ls -l
    
    let cmd = format!("su -c 'ls -l \"{}\"'", path); // 尝试 Root
    let mut output = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;

    if output.contains("denied") || output.contains("not found") {
        // 回退到普通权限 (适合 /sdcard)
        output = cmd_exec("adb", &["-s", &device_id, "shell", "ls", "-l", &path])?;
    }

    let mut files = Vec::new();

    // 解析 ls -l 输出
    // 典型格式: drwxrwx--x 2 root root 4096 2023-01-01 12:00 foldername
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("total") { continue; }

        // 简单的空格分割解析
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; } // 格式不对跳过

        let permissions = parts[0];
        let is_dir = permissions.starts_with('d');
        
        // 处理文件名包含空格的情况：取第8个字段之后的所有内容
        // ls -l date format varies (some have time, some year). 
        // 这是一个简化的解析器，适配大多数 Android ls
        let name_start_index = if parts.len() > 7 { 7 } else { parts.len() - 1 };
        // 有些系统 ls -l 只有日期没有时间，这里做一个容错
        let name = parts[name_start_index..].join(" ");
        
        // 过滤掉 . 和 ..
        if name == "." || name == ".." { continue; }

        let size = if is_dir { "".to_string() } else { parts[4].to_string() }; // 第5列通常是大小
        let date = format!("{} {}", parts[5], parts[6]); // 日期时间

        files.push(FileItem {
            name,
            is_dir,
            size,
            permissions: permissions.to_string(),
            date,
        });
    }

    // 排序：文件夹在前
    files.sort_by(|a, b| {
        if a.is_dir == b.is_dir {
            a.name.cmp(&b.name)
        } else {
            b.is_dir.cmp(&a.is_dir)
        }
    });

    Ok(files)
}

// 读取文件内容 (支持 Root)
#[tauri::command]
pub async fn read_file_content(device_id: String, path: String) -> Result<String, String> {
    // 尝试用 cat 命令读取
    // 如果文件是二进制或者太大，这里可能需要做限制，但作为 MVP 先读文本
    let cmd = format!("su -c 'cat \"{}\"'", path);
    let mut output = cmd_exec("adb", &["-s", &device_id, "shell", &cmd])?;

    // 如果 su 失败，尝试普通 cat
    if output.contains("denied") || output.contains("not found") {
        output = cmd_exec("adb", &["-s", &device_id, "shell", "cat", &path])?;
    }

    // 简单的错误检查
    if output.contains("No such file") || output.contains("Is a directory") {
        return Err(format!("无法读取文件: {}", output));
    }

    // 限制返回大小，防止前端卡死 (比如最大 1MB)
    if output.len() > 1024 * 1024 {
        return Err("文件太大，请下载到电脑查看".to_string());
    }

    Ok(output)
}

// 保存文件内容 (修改文件)
// 逻辑：写入本地临时文件 -> adb push 到手机临时目录 -> su mv 到目标目录 (为了绕过权限问题)
#[tauri::command]
pub async fn save_file_content(device_id: String, path: String, content: String) -> Result<String, String> {
    let temp_dir = std::env::temp_dir();
    // 生成随机文件名避免冲突
    let temp_name = format!("adb_edit_{}.tmp", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
    let local_temp_path = temp_dir.join(&temp_name);
    
    // 1. 写入本地临时文件
    fs::write(&local_temp_path, content).map_err(|e| format!("本地写入失败: {}", e))?;
    
    let local_path_str = local_temp_path.to_string_lossy().to_string();
    let remote_temp = format!("/data/local/tmp/{}", temp_name);

    // 2. 推送到手机临时目录
    let push_res = cmd_exec("adb", &["-s", &device_id, "push", &local_path_str, &remote_temp])?;
    if push_res.to_lowercase().contains("error") {
         return Err(format!("Push 失败: {}", push_res));
    }

    // 3. 使用 Root 权限移动到目标位置 (覆盖原文件)
    let mv_res = cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mv '{}' '{}'", remote_temp, path)])?;
    
    // 清理本地临时文件
    let _ = fs::remove_file(local_temp_path);

    if mv_res.trim().is_empty() {
        Ok("保存成功".to_string())
    } else {
        // mv 命令通常没有输出，如果有输出可能是报错
        Ok(format!("保存可能成功 (Log: {})", mv_res))
    }
}

// 删除文件/文件夹
#[tauri::command]
pub async fn delete_file(device_id: String, path: String) -> Result<String, String> {
    // rm -rf <path>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("rm -rf '{}'", path)])?;
    Ok("删除成功".to_string())
}

// 新建文件夹
#[tauri::command]
pub async fn create_dir(device_id: String, path: String) -> Result<String, String> {
    // mkdir -p <path>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mkdir -p '{}'", path)])?;
    Ok("创建成功".to_string())
}

// 重命名
#[tauri::command]
pub async fn rename_file(device_id: String, old_path: String, new_path: String) -> Result<String, String> {
    // mv <old> <new>
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("mv '{}' '{}'", old_path, new_path)])?;
    Ok("重命名成功".to_string())
}