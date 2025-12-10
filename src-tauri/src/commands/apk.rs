use std::path::Path;
use std::fs::{self, File};
use std::io::BufReader;
use zip::ZipArchive;
use directories::UserDirs;
use walkdir::WalkDir;
use rayon::prelude::*;
use crate::models::{FileNode, SearchResult, SoFile};
use crate::utils::{cmd_exec, get_packer_name, is_text_file, create_command};

// 递归扫描目录 
fn read_dir_recursive(path: &Path) -> Vec<FileNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // 正确判断目录
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let is_dir = file_type.is_dir();

            // 过滤隐藏文件与无用目录
            if name.starts_with(".") || name == "build" || name == "dist" {
                continue;
            }

            let node = FileNode {
                title: name.clone(),
                key: path.to_string_lossy().to_string(),

                is_leaf: !is_dir,
                children: if is_dir { Some(read_dir_recursive(&path)) } else { None },
            };

            nodes.push(node);
        }
    }

    // 文件夹排在前
    nodes.sort_by(|a, b| {
        if a.is_leaf == b.is_leaf {
            a.title.cmp(&b.title)
        } else {
            a.is_leaf.cmp(&b.is_leaf)
        }
    });

    nodes
}

// 解包 APK
#[tauri::command]
pub async fn apk_decode(apk_path: String) -> Result<String, String> {
    // 输出目录: D:\Downloads\app.apk -> D:\Downloads\app_src
    let output_dir = format!("{}_src", apk_path.trim_end_matches(".apk"));
    
    // 先清理旧目录
    let _ = fs::remove_dir_all(&output_dir);

    // 执行: apktool d -f <apk> -o <out>
    let output = create_command("apktool")
        .args(&["d", "-f", &apk_path, "-o", &output_dir])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(output_dir)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// 扫描解包后的目录 (生成树)
#[tauri::command]
pub async fn scan_local_dir(path: String) -> Result<Vec<FileNode>, String> {
    let root = Path::new(&path);
    if !root.exists() {
        return Err("目录不存在".to_string());
    }
    Ok(read_dir_recursive(root))
}

// 读取本地文件内容
#[tauri::command]
pub async fn read_local_file(path: String) -> Result<String, String> {
    // 尝试读取文件为字符串
    // 注意：如果文件不是 UTF-8 编码（比如图片或二进制），这里会报错
    fs::read_to_string(&path).map_err(|e| format!("读取失败: {}", e))
}

// 保存本地文件内容
#[tauri::command]
pub async fn save_local_file(path: String, content: String) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn apk_build_sign_install(project_dir: String, device_id: String) -> Result<String, String> {
    // 1. 回编译 (Build)
    let _dist_apk = format!("{}/dist/signed.apk", project_dir);
    let unsigned_apk = format!("{}_unsigned.apk", project_dir);
    
    let build_res = create_command("apktool")
        .args(&["b", &project_dir, "-o", &unsigned_apk])
        .output()
        .map_err(|e| format!("调用 apktool 失败: {}", e))?;

    if !build_res.status.success() {
        return Err(format!("回编译失败: {}", String::from_utf8_lossy(&build_res.stderr)));
    }

    // 2. 签名 (Sign)
    // 因为运行目录可能是项目根目录，也可能是 src-tauri 目录，我们挨个试
    let possible_paths = vec![
        "resources/uber-apk-signer.jar",           // 情况A: CWD 是 src-tauri
        "src-tauri/resources/uber-apk-signer.jar", // 情况B: CWD 是项目根目录
        "../resources/uber-apk-signer.jar",        // 情况C: 备用
    ];

    let mut signer_jar = "";
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            signer_jar = path;
            println!("✅ 找到签名工具: {}", path);
            break;
        }
    }

    if signer_jar.is_empty() {
        // 如果都没找到，打印详细调试信息
        let cwd = std::env::current_dir().unwrap_or_default();
        println!("❌ 错误: 找不到 uber-apk-signer.jar！");
        println!("当前工作目录: {:?}", cwd);
        println!("请确保文件存在于 src-tauri/resources/ 下");
        // 强行指定一个默认值，虽然大概率会失败
        signer_jar = "resources/uber-apk-signer.jar";
    }
    
    let sign_res = create_command("java")
        .args(&["-jar", signer_jar, "-a", &unsigned_apk, "--allowResign"])
        .output();
        
    let target_apk = if let Ok(res) = sign_res {
        if res.status.success() {
            // uber-apk-signer 默认生成 xxx-aligned-debugSigned.apk
            format!("{}_unsigned-aligned-debugSigned.apk", project_dir)
        } else {
            println!("签名警告: {}", String::from_utf8_lossy(&res.stderr));
            unsigned_apk // 签名失败回退到未签名
        }
    } else {
        unsigned_apk
    };

    // 3. 安装 (Install)
    // 使用 -r -t 强制安装测试包
    let install_res = cmd_exec("adb", &["-s", &device_id, "install", "-r", "-t", &target_apk])?;
    
    if install_res.contains("Success") {
        Ok("编译、签名并安装成功！".to_string())
    } else {
        Err(format!("安装失败: {}", install_res))
    }
}

// 使用 JADX 反编译为 Java 源码
#[tauri::command]
pub async fn jadx_decompile(apk_path: String) -> Result<String, String> {
    // 输出目录: D:\Downloads\app.apk -> D:\Downloads\app_jadx_src
    let output_dir = format!("{}_jadx_src", apk_path.trim_end_matches(".apk"));
    
    // 先清理旧目录
    let _ = fs::remove_dir_all(&output_dir);

    // 命令: jadx -d <out> <apk>
    // 注意：Windows 下可能需要 cmd /C jadx ...
    let output = create_command("jadx")
        .args(&["-d", &output_dir, &apk_path])
        .output()
        .map_err(|e| format!("调用 jadx 失败: {}", e))?;

    if output.status.success() {
        // JADX 的源码通常在 output_dir/sources 目录下
        // 我们直接返回根目录，让前端自己点进去
        Ok(output_dir)
    } else {
        // JADX 有时候会有很多 warning 输出在 stderr，但不代表失败
        // 只要目录存在就算成功
        if std::path::Path::new(&output_dir).exists() {
            Ok(output_dir)
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}

// 项目全局搜索命令
#[tauri::command]
pub async fn search_project(project_dir: String, query: String) -> Result<Vec<SearchResult>, String> {
    let query = query.to_lowercase();
    
    // 1. 收集所有文件路径 (快速遍历)
    let entries: Vec<_> = WalkDir::new(&project_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // 2. 并行搜索 (利用所有 CPU 核心)
    // 使用 par_iter() 替代 iter()
    let results: Vec<SearchResult> = entries.par_iter()
        .flat_map(|entry| {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();
            let mut local_results = Vec::new();

            // A. 搜文件名
            if let Some(fname) = path.file_name() {
                if fname.to_string_lossy().to_lowercase().contains(&query) {
                     local_results.push(SearchResult {
                        file_path: path_str.clone(),
                        line_num: 0,
                        content: fname.to_string_lossy().to_string(),
                        match_type: "file".to_string(),
                    });
                }
            }

            // B. 搜内容 (只搜文本文件)
            if is_text_file(&path_str) {
                // 读取文件内容 (忽略读取错误)
                if let Ok(content) = std::fs::read_to_string(path) {
                    for (i, line) in content.lines().enumerate() {
                        if line.to_lowercase().contains(&query) {
                            local_results.push(SearchResult {
                                file_path: path_str.clone(),
                                line_num: i + 1,
                                content: line.trim().to_string(),
                                match_type: "code".to_string(),
                            });
                            // 单个文件限制匹配数，防止大文件刷屏
                            if local_results.len() > 20 { break; } 
                        }
                    }
                }
            }
            local_results
        })
        .collect();

    // 截取前 500 条，防止前端渲染卡顿
    let final_results = results.into_iter().take(500).collect();
    Ok(final_results)
}

// 查壳
#[tauri::command]
pub async fn detect_packer(apk_path: String) -> Result<String, String> {
    let file = File::open(&apk_path).map_err(|e| format!("无法打开文件: {}", e))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).map_err(|e| format!("APK 解析失败: {}", e))?;

    let mut detected = Vec::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        let name = file.name();
        if let Some(packer) = get_packer_name(name) {
            if !detected.contains(&packer.to_string()) {
                detected.push(packer.to_string());
            }
        }
    }

    if detected.is_empty() {
        Ok("未发现常见加固特征 (可能是原包或未知壳)".to_string())
    } else {
        Ok(detected.join(", "))
    }
}

// 拉取并整理 Dex 文件
#[tauri::command]
pub async fn pull_and_organize_dex(device_id: String, pkg: String) -> Result<String, String> {
    // 1. 定义手机端 Dump 目录
    let remote_dump_dir = format!("/data/data/{}/files/dump_dex", pkg);
    
    // 2. 定义电脑端保存目录 (Downloads/Dump_PkgName_Time)
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let local_folder_name = format!("{}_dump_{}", pkg, timestamp);
    let local_save_path = download_dir.join(&local_folder_name);
    
    // 创建本地目录
    fs::create_dir_all(&local_save_path).map_err(|e| e.to_string())?;
    let local_save_str = local_save_path.to_string_lossy().to_string();

    // 3. 执行 adb pull
    // 注意：因为 /data/data 需要 root 权限，普通 pull 可能失败。
    // 建议先用 su 把文件复制到 /data/local/tmp/ 再 pull，或者直接 su -c tar
    
    // 方案：先 cp 到 tmp (确保有读写权限)
    let remote_tmp = format!("/data/local/tmp/{}_dump", pkg);
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("rm -rf {}; cp -r {} {}", remote_tmp, remote_dump_dir, remote_tmp)])?;
    cmd_exec("adb", &["-s", &device_id, "shell", "su", "-c", &format!("chmod -R 777 {}", remote_tmp)])?;
    
    let pull_res = cmd_exec("adb", &["-s", &device_id, "pull", &remote_tmp, &local_save_str])?;
    
    // 清理手机临时文件
    cmd_exec("adb", &["-s", &device_id, "shell", "rm -rf", &remote_tmp])?;

    // 4. 整理文件名 (把莫名其妙的名字改成 classes.dex, classes2.dex)
    // 遍历下载下来的文件夹
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

    if pull_res.contains("pulled") {
        Ok(local_save_str)
    } else {
        Err(format!("拉取失败 (请确认应用是否运行且脱壳脚本已执行): {}", pull_res))
    }
}


// 1. 获取 APK 路径 (辅助函数，也可单独调用)
#[tauri::command]
pub async fn get_apk_path(device_id: String, pkg: String) -> Result<String, String> {
    let output = cmd_exec("adb", &["-s", &device_id, "shell", "pm", "path", &pkg])?;
    // 输出示例: package:/data/app/~~xxx/com.example/base.apk
    // 可能有多行 (split apk)，我们取 base.apk
    
    for line in output.lines() {
        if let Some(path) = line.trim().strip_prefix("package:") {
            if path.ends_with("base.apk") || !output.contains("base.apk") {
                return Ok(path.to_string());
            }
        }
    }
    Err("未找到 APK 路径".to_string())
}

// 2. 列出 APK 内部的 SO 文件 (核心功能)
#[tauri::command]
pub async fn lists_so_files(device_id: String, apk_path: String) -> Result<Vec<SoFile>, String> {
    println!(">>> 正在通过 Pull 方式获取 SO 列表，源路径: {}", apk_path);

    // 1. 获取安全的临时路径 (改用 Downloads 目录，避开 Temp 权限坑)
    let user_dirs = UserDirs::new().ok_or("无法获取用户目录")?;
    let download_dir = user_dirs.download_dir().ok_or("无法获取下载目录")?;
    
    // 生成一个带时间戳的文件名，防止冲突
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let temp_filename = format!("temp_scan_{}.apk", timestamp);
    let temp_apk_path = download_dir.join(&temp_filename);
    let temp_apk_str = temp_apk_path.to_string_lossy().to_string();

    println!(">>> 本地临时保存路径: {}", temp_apk_str);

    // 2. Pull APK 到电脑
    let pull_res = cmd_exec("adb", &["-s", &device_id, "pull", &apk_path, &temp_apk_str]);
    
    if let Err(e) = pull_res {
        return Err(format!("拉取 APK 失败: {}", e));
    }

    // 🔥 关键修复：Windows 上写完文件后可能不会立即释放锁，稍微等待一下
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 3. 使用 Rust zip 库解析
    // 这里的 File::open 之前报错了，现在换了目录应该没问题
    let file = fs::File::open(&temp_apk_path).map_err(|e| format!("无法打开本地 APK 文件 (权限拒绝): {}", e))?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).map_err(|e| format!("APK 解析失败 (不是有效的ZIP): {}", e))?;

    let mut so_list = Vec::new();
    // 尝试获取 APK 在手机上的基础目录名
    let base_dir = apk_path.rsplitn(2, '/').nth(1).unwrap_or(""); 

    for i in 0..archive.len() {
        let file = archive.by_index(i).unwrap();
        let name = file.name().to_string();

        // 过滤 .so 文件 (通常在 lib/ 目录下)
        if name.ends_with(".so") && name.contains("lib/") {
            let file_name = name.split('/').last().unwrap().to_string();
            let size = file.size().to_string();

            // 识别架构
            let arch = if name.contains("arm64") { "arm64-v8a" }
            else if name.contains("armeabi") { "armeabi-v7a" }
            else if name.contains("x86_64") { "x86_64" }
            else if name.contains("x86") { "x86" }
            else { "unknown" };

            // 构造推测的磁盘路径 (仅供参考)
            let disk_arch = if arch == "arm64-v8a" { "arm64" } else { "arm" };
            let disk_path = format!("{}/lib/{}/{}", base_dir, disk_arch, file_name);

            so_list.push(SoFile {
                name: file_name,
                zip_path: name,
                disk_path,
                size,
                arch: arch.to_string(),
            });
        }
    }

    // 4. 解析完成后删除临时文件
    // 即使删除失败也不影响功能，只是多占用一点磁盘空间
    let _ = fs::remove_file(temp_apk_path);

    // 排序
    so_list.sort_by(|a, b| a.name.cmp(&b.name));

    println!(">>> 扫描完成，找到 {} 个 SO 文件", so_list.len());
    Ok(so_list)
}