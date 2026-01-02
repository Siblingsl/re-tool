pub mod device;
pub mod app;
pub mod file;
pub mod scrcpy;
pub mod frida;
pub mod apk;
pub mod network;
pub mod ai;
pub mod weblab;
pub mod agent;

// 将通用命令放在这里或者单独文件，这里为了简单放在 mod.rs
#[tauri::command]
pub async fn run_command(cmd: String, args: Vec<String>) -> Result<String, String> {
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    crate::utils::cmd_exec(&cmd, &args_slice)
}

#[tauri::command]
pub async fn open_file_explorer(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        crate::utils::create_command("explorer")
            .args(["/select,", &path])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        open::that(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}