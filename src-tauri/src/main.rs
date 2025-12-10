#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod models;
mod state;
mod utils;
mod commands;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tauri::Manager;
use state::{AdbState, MitmState};
use commands::*; // 引入所有模块的命令

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(MitmState {
            child: Arc::new(Mutex::new(None)),
        })
        .manage(AdbState { 
            sockets: Arc::new(Mutex::new(HashMap::new())) 
        })
        .setup(|app| {
            let handle = app.handle().clone();
            // 启动设备监控
            device::start_device_monitor(handle.clone());
            // 启动 mDNS 发现
            device::start_mdns_discovery(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // ai
            ai::call_gemini_service,

            // Device
            device::get_all_devices,
            device::enable_wireless_mode,
            device::get_device_ip,
            device::adb_pair,
            device::get_device_abi,
            device::check_is_rooted,
            
            // App
            app::get_device_apps,
            app::install_apk,
            app::get_app_detail,
            app::launch_app,
            app::stop_app,
            app::get_foreground_app,
            app::extract_apk,

            // File (Remote)
            file::get_file_list,
            file::read_file_content,
            file::save_file_content,
            file::delete_file,
            file::create_dir,
            file::rename_file,

            // Scrcpy
            scrcpy::start_scrcpy,
            scrcpy::adb_connect,
            scrcpy::adb_write,
            scrcpy::adb_close,

            // Frida
            frida::get_frida_versions,
            frida::check_frida_installed,
            frida::deploy_tool,
            frida::check_frida_running,
            frida::run_frida_script,

            // APK Tools (Local)
            apk::apk_decode,
            apk::scan_local_dir,
            apk::read_local_file,
            apk::save_local_file,
            apk::apk_build_sign_install,
            apk::jadx_decompile,
            apk::search_project,
            apk::detect_packer,
            apk::pull_and_organize_dex,
            apk::get_apk_path,   // 注册
            apk::lists_so_files,

            // Network / Mitm
            network::start_mitmproxy,
            network::stop_mitmproxy,
            network::install_cert_to_phone,
            network::install_cert_root,
            network::get_local_ip,
            network::replay_request,

            // Common
            commands::run_command,
            commands::open_file_explorer
            
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            match event {
                // --- 3. 监听退出事件 ---
                tauri::RunEvent::ExitRequested { .. } => {
                    println!("[Main] App is exiting, cleaning up child processes...");

                    // 清理 Mitmproxy
                    let mitm_state = app_handle.state::<MitmState>();
                    let mut mitm_child = mitm_state.child.lock().unwrap();
                    if let Some(child) = mitm_child.take() {
                        // child.kill() 可能会失败（例如进程早退出了），用 Result 忽略错误
                        let _ = child.kill(); 
                        println!("[Main] Mitmproxy process killed.");
                    }
                }
                _ => {}
            }
        });
}