use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::TcpStream;
use tauri_plugin_shell::process::CommandChild;
use std::process::Child;

pub struct AdbState {
    pub sockets: Arc<Mutex<HashMap<u32, TcpStream>>>,
}

pub struct MitmState {
    pub child: Arc<Mutex<Option<CommandChild>>>,
}

// 定义全局状态来持有 Node 进程
pub struct WebLabState {
    pub child: Arc<Mutex<Option<Child>>>,
    pub tx: Arc<Mutex<Option<std::sync::mpsc::Sender<String>>>>, // 用于向 stdin 发送数据
}