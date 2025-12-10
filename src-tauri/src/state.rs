use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::TcpStream;
use tauri_plugin_shell::process::CommandChild;

pub struct AdbState {
    pub sockets: Arc<Mutex<HashMap<u32, TcpStream>>>,
}

pub struct MitmState {
    pub child: Arc<Mutex<Option<CommandChild>>>,
}

pub struct UnidbgState {
    pub child: Arc<Mutex<Option<CommandChild>>>,
    pub server_child: Mutex<Option<CommandChild>>,

}

pub struct UnidbgProcessState {
    pub child: Mutex<Option<std::process::Child>>,
}