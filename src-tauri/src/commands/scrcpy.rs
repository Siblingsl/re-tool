use std::process::Command;
use std::thread;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;
use tauri::{AppHandle, Manager, Emitter};
use crate::state::AdbState;

#[tauri::command]
pub async fn start_scrcpy(serial: String, max_size: u32, bit_rate: u32) -> Result<(), String> {
    std::thread::spawn(move || {
        let _ = Command::new("scrcpy").arg("-s").arg(serial).arg("--max-size").arg(max_size.to_string()).arg("--video-bit-rate").arg(format!("{}M", bit_rate)).spawn();
    });
    Ok(())
}

#[tauri::command]
pub fn adb_connect(app_handle: tauri::AppHandle, connection_id: u32) -> Result<bool, String> {
    let stream = TcpStream::connect("127.0.0.1:5037").map_err(|e| e.to_string())?;
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut stream_clone = stream.try_clone().map_err(|e| e.to_string())?;
    let app_handle_clone = app_handle.clone(); 

    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match stream_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    let _ = app_handle_clone.emit(&format!("adb-data-{}", connection_id), data);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        let _ = app_handle_clone.emit(&format!("adb-close-{}", connection_id), ());
    });

    let state = app_handle.state::<AdbState>();
    state.sockets.lock().unwrap().insert(connection_id, stream);
    Ok(true)
}

#[tauri::command]
pub fn adb_write(connection_id: u32, data: Vec<u8>, state: tauri::State<'_, AdbState>) -> Result<(), String> {
    let mut sockets = state.sockets.lock().unwrap();
    if let Some(stream) = sockets.get_mut(&connection_id) {
        stream.write_all(&data).map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("Socket not found".to_string())
}

#[tauri::command]
pub fn adb_close(connection_id: u32, state: tauri::State<'_, AdbState>) -> Result<(), String> {
    let mut sockets = state.sockets.lock().unwrap();
    sockets.remove(&connection_id);
    Ok(())
}