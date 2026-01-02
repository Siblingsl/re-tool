use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceItem {
    pub id: String,
    pub name: String,
    pub status: String,
    pub os: String,
    pub type_: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppItem {
    pub id: String,
    pub name: String,
    pub pkg: String,
    pub ver: String,
    pub icon: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppDetail {
    pub versionName: String,
    pub versionCode: String,
    pub minSdk: String,
    pub targetSdk: String,
    pub dataDir: String,
    pub sourceDir: String,
    pub uid: String,
    pub firstInstallTime: String,
    pub lastUpdateTime: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FridaRelease {
    pub tag_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileItem {
    pub name: String,
    pub is_dir: bool,
    pub size: String,
    pub permissions: String,
    pub date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileNode {
    pub key: String,
    #[serde(rename = "isLeaf")]
    pub is_leaf: bool, 
    pub title: String,
    pub children: Option<Vec<FileNode>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchResult {
    pub file_path: String,
    pub line_num: usize,
    pub content: String,
    pub match_type: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AiRequest {
    pub prompt: String,
    pub task_type: String,
    pub context_code: Option<String>,
    pub error_log: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SoFile {
    pub name: String,
    pub zip_path: String,  // 在 APK 内部的路径
    pub disk_path: String, // 推测的磁盘路径
    pub size: String,
    pub arch: String,
}