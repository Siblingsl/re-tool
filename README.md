# 🛠️ Android Reverse Workbench (安卓逆向工作台)

> 一个基于 **Rust** (Tauri) 和 **React** 构建的现代化、高性能 Android 逆向工程综合工具箱。

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Tauri](https://img.shields.io/badge/Tauri-v2-orange)
![React](https://img.shields.io/badge/React-18-blue)
![Rust](https://img.shields.io/badge/Rust-1.70%2B-black)

## 📖 简介

**Android Reverse Workbench** 旨在为逆向工程师提供一个 **All-in-One** 的可视化操作平台。它将繁琐的命令行工具（ADB, Frida, Apktool 等）封装在优雅的图形界面中，通过 Rust 后端提供极致的性能体验。

无需记忆复杂的命令，从应用管理、Frida 动态注入到 Native 库分析，一切操作尽在指尖。

## ✨ 核心功能

### 1. 📱 设备与应用全生命周期管理

- **多设备支持**：自动检测并管理连接的 Android 设备（同时预留 iOS 支持）。
- **可视化应用列表**：网格化展示已安装应用，支持图标显示、关键词搜索。
- **深度信息查看**：一键查看 App 的核心信息，包括：
  - Package Name / UID
  - Version Code / Name
  - Min SDK / Target SDK
  - 真实数据目录 (`/data/user/0/...`)
  - 真实 APK 路径
  - 安装时间
- **快捷操作**：支持一键**卸载应用**、**提取 APK** 到本地。

### 2. 💉 Frida 动态调试工作台

告别繁琐的命令行，内置强大的 Frida 交互面板：

- **双模式注入**：
  - **Spawn (重启注入)**：冷启动应用，适合 Hook 启动阶段逻辑或加固壳。
  - **Attach (热注入)**：无缝附加到当前运行进程，不打断应用运行。
- **脚本管理**：下拉选择常用脚本（如 `通用 SSL Bypass`），支持脚本工坊扩展。
- **算法分析**：内置算法助手，辅助分析加密逻辑。

### 3. 📂 SO 库深度分析器 (SO Viewer)

- **智能解析**：无需手动解压 APK，直接查看应用内部的 Native 库 (`.so`) 列表。
- **架构识别**：自动识别 SO 文件架构 (`arm64-v8a`, `armeabi-v7a` 等) 及文件大小。
- **一键导出**：支持将选中的 `.so` 文件单独导出到电脑进行 IDA 分析。
- **稳健模式**：后端采用智能拉取策略，兼容未 Root 手机的文件读取权限。

### 4. 🧰 综合逆向工具箱 (Sidebar Tools)

集成了逆向工程所需的常用工具链：

- **一键抓包**：集成 Mitmproxy，可视化配置网络代理。
- **Java 源码分析**：集成 JADX，快速反编译预览。
- **Unidbg 实验室**：(实验性) 可视化运行 Unidbg 模拟执行代码，支持参数构造与 API 调试。
- **APK 改包工坊**：提供 APK 反编译、回编译、签名的一站式流。
- **ARM 汇编实验室**：辅助汇编代码学习与转换。

## 🛠️ 技术栈

- **Frontend**: React, TypeScript, Ant Design (UI)
- **Backend**: Rust (Tauri), Rayon (并行计算), Zip (文件解析)
- **Communication**: Tauri IPC (Frontend-Backend Bridge)
- **External Tools**: ADB, Frida-tools, Python

## 🚀 快速开始

### 环境要求

- Node.js (v16+)
- Rust (Cargo)
- ADB (需配置到系统环境变量)
- Python & Frida (用于动态注入功能)

### 安装与运行

1.  **安装前端依赖**

    ```bash
    npm install
    # 或者
    yarn install
    ```

2.  **开发模式启动**

    ```bash
    npm run tauri dev
    # 或者
    yarn tauri dev
    ```

3.  **生产环境打包**
    ```bash
    npm run tauri build
    ```

## 🤝 贡献

欢迎提交 Issue 或 Pull Request 来改进这个项目！无论是新功能的建议还是 Bug 反馈，都非常感谢。

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源。
