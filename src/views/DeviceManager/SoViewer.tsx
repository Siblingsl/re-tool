import React, { useEffect, useState } from "react";
import {
  List,
  Button,
  Tag,
  Space,
  Input,
  message,
  Tooltip,
  Empty,
  Spin,
} from "antd";
import {
  FileZipOutlined,
  DownloadOutlined,
  SearchOutlined,
  CloseOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

interface SoFile {
  name: string;
  zip_path: string;
  disk_path: string;
  size: string;
  arch: string;
}

interface SoViewerProps {
  deviceId: string;
  pkg: string;
  apkPath?: string;
  onClose: () => void;
  onAnalyze?: (path: string) => void;
}

const SoViewer: React.FC<SoViewerProps> = ({
  deviceId,
  pkg,
  apkPath: propApkPath,
  onClose,
  onAnalyze,
}) => {
  const [loading, setLoading] = useState(false);
  const [files, setFiles] = useState<SoFile[]>([]);
  const [searchText, setSearchText] = useState("");

  useEffect(() => {
    loadSoList();
  }, [pkg]);

  // 🔥 核心修正：这里只保留调用 Rust 后端的逻辑
  // 之前的 loadData 逻辑现在合并到了这里
  const loadSoList = async () => {
    setLoading(true);
    setFiles([]);

    try {
      let targetPath = propApkPath;

      // 1. 获取 APK 路径
      if (!targetPath) {
        targetPath = await invoke<string>("get_apk_path", { deviceId, pkg });
      }

      if (!targetPath) {
        throw new Error("无法定位 APK 路径");
      }

      console.log("正在请求后端解析 SO, APK:", targetPath);

      // 2. 🔥 调用 Rust 后端命令 (list_so_files)
      // 这个命令会自动把 APK 拉到电脑临时目录并解析，绕过手机权限限制
      const list = await invoke<SoFile[]>("lists_so_files", {
        deviceId,
        apkPath: targetPath,
      });

      setFiles(list);
    } catch (e: any) {
      console.error(e);
      message.error(`加载失败: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (item: SoFile) => {
    try {
      const savePath = await save({
        defaultPath: item.name,
        filters: [{ name: "Shared Object", extensions: ["so"] }],
      });
      if (!savePath) return;

      const msgKey = "pull_so";
      message.loading({ content: `正在导出 ${item.name}...`, key: msgKey });

      // 尝试直接导出 (后端计算好的 disk_path)
      try {
        await invoke("run_command", {
          cmd: "adb",
          args: ["-s", deviceId, "pull", item.disk_path, savePath],
        });
        message.success({ content: "导出成功", key: msgKey });
      } catch (e) {
        message.warning({
          content: "无法直接导出 (App未解压SO)，请使用「提取APK」功能",
          key: msgKey,
        });
      }
    } catch (e) {
      message.error(`导出失败: ${e}`);
    }
  };

  const filteredFiles = files.filter((f) =>
    f.name.toLowerCase().includes(searchText.toLowerCase())
  );

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "#fff",
        borderLeft: "1px solid #f0f0f0",
      }}
    >
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid #f0f0f0",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "#fafafa",
        }}
      >
        <Space>
          <FileZipOutlined />
          <span style={{ fontWeight: "bold" }}>
            SO 库 ({filteredFiles.length})
          </span>
          <Button
            type="text"
            size="small"
            icon={<ReloadOutlined />}
            onClick={loadSoList}
            loading={loading}
          />
        </Space>
        <Space>
          <Input
            placeholder="搜索..."
            prefix={<SearchOutlined style={{ color: "#ccc" }} />}
            size="small"
            style={{ width: 120 }}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            allowClear
          />
          <Button type="text" icon={<CloseOutlined />} onClick={onClose} />
        </Space>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 0 }}>
        <Spin spinning={loading} tip="正在拉取 APK 解析中...">
          {filteredFiles.length === 0 ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description={loading ? "分析中..." : "未找到 SO 文件"}
              style={{ marginTop: 50 }}
            />
          ) : (
            <List
              dataSource={filteredFiles}
              renderItem={(item) => (
                <List.Item
                  style={{ padding: "10px 16px", cursor: "pointer" }}
                  actions={[
                    <Tooltip title="导出">
                      <Button
                        type="text"
                        icon={<DownloadOutlined />}
                        onClick={() => handleExport(item)}
                      />
                    </Tooltip>,
                  ]}
                >
                  <List.Item.Meta
                    avatar={
                      <Tag color={item.arch.includes("64") ? "blue" : "orange"}>
                        {item.arch}
                      </Tag>
                    }
                    title={
                      <span style={{ fontSize: 13, fontWeight: 500 }}>
                        {item.name}
                      </span>
                    }
                    description={
                      <div style={{ fontSize: 11, color: "#999" }}>
                        {item.zip_path} <br />
                        <span style={{ color: "#ccc" }}>
                          Size: {parseInt(item.size).toLocaleString()} bytes
                        </span>
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          )}
        </Spin>
      </div>
    </div>
  );
};

export default SoViewer;
