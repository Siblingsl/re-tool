import React, { useState, useEffect } from "react";
import {
  Table,
  Button,
  Breadcrumb,
  Space,
  message,
  Input,
  Dropdown,
  Tooltip,
} from "antd";
import {
  FolderOpenFilled,
  FileOutlined,
  ArrowUpOutlined,
  ReloadOutlined,
  HomeOutlined,
  DownloadOutlined,
  MoreOutlined,
  FileTextOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { FileItem } from "../../types";

interface FileExplorerProps {
  deviceId: string;
  initialPath?: string; // 初始路径
  // 🔥 新增：显示模式 ('full' = 全屏大模式, 'compact' = 抽屉小模式)
  mode?: "full" | "compact";
}

const FileExplorer: React.FC<FileExplorerProps> = ({
  deviceId,
  initialPath = "/sdcard",
  mode = "full",
}) => {
  const [currentPath, setCurrentPath] = useState(initialPath);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchFiles = async (path: string) => {
    setLoading(true);
    try {
      const res = await invoke<FileItem[]>("get_file_list", { deviceId, path });
      setFiles(res);
      setCurrentPath(path);
    } catch (e: any) {
      message.error(`无法访问路径: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles(currentPath);
  }, [deviceId, initialPath]); // 初始化加载

  // 进入文件夹
  const handleEnter = (name: string) => {
    const newPath = currentPath === "/" ? `/${name}` : `${currentPath}/${name}`;
    fetchFiles(newPath);
  };

  // 返回上一级
  const handleUp = () => {
    if (currentPath === "/") return;
    const parts = currentPath.split("/");
    parts.pop();
    const newPath = parts.length === 1 ? "/" : parts.join("/");
    fetchFiles(newPath);
  };

  const formatSize = (sizeStr: string) => {
    if (!sizeStr) return "-";
    const size = parseInt(sizeStr);
    if (isNaN(size)) return "-";
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
    return (size / 1024 / 1024).toFixed(1) + " MB";
  };

  // --- 列定义 ---
  const allColumns: any = [
    {
      title: "名称",
      dataIndex: "name",
      key: "name",
      ellipsis: true,
      // 小屏自适应，大屏给宽一点
      width: mode === "compact" ? undefined : 300,
      render: (text: string, record: FileItem) => (
        <Space
          style={{ cursor: "pointer", width: "100%" }}
          onClick={() => record.is_dir && handleEnter(text)}
        >
          {record.is_dir ? (
            <FolderOpenFilled style={{ color: "#faad14", fontSize: 18 }} />
          ) : (
            <FileTextOutlined style={{ color: "#8c8c8c", fontSize: 16 }} />
          )}
          <span
            style={{ fontWeight: record.is_dir ? 500 : 400, color: "#333" }}
          >
            {text}
          </span>
        </Space>
      ),
    },
    {
      title: "权限",
      dataIndex: "permissions",
      key: "permissions",
      width: 100,
      className: "text-gray-400",
      render: (text: string) => (
        <span style={{ fontFamily: "monospace", fontSize: 12, color: "#999" }}>
          {text}
        </span>
      ),
      hidden: mode === "compact", // 小屏隐藏
    },
    {
      title: "大小",
      dataIndex: "size",
      key: "size",
      width: 80,
      align: "right",
      render: (text: string) => (
        <span style={{ color: "#999", fontSize: 12 }}>{formatSize(text)}</span>
      ),
    },
    {
      title: "修改时间",
      dataIndex: "date",
      key: "date",
      width: mode === "compact" ? 90 : 150,
      align: "right",
      ellipsis: true,
      render: (text: string) => (
        <Tooltip title={text}>
          {/* 小屏只显示日期 */}
          <span style={{ color: "#999", fontSize: 12 }}>
            {mode === "compact" ? text.split(" ")[0] : text}
          </span>
        </Tooltip>
      ),
    },
    {
      title: " ",
      key: "action",
      width: 40,
      align: "center",
      render: (_: any, record: FileItem) =>
        !record.is_dir && (
          <Dropdown
            menu={{
              items: [
                {
                  key: "download",
                  label: "下载到电脑",
                  icon: <DownloadOutlined />,
                },
                { key: "info", label: "详细信息" },
              ],
            }}
          >
            <Button
              type="text"
              size="small"
              icon={<MoreOutlined style={{ color: "#999" }} />}
            />
          </Dropdown>
        ),
    },
  ];

  const columns = allColumns.filter((col: any) => !col.hidden);

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "#fff",
      }}
    >
      {/* 顶部导航栏 */}
      <div
        style={{
          padding: "8px 8px",
          borderBottom: "1px solid #eee",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <Button
          icon={<ArrowUpOutlined />}
          onClick={handleUp}
          disabled={currentPath === "/"}
        />
        <Button icon={<HomeOutlined />} onClick={() => fetchFiles("/sdcard")} />
        <Input
          value={currentPath}
          onPressEnter={(e) => fetchFiles(e.currentTarget.value)}
          style={{ flex: 1 }}
        />
        <Button
          icon={<ReloadOutlined />}
          onClick={() => fetchFiles(currentPath)}
          loading={loading}
        />
      </div>

      {/* 文件列表 */}
      <div
        className={`auto-fit-table ${mode === "compact" ? "no-scrollbar" : ""}`}
        style={{ flex: 1, overflow: "hidden" }}
      >
        <Table
          dataSource={files}
          columns={columns}
          rowKey="name"
          size="small"
          pagination={false}
          loading={loading}
          scroll={{ x: "max-content", y: "100%" }}
          onRow={(record) => ({
            onDoubleClick: () => {
              if (record.is_dir) handleEnter(record.name);
            },
          })}
        />
      </div>
      <div
        style={{
          padding: "4px 12px",
          borderTop: "1px solid #f0f0f0",
          fontSize: 11,
          color: "#bbb",
          display: "flex",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <span>{files.length} 个项目</span>
        {mode === "full" && <span>{deviceId}</span>}
      </div>
    </div>
  );
};

export default FileExplorer;
