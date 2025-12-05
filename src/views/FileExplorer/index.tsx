import React, { useState, useEffect } from "react";
import {
  Table,
  Button,
  Input,
  Space,
  message,
  Tooltip,
  Dropdown,
  Modal,
} from "antd";
import {
  FolderOpenFilled,
  ArrowUpOutlined,
  ReloadOutlined,
  HomeOutlined,
  DownloadOutlined,
  MoreOutlined,
  FileTextOutlined,
  EditOutlined,
  DeleteOutlined,
  FolderAddOutlined,
  FileAddOutlined,
  SaveOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { FileItem } from "../../types";

interface FileExplorerProps {
  deviceId: string;
  initialPath?: string;
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

  // --- 状态管理：文件查看/编辑 ---
  // 复用 viewModalOpen 作为编辑器开关
  const [editorOpen, setEditorOpen] = useState(false);
  const [fileContent, setFileContent] = useState("");
  const [editingFile, setEditingFile] = useState(""); // 当前正在操作的文件名
  const [editorLoading, setEditorLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  // --- 状态管理：新建/重命名 ---
  const [inputModalOpen, setInputModalOpen] = useState(false);
  const [inputType, setInputType] = useState<
    "new-folder" | "new-file" | "rename"
  >("new-folder");
  const [inputValue, setInputValue] = useState("");

  // 基础操作：获取文件列表
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
  }, [deviceId, initialPath]);

  // 导航操作
  const handleEnter = (name: string) => {
    const newPath = currentPath === "/" ? `/${name}` : `${currentPath}/${name}`;
    fetchFiles(newPath);
  };

  const handleUp = () => {
    if (currentPath === "/") return;
    const parts = currentPath.split("/");
    parts.pop();
    const newPath = parts.length === 1 ? "/" : parts.join("/") || "/";
    fetchFiles(newPath);
  };

  // --- 核心逻辑：查看与编辑文件 ---
  const handleOpenFile = async (fileName: string) => {
    const filePath =
      currentPath === "/" ? `/${fileName}` : `${currentPath}/${fileName}`;
    setEditingFile(fileName); // 记录文件名
    setEditorOpen(true); // 打开编辑器 Modal
    setEditorLoading(true);
    setFileContent(""); // 清空旧内容

    try {
      const content = await invoke<string>("read_file_content", {
        deviceId,
        path: filePath,
      });
      setFileContent(content);
    } catch (e: any) {
      setFileContent(`(无法读取文件内容: ${e})`);
    } finally {
      setEditorLoading(false);
    }
  };

  // --- 核心逻辑：保存文件 ---
  const handleSaveContent = async () => {
    setSaving(true);
    const filePath =
      currentPath === "/" ? `/${editingFile}` : `${currentPath}/${editingFile}`;
    try {
      await invoke("save_file_content", {
        deviceId,
        path: filePath,
        content: fileContent,
      });
      message.success("保存成功");
      setEditorOpen(false);
      fetchFiles(currentPath); // 刷新列表以更新大小/时间
    } catch (e: any) {
      message.error("保存失败: " + e);
    } finally {
      setSaving(false);
    }
  };

  // --- 核心逻辑：删除 ---
  const handleDelete = (fileName: string) => {
    Modal.confirm({
      title: `确认删除 "${fileName}"?`,
      content: "此操作不可恢复，如果是系统文件请谨慎操作。",
      okText: "删除",
      okType: "danger",
      cancelText: "取消",
      onOk: async () => {
        const filePath =
          currentPath === "/" ? `/${fileName}` : `${currentPath}/${fileName}`;
        try {
          await invoke("delete_file", { deviceId, path: filePath });
          message.success("已删除");
          fetchFiles(currentPath);
        } catch (e) {
          message.error("删除失败: " + e);
        }
      },
    });
  };

  // --- 核心逻辑：新建/重命名输入框 ---
  const openInputModal = (
    type: "new-folder" | "new-file" | "rename",
    targetName?: string
  ) => {
    setInputType(type);
    setInputValue(type === "rename" ? targetName || "" : "");
    // 如果是重命名，记录原始文件名到 editingFile，方便提交时查找
    if (type === "rename" && targetName) {
      setEditingFile(targetName);
    }
    setInputModalOpen(true);
  };

  const handleInputSubmit = async () => {
    if (!inputValue.trim()) return;

    const fullPath =
      currentPath === "/"
        ? `/${inputValue}`
        : `${currentPath}/${inputValue}`;

    try {
      if (inputType === "new-folder") {
        await invoke("create_dir", { deviceId, path: fullPath });
        message.success("文件夹已创建");
      } else if (inputType === "new-file") {
        await invoke("save_file_content", {
          deviceId,
          path: fullPath,
          content: "",
        }); // 创建空文件
        message.success("文件已创建");
      } else if (inputType === "rename") {
        const oldPath =
          currentPath === "/"
            ? `/${editingFile}`
            : `${currentPath}/${editingFile}`;
        await invoke("rename_file", {
          deviceId,
          oldPath,
          newPath: fullPath,
        });
        message.success("重命名成功");
      }
      setInputModalOpen(false);
      fetchFiles(currentPath);
    } catch (e) {
      message.error("操作失败: " + e);
    }
  };

  // 辅助：格式化大小
  const formatSize = (sizeStr: string) => {
    if (!sizeStr) return "-";
    const size = parseInt(sizeStr);
    if (isNaN(size)) return "-";
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
    return (size / 1024 / 1024).toFixed(1) + " MB";
  };

  const allColumns: any = [
    {
      title: "名称",
      dataIndex: "name",
      key: "name",
      ellipsis: true,
      width: mode === "compact" ? undefined : 300,
      render: (text: string, record: FileItem) => (
        <Space
          style={{ cursor: "pointer", width: "100%" }}
          onClick={() =>
            record.is_dir ? handleEnter(text) : handleOpenFile(text)
          }
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
      hidden: mode === "compact",
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
      render: (_: any, record: FileItem) => (
        <Dropdown
          menu={{
            items: [
              // 🔥 新增：重命名和删除
              {
                key: "rename",
                label: "重命名",
                icon: <EditOutlined />,
                onClick: () => openInputModal("rename", record.name),
              },
              {
                key: "delete",
                label: "删除",
                icon: <DeleteOutlined />,
                danger: true,
                onClick: () => handleDelete(record.name),
              },
              { type: "divider" },
              !record.is_dir
                ? {
                    key: "download",
                    label: "下载到电脑",
                    icon: <DownloadOutlined />,
                    onClick: () => {
                      // 这里调用之前的 extract_apk 逻辑或者新建一个 download_file 接口
                      message.info("下载功能复用 extract_apk 逻辑即可");
                    },
                  }
                : null,
            ].filter(Boolean) as any,
          }}
        >
          <Button
            type="text"
            size="small"
            icon={<MoreOutlined style={{ color: "#999" }} />}
            onClick={(e) => e.stopPropagation()}
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
      {/* 顶部工具栏 */}
      <div
        style={{
          padding: "8px 16px",
          borderBottom: "1px solid #eee",
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexShrink: 0,
        }}
      >
        <Button
          icon={<ArrowUpOutlined />}
          onClick={handleUp}
          disabled={currentPath === "/"}
        />
        <Button icon={<HomeOutlined />} onClick={() => fetchFiles("/sdcard")} />
        <Input
          prefix={<FolderOpenFilled style={{ color: "#faad14" }} />}
          value={currentPath}
          onChange={(e) => setCurrentPath(e.target.value)}
          onPressEnter={(e: any) => fetchFiles(e.target.value)}
          style={{ flex: 1, fontSize: 13 }}
          variant="filled"
        />
        {/* 🔥 新增：新建按钮组 */}
        <Tooltip title="新建文件夹">
          <Button
            icon={<FolderAddOutlined />}
            onClick={() => openInputModal("new-folder")}
          />
        </Tooltip>
        <Tooltip title="新建文件">
          <Button
            icon={<FileAddOutlined />}
            onClick={() => openInputModal("new-file")}
          />
        </Tooltip>
        <Button
          icon={<ReloadOutlined />}
          onClick={() => fetchFiles(currentPath)}
          loading={loading}
        />
      </div>

      {/* 文件列表 */}
      <div
        className={`auto-fit-table ${
          mode === "compact" ? "no-scrollbar" : ""
        }`}
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
          bordered={false}
          onRow={(record) => ({
            onDoubleClick: () => {
              if (record.is_dir) {
                handleEnter(record.name);
              } else {
                handleOpenFile(record.name); // 双击编辑
              }
            },
          })}
        />
      </div>

      {/* 底部信息 */}
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

      {/* 🔥 升级版：文件查看/编辑器 Modal */}
      <Modal
        title={
          <Space>
            <span>{editingFile}</span>
            <span style={{ fontSize: 12, color: "#999", fontWeight: "normal" }}>
              {editorLoading ? "读取中..." : ""}
            </span>
          </Space>
        }
        open={editorOpen}
        onCancel={() => setEditorOpen(false)}
        width={800}
        // 🔥 增加保存按钮
        footer={[
          <Button key="cancel" onClick={() => setEditorOpen(false)}>
            取消
          </Button>,
          <Button
            key="save"
            type="primary"
            icon={<SaveOutlined />}
            loading={saving}
            onClick={handleSaveContent}
          >
            保存修改
          </Button>,
        ]}
      >
        <Input.TextArea
          value={fileContent}
          onChange={(e) => setFileContent(e.target.value)}
          rows={20}
          style={{
            fontFamily: "monospace",
            fontSize: 12,
            whiteSpace: "pre", // 保留换行格式
            backgroundColor: "#1e1e1e",
            color: "#d4d4d4",
            border: "none",
          }}
          spellCheck={false}
        />
      </Modal>

      {/* 🔥 新增：输入 Modal (新建/重命名) */}
      <Modal
        title={
          inputType === "new-folder"
            ? "新建文件夹"
            : inputType === "new-file"
            ? "新建文件"
            : "重命名"
        }
        open={inputModalOpen}
        onOk={handleInputSubmit}
        onCancel={() => setInputModalOpen(false)}
        okText="确定"
        cancelText="取消"
      >
        <Input
          placeholder="请输入名称"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onPressEnter={handleInputSubmit}
          autoFocus
        />
      </Modal>
    </div>
  );
};

export default FileExplorer;