import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Button,
  Input,
  Space,
  Tag,
  message,
  Modal,
  Upload,
  List,
  Form,
  Layout,
  Select,
  Tabs,
  Typography,
  Tooltip,
  Card,
} from "antd";
import {
  PlayCircleOutlined,
  StopOutlined,
  ClearOutlined, // 确保引入了清除图标
  SendOutlined,
  SaveOutlined,
  RobotOutlined,
  InboxOutlined,
  FileAddOutlined,
  SettingOutlined,
  CodeOutlined,
  BugOutlined,
  FolderOpenOutlined,
  ConsoleSqlOutlined,
  ApiOutlined,
  DeleteOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import Editor from "@monaco-editor/react";

const { TextArea } = Input;
const { Header } = Layout;
const { Text, Title } = Typography;

const UnidbgLab: React.FC = () => {
  // === 核心状态 ===
  const [projectPath, setProjectPath] = useState<string>("");

  // === UI & 业务状态 ===
  const [activeBottomTab, setActiveBottomTab] = useState("console");
  const [settingsOpen, setSettingsOpen] = useState(false);

  // 🔥 优化初始高度和拖拽体验
  const [panelHeight, setPanelHeight] = useState(250);
  const [isDragging, setIsDragging] = useState(false);

  const [serverStatus, setServerStatus] = useState<"stopped" | "running">(
    "stopped"
  );
  const [loading, setLoading] = useState(false);
  const [soFiles, setSoFiles] = useState<string[]>([]);
  const [config, setConfig] = useState({
    port: 9090,
    aiUrl: "https://api.openai.com/v1",
    aiKey: "",
    aiModel: "gpt-3.5-turbo",
  });

  // === 数据 ===
  const [javaCode, setJavaCode] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const [isCodeDirty, setIsCodeDirty] = useState(false);
  const [aiAnalyzing, setAiAnalyzing] = useState(false);

  // === 调试 ===
  const [endpoint, setEndpoint] = useState("do_work");
  const [requestBody, setRequestBody] = useState(
    JSON.stringify({ data: "test" }, null, 2)
  );
  const [responseBody, setResponseBody] = useState("");

  const logEndRef = useRef<HTMLDivElement>(null);

  // ================= 1. 项目管理 (欢迎页逻辑) =================

  const handleCreateProject = async () => {
    try {
      const selected = await open({ directory: true, title: "选择空文件夹" });
      if (!selected) return;

      setLoading(true);
      await invoke("create_project", { targetDir: selected });
      message.success("创建成功");
      await loadProject(selected as string);
    } catch (e: any) {
      Modal.error({ title: "创建失败", content: e });
    } finally {
      setLoading(false);
    }
  };

  const handleOpenProject = async () => {
    try {
      const selected = await open({ directory: true, title: "选择项目目录" });
      if (!selected) return;

      const isValid = await invoke("check_project_valid", {
        targetDir: selected,
      });
      if (!isValid) {
        message.error("无效的项目 (缺少 pom.xml)");
        return;
      }
      await loadProject(selected as string);
    } catch (e: any) {
      message.error("打开失败: " + e);
    }
  };

  const loadProject = async (path: string) => {
    setProjectPath(path);
    setLoading(true);
    try {
      const code = await invoke<string>("read_code", { projectPath: path });
      setJavaCode(code);
      await refreshSoList(path);
      setupLogListener();
      message.success("项目加载完成");
    } catch (e: any) {
      message.error("加载失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  const handleCloseProject = async () => {
    if (serverStatus === "running") {
      await invoke("stop_server");
    }
    setProjectPath("");
    setLogs([]);
    setServerStatus("stopped");
  };

  // ================= 2. 核心功能 =================

  const refreshSoList = async (path: string) => {
    try {
      const files = await invoke<string[]>("list_so_files", {
        projectPath: path,
      });
      setSoFiles(files);
    } catch (e) {
      console.error(e);
    }
  };

  const setupLogListener = async () => {
    await listen<string>("unidbg-log", (e) => appendLog(e.payload, "info"));
    await listen<string>("unidbg-error", (e) => appendLog(e.payload, "error"));
  };

  const appendLog = (msg: string, type: "info" | "error") => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev.slice(-999), `[${time}] ${msg}`]);
  };

  const toggleServer = async () => {
    if (serverStatus === "stopped") {
      if (isCodeDirty) message.warning("注意：代码未保存，运行的可能是旧代码");
      setActiveBottomTab("console");
      setLoading(true);
      try {
        await invoke("run_server", { projectPath, port: Number(config.port) });
        setServerStatus("running");
        message.success("服务启动中...");
      } catch (e: any) {
        message.error("启动失败: " + e);
        appendLog("Start Error: " + e, "error");
      } finally {
        setLoading(false);
      }
    } else {
      await invoke("stop_server");
      setServerStatus("stopped");
      message.success("服务已停止");
    }
  };

  const handleSave = async () => {
    try {
      await invoke("save_code", { projectPath, code: javaCode });
      message.success("保存成功");
      setIsCodeDirty(false);
    } catch (e) {
      message.error("保存失败: " + e);
    }
  };

  const handleUpload = async (options: any) => {
    const file = options.file as File;
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = async () => {
      const base64 = (reader.result as string).split(",")[1];
      try {
        await invoke("import_so_file", {
          projectPath,
          fileName: file.name,
          base64Data: base64,
        });
        message.success("上传成功");
        refreshSoList(projectPath);
      } catch (e) {
        message.error("上传失败: " + e);
      }
    };
  };

  const handleDeleteSo = (fileName: string) => {
    Modal.confirm({
      title: `确认删除 ${fileName}?`,
      content: "文件将从项目目录中永久删除。",
      okType: "danger",
      onOk: async () => {
        await invoke("delete_so_file", { projectPath, fileName });
        message.success("已删除");
        refreshSoList(projectPath);
      },
    });
  };

  // ================= 3. AI 功能 (新增) =================

  // 功能 1: AI 全量修复 (AI Fix)
  const handleAiFix = async () => {
    const errorLogs = logs.filter(
      (l) =>
        l.includes("JNI") ||
        l.includes("CallStatic") ||
        l.includes("CallObject")
    );
    if (errorLogs.length === 0) return message.warning("暂无明显报错");
    const lastError = errorLogs.slice(-3).join("\n");

    setAiAnalyzing(true);
    message.loading({
      content: "AI 正在思考并重写方法...",
      key: "ai_process",
      duration: 0,
    });

    try {
      const fullPatchedCode = await invoke<string>("call_gemini_service", {
        request: {
          task_type: "unidbg_fix",
          prompt: "",
          context_code: javaCode,
          error_log: lastError,
        },
      });
      setJavaCode(fullPatchedCode);
      setIsCodeDirty(true);
      message.success({ content: "代码已智能修复！", key: "ai_process" });
    } catch (e: any) {
      console.error(e);
      message.error({ content: "修复失败: " + e, key: "ai_process" });
    } finally {
      setAiAnalyzing(false);
    }
  };

  // 功能 2: AI 自动补全 (Auto Fix)
  const handleAutoFix = async () => {
    // 1. 先检查是不是编译挂了
    const buildFailed = logs.some(
      (l) => l.includes("BUILD FAILURE") || l.includes("Compilation failure")
    );
    if (buildFailed) {
      Modal.confirm({
        title: "检测到编译错误",
        content:
          "当前 Java 代码存在语法错误（编译失败），无法使用'追加补全'模式。建议点击右侧的【AI Fix】按钮让 AI 尝试重写修复代码。",
        okText: "帮我点击 AI Fix",
        onOk: handleAiFix,
      });
      return;
    }

    // 2. 检查 JNI 报错
    const errorLogs = logs.filter(
      (l) =>
        l.includes("CallStatic") ||
        l.includes("CallObject") ||
        l.includes("JNI") ||
        l.includes("AbstractJni")
    );
    if (errorLogs.length === 0) {
      return message.warning("当前日志没有明显的 JNI 缺失报错，无法自动修复。");
    }
    const lastError = errorLogs[errorLogs.length - 1];

    setAiAnalyzing(true);
    message.loading({
      content: "AI 正在分析 JNI 缺失并生成代码...",
      key: "ai_fix",
    });

    try {
      const patchCode = await invoke<string>("call_gemini_service", {
        request: {
          task_type: "unidbg_fix",
          prompt: "Fix JNI Error",
          context_code: javaCode,
          error_log: lastError,
        },
      });

      // 插入代码逻辑：找到最后一个花括号
      const trimmedCode = javaCode.trim();
      const lastBraceIndex = trimmedCode.lastIndexOf("}");
      if (lastBraceIndex === -1) {
        throw new Error("无法解析 Java 代码结构");
      }
      const newJavaCode =
        trimmedCode.substring(0, lastBraceIndex) +
        "\n\n    // [AI Auto-Fix]\n" +
        "    " +
        patchCode +
        "\n" +
        trimmedCode.substring(lastBraceIndex);

      setJavaCode(newJavaCode);
      setIsCodeDirty(true);
      message.success({ content: "补丁已自动追加！", key: "ai_fix" });
    } catch (e: any) {
      console.error(e);
      message.error({ content: "AI 修复失败: " + e, key: "ai_fix" });
    } finally {
      setAiAnalyzing(false);
    }
  };

  // ================= 4. 拖拽逻辑 =================

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleMouseMove = useCallback(
    (e: MouseEvent) => {
      if (isDragging) {
        const newHeight = window.innerHeight - e.clientY;
        // 限制最小和最大高度 (Min: 40px 防止死区, Max: 窗口-100px)
        if (newHeight > 40 && newHeight < window.innerHeight - 100) {
          setPanelHeight(newHeight);
        }
      }
    },
    [isDragging]
  );

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    if (isDragging) {
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    } else {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    }
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDragging, handleMouseMove, handleMouseUp]);

  useEffect(() => {
    if (activeBottomTab === "console") {
      logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, activeBottomTab]);

  // ================= 5. 视图渲染 =================

  // === A. 欢迎页 ===
  if (!projectPath) {
    return (
      <div
        style={{
          height: "100vh",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          background: "#f5f5f5",
        }}
      >
        <Card style={{ width: 400, textAlign: "center" }}>
          <Title level={3}>
            <CodeOutlined /> Unidbg Lab
          </Title>
          <Space
            direction="vertical"
            style={{ width: "100%", marginTop: 20 }}
            size="large"
          >
            <Button
              type="primary"
              block
              size="large"
              icon={<PlusOutlined />}
              onClick={handleCreateProject}
              loading={loading}
            >
              新建项目
            </Button>
            <Button
              block
              size="large"
              icon={<FolderOpenOutlined />}
              onClick={handleOpenProject}
            >
              打开项目
            </Button>
          </Space>
        </Card>
      </div>
    );
  }

  // === B. 工作台 ===
  return (
    <Layout style={{ height: "100vh", background: "#fff" }}>
      {/* 拖拽遮罩层 */}
      {isDragging && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 9999,
            cursor: "row-resize",
          }}
        />
      )}

      <Header
        style={{
          background: "#fff",
          borderBottom: "1px solid #eee",
          padding: "0 16px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Space>
          <Button
            type="text"
            icon={<FolderOpenOutlined />}
            onClick={handleCloseProject}
            title="关闭当前项目"
          />
          <Text strong style={{ fontSize: 16 }}>
            {projectPath.split(/[\\/]/).pop()}
          </Text>
          <Tag color="blue">IDE Mode</Tag>
        </Space>
        <Space>
          <Button
            type="primary"
            danger={serverStatus === "running"}
            icon={
              serverStatus === "running" ? (
                <StopOutlined />
              ) : (
                <PlayCircleOutlined />
              )
            }
            onClick={toggleServer}
            loading={loading}
          >
            {serverStatus === "running" ? "停止服务" : "启动 Maven"}
          </Button>
          {serverStatus === "running" && (
            <Tag color="green">Port: {config.port}</Tag>
          )}
          <Button
            icon={<SaveOutlined />}
            onClick={handleSave}
            disabled={!isCodeDirty}
          />
          <Button
            icon={<SettingOutlined />}
            onClick={() => setSettingsOpen(true)}
          />
        </Space>
      </Header>

      <Layout
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          overflow: "hidden",
        }}
      >
        {/* 编辑器 */}
        <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
          <Editor
            height="100%"
            defaultLanguage="java"
            value={javaCode}
            theme="vs-light"
            onChange={(v) => {
              setJavaCode(v || "");
              setIsCodeDirty(true);
            }}
            options={{
              minimap: { enabled: false },
              fontSize: 14,
              padding: { top: 16 },
            }}
          />
        </div>

        {/* 拖拽分割线 */}
        <div
          onMouseDown={handleMouseDown}
          style={{
            height: "5px",
            background: isDragging ? "#1890ff" : "#f0f0f0",
            cursor: "row-resize",
            zIndex: 10,
            transition: "background 0.2s",
          }}
        />

        {/* 底部面板 */}
        <div
          style={{
            height: panelHeight,
            minHeight: 250, // 🔥 修复：与 JS 逻辑对齐，允许拖拽得更小
            background: "#fff",
            display: "flex",
            flexDirection: "column",
            borderTop: "1px solid #ddd",
            userSelect: isDragging ? "none" : "auto",
          }}
        >
          {/* 底部面板 Tab 栏 */}
          <div style={{ background: "#f5f5f5", padding: "0 16px" }}>
            <Tabs
              activeKey={activeBottomTab}
              onChange={setActiveBottomTab}
              size="small"
              tabBarStyle={{ marginBottom: 0, border: "none" }}
              items={[
                {
                  key: "console",
                  label: (
                    <span>
                      <ConsoleSqlOutlined /> 控制台
                    </span>
                  ),
                },
                {
                  key: "debug",
                  label: (
                    <span>
                      <BugOutlined /> 调试
                    </span>
                  ),
                },
                {
                  key: "files",
                  label: (
                    <span>
                      <FolderOpenOutlined /> 资源文件
                    </span>
                  ),
                },
              ]}
            />
          </div>

          <div style={{ flex: 1, overflow: "hidden" }}>
            {/* === 1. 控制台面板 (带 AI 按钮) === */}
            {activeBottomTab === "console" && (
              <div
                style={{
                  height: "100%",
                  display: "flex",
                  flexDirection: "column",
                  background: "#1e1e1e",
                  borderTop: "1px solid #333",
                }}
              >
                {/* 工具栏 */}
                <div
                  style={{
                    padding: "4px 12px",
                    background: "#252526",
                    borderBottom: "1px solid #333",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <Text style={{ color: "#ccc", fontSize: 12 }}>
                    System Output
                  </Text>
                  <Space>
                    {/* 🔥🔥 新增 AI 按钮区域 🔥🔥 */}
                    <Tooltip title="自动分析日志，生成缺失的 JNI 方法">
                      <Button
                        size="small"
                        type="primary"
                        icon={<ApiOutlined />}
                        loading={aiAnalyzing}
                        onClick={handleAutoFix}
                        style={{
                          background:
                            "linear-gradient(90deg, #722ed1, #1890ff)",
                          border: "none",
                          fontSize: 12,
                        }}
                      >
                        AI 补全
                      </Button>
                    </Tooltip>
                    <Tooltip title="AI 修复全量代码">
                      <Button
                        size="small"
                        type="primary"
                        ghost
                        icon={<RobotOutlined />}
                        loading={aiAnalyzing}
                        onClick={handleAiFix}
                        style={{ fontSize: 12 }}
                      >
                        AI Fix
                      </Button>
                    </Tooltip>
                    <Button
                      size="small"
                      icon={<ClearOutlined />}
                      onClick={() => setLogs([])}
                    />
                  </Space>
                </div>
                {/* 日志内容 */}
                <div
                  style={{
                    flex: 1,
                    overflowY: "auto",
                    padding: 10,
                    fontFamily: "monospace",
                    color: "#ccc",
                  }}
                >
                  {logs.map((l, i) => (
                    <div
                      key={i}
                      style={{
                        color:
                          l.includes("ERROR") || l.includes("FAILURE")
                            ? "#ff4d4f"
                            : l.includes("INFO")
                            ? "#5cdbd3"
                            : "inherit",
                      }}
                    >
                      {l}
                    </div>
                  ))}
                  <div ref={logEndRef} />
                </div>
              </div>
            )}

            {/* === 2. 调试面板 === */}
            {activeBottomTab === "debug" && (
              <div
                style={{
                  padding: 10,
                  display: "flex",
                  height: "100%",
                  gap: 10,
                }}
              >
                <div style={{ flex: 1 }}>
                  <Input
                    addonBefore="/api/"
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    style={{ marginBottom: 8 }}
                  />
                  <TextArea
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    style={{ height: "calc(100% - 80px)" }}
                  />
                  <Button
                    type="primary"
                    block
                    style={{ marginTop: 8 }}
                    onClick={async () => {
                      try {
                        const res = await invoke<string>("unidbg_request", {
                          path: endpoint,
                          payload: JSON.parse(requestBody),
                        });
                        setResponseBody(res);
                      } catch (e: any) {
                        setResponseBody("Error: " + e);
                      }
                    }}
                  >
                    发送请求
                  </Button>
                </div>
                <div style={{ flex: 1 }}>
                  <TextArea
                    value={responseBody}
                    readOnly
                    style={{ height: "100%", background: "#f5f5f5" }}
                  />
                </div>
              </div>
            )}

            {/* === 3. 文件列表面板 === */}
            {activeBottomTab === "files" && (
              <div
                style={{
                  padding: 10,
                  display: "flex",
                  height: "100%",
                  gap: 10,
                }}
              >
                <div style={{ width: 250 }}>
                  <Upload.Dragger
                    customRequest={handleUpload}
                    showUploadList={false}
                    style={{ padding: 20, background: "#fff" }}
                  >
                    <p>
                      <InboxOutlined
                        style={{ fontSize: 24, color: "#1890ff" }}
                      />
                    </p>
                    <p>点击或拖拽上传 .so</p>
                  </Upload.Dragger>
                </div>
                <div
                  style={{
                    flex: 1,
                    overflowY: "auto",
                    border: "1px solid #eee",
                  }}
                >
                  <List
                    size="small"
                    dataSource={soFiles}
                    renderItem={(item) => (
                      <List.Item
                        actions={[
                          <Button
                            danger
                            type="text"
                            size="small"
                            icon={<DeleteOutlined />}
                            onClick={() => handleDeleteSo(item)}
                          />,
                        ]}
                      >
                        <Space>
                          <FileAddOutlined /> {item}
                        </Space>
                      </List.Item>
                    )}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      </Layout>

      {/* 设置弹窗 */}
      <Modal
        title="环境设置"
        open={settingsOpen}
        onCancel={() => setSettingsOpen(false)}
        onOk={() => setSettingsOpen(false)}
      >
        <Form layout="vertical">
          <Form.Item label="服务端口">
            <Input
              type="number"
              value={config.port}
              onChange={(e) =>
                setConfig({ ...config, port: Number(e.target.value) })
              }
            />
          </Form.Item>
          <Form.Item label="AI Base URL">
            <Input
              value={config.aiUrl}
              onChange={(e) => setConfig({ ...config, aiUrl: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="AI API Key">
            <Input.Password
              value={config.aiKey}
              onChange={(e) => setConfig({ ...config, aiKey: e.target.value })}
            />
          </Form.Item>
          <Form.Item label="AI Model">
            <Select
              value={config.aiModel}
              onChange={(v) => setConfig({ ...config, aiModel: v })}
              options={[
                { value: "gpt-3.5-turbo", label: "GPT-3.5" },
                { value: "gpt-4", label: "GPT-4" },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
};

export default UnidbgLab;
