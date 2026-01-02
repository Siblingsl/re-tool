import React, { useState, useRef, useEffect } from "react";
import {
  CloudSyncOutlined,
  MobileOutlined,
  FundViewOutlined,
  FileZipOutlined,
  CloseOutlined,
  WifiOutlined,
  RobotOutlined,
  WarningOutlined,
  PaperClipOutlined,
  SendOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import {
  Input,
  Button,
  Avatar,
  List,
  theme,
  Card,
  Upload,
  Steps,
  Tag,
  Alert,
  Tooltip,
  Modal,
  Badge,
  Progress, // ✅ 新增引用
} from "antd";
import { useLiveQuery } from "dexie-react-hooks";
import { db } from "@/db";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event"; // ✅ 新增引用

const { TextArea } = Input;

// --- 类型定义 ---
type TaskPhase =
  | "IDLE"
  | "LOCAL_PREPROCESS"
  | "CLOUD_HANDSHAKE"
  | "ON_DEMAND_ANALYSIS"
  | "NATIVE_ANALYSIS"
  | "DYNAMIC_VERIFY"
  | "COMPLETED";

interface LogEntry {
  source: "Local" | "Cloud" | "Agent" | "Device";
  msg: string;
  codeSnippet?: string;
  type?: "info" | "success" | "warning" | "error";
}

const AiWorkbenchPage: React.FC<{ sessionId: string }> = ({
  sessionId = "default",
}) => {
  const { token } = theme.useToken();
  const [chatInput, setChatInput] = useState("");
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // 进度条状态
  const [progressPercent, setProgressPercent] = useState(0);

  // Session Ref
  const currentSessionRef = useRef(sessionId);
  useEffect(() => {
    currentSessionRef.current = sessionId;
  }, [sessionId]);

  // Render-time Reset
  const [prevSessionId, setPrevSessionId] = useState(sessionId);
  const initialTaskState = {
    isTaskPanelOpen: false,
    activeApkName: "",
    currentPhase: "IDLE" as TaskPhase,
    logs: [] as LogEntry[],
    isWaitingForIda: false,
    isIdaHelpModalOpen: false,
    idaCodeInput: "",
  };
  const [taskState, setTaskState] = useState(initialTaskState);

  if (sessionId !== prevSessionId) {
    setPrevSessionId(sessionId);
    setTaskState(initialTaskState);
    setProgressPercent(0); // 重置进度条
  }

  const {
    isTaskPanelOpen,
    activeApkName,
    currentPhase,
    logs,
    isWaitingForIda,
    isIdaHelpModalOpen,
    idaCodeInput,
  } = taskState;

  const updateState = (updates: Partial<typeof initialTaskState>) => {
    setTaskState((prev) => ({ ...prev, ...updates }));
  };

  const messages =
    useLiveQuery(async () => {
      return await db.chatMessages.where({ sessionId }).toArray();
    }, [sessionId]) || [];

  // Load state
  useEffect(() => {
    const savedState = localStorage.getItem(`task_state_${sessionId}`);
    if (savedState) {
      try {
        const data = JSON.parse(savedState);
        updateState({
          activeApkName: data.activeApkName || "",
          currentPhase: data.currentPhase || "IDLE",
          logs: data.logs || [],
          isWaitingForIda: data.isWaitingForIda || false,
          isTaskPanelOpen: false,
          isIdaHelpModalOpen: false,
        });
        // 恢复时如果已经完成，进度条设为100
        if (data.currentPhase === "COMPLETED" || data.currentPhase !== "IDLE") {
          setProgressPercent(100);
        }
      } catch (e) {
        console.error("存档加载失败", e);
      }
    }
    setChatInput("");
    setPendingFile(null);
  }, [sessionId]);

  // Auto save
  useEffect(() => {
    if (currentPhase === "IDLE" && !activeApkName && logs.length === 0) return;
    const stateToSave = {
      activeApkName,
      currentPhase,
      logs,
      isWaitingForIda,
    };
    localStorage.setItem(
      `task_state_${sessionId}`,
      JSON.stringify(stateToSave)
    );
  }, [sessionId, activeApkName, currentPhase, logs, isWaitingForIda]);

  useEffect(() => {
    if (logsEndRef.current)
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [logs, isTaskPanelOpen]);

  const addLog = (
    source: LogEntry["source"],
    msg: string,
    type: LogEntry["type"] = "info",
    codeSnippet?: string
  ) => {
    setTaskState((prev) => ({
      ...prev,
      logs: [...prev.logs, { source, msg, type, codeSnippet }],
    }));
  };

  const sendAiMessage = async (content: string) => {
    await db.chatMessages.add({
      sessionId,
      role: "ai",
      content,
      time: new Date().toLocaleTimeString(),
    });
  };

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  // ==========================================
  // 🔥 任务执行流程
  // ==========================================

  const startPipeline = async (file: File) => {
    updateState({
      isTaskPanelOpen: true,
      activeApkName: file.name,
      logs: [],
      isWaitingForIda: false,
      currentPhase: "LOCAL_PREPROCESS",
    });
    setProgressPercent(0);
    addLog("Local", `开始处理文件: ${file.name}`, "info");

    let unlistenJadx: () => void = () => {};
    let unlistenConnect: () => void = () => {};

    try {
      // 1. 监听 JADX 进度
      addLog("Local", "启动 JADX 引擎...", "info");
      unlistenJadx = await listen("jadx-progress-tick", () => {
        setProgressPercent((prev) => {
          const next = prev + (99 - prev) * 0.05;
          return next > 99 ? 99 : next;
        });
      });

      // 2. 执行 JADX 反编译
      const outputDir = await invoke("jadx_decompile", {
        apkPath: file.name,
      });

      unlistenJadx();
      setProgressPercent(100);
      addLog("Local", `反编译完成，输出路径: ${outputDir}`, "success");

      // =======================================================
      // 🔥🔥🔥 核心修正：等待 Agent 连接成功的信号 🔥🔥🔥
      // =======================================================
      updateState({ currentPhase: "CLOUD_HANDSHAKE" });
      addLog("Local", "正在连接云端大脑 (等待握手)...", "info");

      // 这里创建一个 Promise，直到收到 'agent-connected-success' 事件才 resolve
      await new Promise<void>(async (resolve, reject) => {
        // 设置一个 15秒 的超时，防止永远卡死
        const timeout = setTimeout(() => {
          reject("连接云端超时 (15s)，请检查网络");
        }, 15000);

        // 监听连接成功事件
        unlistenConnect = await listen("agent-connected-success", () => {
          clearTimeout(timeout);
          addLog("Agent", "✅ 与云端建立长连接成功！", "success");
          resolve();
        });

        // 触发连接 (如果你在 useEffect 里已经连了，这里可以重复调用一次确保万一，或者依赖 useEffect 的结果)
        // 建议：为了保险，这里再次明确调用连接
        invoke("connect_agent", { sessionId }).catch(reject);
      });

      unlistenConnect(); // 清理监听器

      // 3. 只有收到成功信号后，才通知云端
      addLog("Local", "发送任务就绪指令...", "info");
      await invoke("notify_cloud_job_start", {
        sessionId: sessionId,
        filePath: outputDir,
      });
    } catch (e) {
      unlistenJadx();
      if (unlistenConnect) unlistenConnect();
      setProgressPercent(0);
      addLog("Local", `处理失败: ${e}`, "error");
    }
  };

  const handleIdaCodeSubmit = async () => {
    if (!idaCodeInput.trim()) return;
    updateState({ isIdaHelpModalOpen: false, isWaitingForIda: false });
    await db.chatMessages.add({
      sessionId,
      role: "user",
      content:
        "这是 IDA 的伪代码：\n```c\n" + idaCodeInput.slice(0, 50) + "...\n```",
      time: new Date().toLocaleTimeString(),
    });
    addLog("Local", "已发送人工辅助代码", "success");
    addLog("Agent", "接收代码成功，继续分析逻辑...", "info");
    await sleep(1500);
    startDynamicVerify();
  };

  const startDynamicVerify = async () => {
    const executionSessionId = sessionId;
    updateState({ currentPhase: "DYNAMIC_VERIFY" });
    addLog("Agent", "正在生成 Frida Hook 脚本...", "info");
    await sleep(1000);
    if (currentSessionRef.current !== executionSessionId) return;

    addLog("Cloud", "指令: EXEC_FRIDA(script_id=882)", "warning");
    addLog("Local", "连接设备: OnePlus 6", "info");
    addLog("Device", "Spawn com.example.app...", "info");

    await sleep(1000);
    addLog("Device", "💥 Process Crashed (Signal 11)", "error");
    addLog("Local", "检测到反调试，正在上报异常...", "error");

    await sleep(1500);
    if (currentSessionRef.current !== executionSessionId) return;
    addLog("Cloud", "策略调整: 启用 Anti-Anti-Frida 脚本", "warning");
    await sleep(1000);
    addLog(
      "Device",
      "✅ Hook 成功！[Frida] input='hello', output='a1b2...'",
      "success"
    );

    updateState({ currentPhase: "COMPLETED" });
    sendAiMessage("全托管分析完成！Hook 脚本已生成。");
  };

  const handleSend = async () => {
    if (!chatInput.trim() && !pendingFile) return;
    await db.chatMessages.add({
      sessionId,
      role: "user",
      content: pendingFile
        ? `[文件] ${pendingFile.name}\n${chatInput}`
        : chatInput,
      time: new Date().toLocaleTimeString(),
    });

    if (pendingFile) {
      const file = pendingFile;
      setPendingFile(null);
      setChatInput("");
      setTimeout(async () => {
        await sendAiMessage(`收到 ${file.name}。已启动分析流水线。`);
        startPipeline(file);
      }, 500);
    } else {
      setChatInput("");
    }
  };

  const handleFileSelect = (file: File) => {
    setPendingFile(file);
    return false;
  };
  const isTaskActive = currentPhase !== "IDLE" && currentPhase !== "COMPLETED";

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "#f5f7fa",
      }}
    >
      {/* Header */}
      <div
        style={{
          height: 60,
          background: "#fff",
          borderBottom: "1px solid #e8e8e8",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 24px",
          flexShrink: 0,
          zIndex: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 32,
              height: 32,
              background: token.colorPrimary,
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#fff",
              fontSize: 18,
            }}
          >
            <CloudSyncOutlined />
          </div>
          <span style={{ fontWeight: 600, fontSize: 16 }}>
            Reverse Agent Pro
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", gap: 8, marginRight: 16 }}>
            <Tooltip title="云端服务正常">
              <Tag
                icon={<WifiOutlined />}
                color="success"
                style={{ cursor: "default" }}
              >
                云端: 在线
              </Tag>
            </Tooltip>
            <Tooltip title="USB 连接正常">
              <Tag
                icon={<MobileOutlined />}
                color="processing"
                style={{ cursor: "default" }}
              >
                OnePlus 6
              </Tag>
            </Tooltip>
          </div>
          <div style={{ width: 1, height: 20, background: "#f0f0f0" }}></div>
          {activeApkName && (
            <Tooltip title={isTaskPanelOpen ? "收起面板" : "展开任务监控"}>
              <Badge dot={!isTaskPanelOpen && isTaskActive} offset={[-6, 6]}>
                <Button
                  type={isTaskPanelOpen ? "primary" : "text"}
                  shape="square"
                  size="middle"
                  icon={<FundViewOutlined style={{ fontSize: 20 }} />}
                  onClick={() =>
                    updateState({ isTaskPanelOpen: !isTaskPanelOpen })
                  }
                  style={{
                    transition: "all 0.3s",
                    color: isTaskPanelOpen ? "#fff" : token.colorTextSecondary,
                    backgroundColor: isTaskPanelOpen
                      ? token.colorPrimary
                      : "transparent",
                  }}
                />
              </Badge>
            </Tooltip>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left: Chat */}
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            borderRight: "1px solid #e8e8e8",
            background: "#fff",
            maxWidth: isTaskPanelOpen ? "60%" : "100%",
            transition: "max-width 0.3s cubic-bezier(0.2, 0, 0, 1)",
          }}
        >
          <div
            ref={scrollRef}
            style={{ flex: 1, overflowY: "auto", padding: "20px" }}
          >
            <List
              dataSource={messages}
              split={false}
              renderItem={(item) => (
                <div
                  style={{
                    display: "flex",
                    marginBottom: 20,
                    flexDirection: item.role === "user" ? "row-reverse" : "row",
                    gap: 12,
                  }}
                >
                  {" "}
                  <Avatar
                    size={36}
                    style={{
                      backgroundColor:
                        item.role === "user" ? token.colorPrimary : "#333",
                    }}
                    icon={item.role === "user" ? null : <RobotOutlined />}
                  />{" "}
                  <div
                    style={{
                      maxWidth: "85%",
                      background:
                        item.role === "user" ? token.colorPrimary : "#f7f7f7",
                      color: item.role === "user" ? "#fff" : "#333",
                      padding: "10px 16px",
                      borderRadius: 12,
                      fontSize: 14,
                      whiteSpace: "pre-wrap",
                      lineHeight: 1.6,
                    }}
                  >
                    {" "}
                    {item.content}{" "}
                  </div>{" "}
                </div>
              )}
            />
          </div>

          <div style={{ padding: "20px", borderTop: "1px solid #f0f0f0" }}>
            {isWaitingForIda && (
              <Alert
                message="任务挂起：等待人工介入"
                description="Agent 遇到了无法解决的混淆，需要您提供 IDA 伪代码以继续分析。"
                type="warning"
                showIcon
                icon={<WarningOutlined />}
                action={
                  <Button
                    size="small"
                    type="primary"
                    ghost
                    onClick={() => updateState({ isIdaHelpModalOpen: true })}
                  >
                    {" "}
                    输入代码{" "}
                  </Button>
                }
                style={{
                  marginBottom: 12,
                  border: "1px solid #ffe58f",
                  background: "#fffbe6",
                }}
              />
            )}
            {pendingFile && (
              <Alert
                message={`准备解析: ${pendingFile.name}`}
                type="info"
                showIcon
                closable
                onClose={() => setPendingFile(null)}
                style={{ marginBottom: 10 }}
              />
            )}
            <div
              style={{
                display: "flex",
                gap: 10,
                alignItems: "flex-end",
                background: "#f9f9f9",
                padding: "10px 12px",
                borderRadius: 12,
                border: "1px solid #eee",
              }}
            >
              {" "}
              <Upload showUploadList={false} beforeUpload={handleFileSelect}>
                {" "}
                <Button
                  type="text"
                  shape="circle"
                  icon={<PaperClipOutlined />}
                  style={{ marginBottom: 4 }}
                />{" "}
              </Upload>{" "}
              <TextArea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder={pendingFile ? "输入分析目标..." : "输入消息..."}
                autoSize={{ minRows: 1, maxRows: 4 }}
                bordered={false}
                style={{ padding: "4px 0", resize: "none" }}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  !e.shiftKey &&
                  (e.preventDefault(), handleSend())
                }
              />{" "}
              <Button
                type="primary"
                shape="circle"
                icon={<SendOutlined />}
                onClick={handleSend}
                style={{ marginBottom: 4 }}
              />{" "}
            </div>
          </div>
        </div>

        {/* Right: Monitor Panel */}
        <div
          style={{
            width: isTaskPanelOpen ? "40%" : 0,
            opacity: isTaskPanelOpen ? 1 : 0,
            overflow: "hidden",
            transition: "all 0.3s cubic-bezier(0.2, 0, 0, 1)",
            background: "#fcfcfc",
            borderLeft: "1px solid #e8e8e8",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid #eee",
              background: "#fff",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexShrink: 0,
            }}
          >
            {" "}
            <span
              style={{
                fontWeight: 600,
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              {" "}
              <FundViewOutlined style={{ color: token.colorPrimary }} />{" "}
              任务监控{" "}
            </span>{" "}
            <Button
              type="text"
              icon={<CloseOutlined />}
              onClick={() => updateState({ isTaskPanelOpen: false })}
            />{" "}
          </div>

          <div style={{ flex: 1, padding: "20px", overflowY: "auto" }}>
            <Card
              size="small"
              style={{
                marginBottom: 20,
                boxShadow: "0 2px 6px rgba(0,0,0,0.02)",
                border: "1px solid #f0f0f0",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div
                  style={{
                    width: 40,
                    height: 40,
                    background: "#fff7e6",
                    borderRadius: 8,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  {" "}
                  <FileZipOutlined
                    style={{ fontSize: 20, color: "#faad14" }}
                  />{" "}
                </div>
                <div style={{ flex: 1 }}>
                  <div
                    style={{
                      fontWeight: 600,
                      display: "flex",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>{activeApkName || "等待上传..."}</span>
                    {/* 🔥 进度条显示在这里 */}
                    {currentPhase === "LOCAL_PREPROCESS" && (
                      <span style={{ fontSize: 12, color: token.colorPrimary }}>
                        {Math.floor(progressPercent)}%
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: "#999" }}>
                    {" "}
                    {currentPhase === "IDLE"
                      ? "未开始"
                      : currentPhase === "COMPLETED"
                      ? "分析完成"
                      : "分析进行中..."}{" "}
                  </div>
                  {/* 🔥 进度条组件 */}
                  {currentPhase === "LOCAL_PREPROCESS" && (
                    <Progress
                      percent={progressPercent}
                      showInfo={false}
                      strokeColor={token.colorPrimary}
                      size="small"
                      status="active"
                      style={{ marginTop: 8 }}
                    />
                  )}
                </div>
              </div>
            </Card>

            <Steps
              direction="vertical"
              size="small"
              current={
                [
                  "IDLE",
                  "LOCAL_PREPROCESS",
                  "CLOUD_HANDSHAKE",
                  "ON_DEMAND_ANALYSIS",
                  "NATIVE_ANALYSIS",
                  "DYNAMIC_VERIFY",
                  "COMPLETED",
                ].indexOf(currentPhase) - 1
              }
              style={{ marginBottom: 20, padding: "0 8px" }}
              items={[
                { title: "本地预处理", description: "JADX 反编译 & 索引" },
                { title: "云端握手", description: "Metadata 同步" },
                { title: "按需分析", description: "Java / Native 语义分析" },
                { title: "动态验证", description: "Frida 注入 & 对抗" },
              ]}
            />

            <div
              style={{
                background: "#1e1e1e",
                borderRadius: 8,
                padding: "12px",
                fontFamily: "'Menlo', 'Monaco', 'Courier New', monospace",
                fontSize: 12,
                color: "#d4d4d4",
                height: 350,
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
              }}
            >
              {logs.length === 0 && (
                <div style={{ color: "#666" }}>等待任务启动...</div>
              )}
              {logs.map((log, idx) => {
                let color = "#ccc";
                if (log.source === "Local") color = "#faad14";
                if (log.source === "Cloud") color = "#1890ff";
                if (log.source === "Agent") color = "#52c41a";
                if (log.source === "Device") color = "#eb2f96";
                if (log.type === "error") color = "#ff4d4f";
                return (
                  <div
                    key={idx}
                    style={{ marginBottom: 6, wordBreak: "break-all" }}
                  >
                    {" "}
                    <div style={{ color }}>
                      {" "}
                      <span style={{ opacity: 0.7, marginRight: 8 }}>
                        {" "}
                        [{log.source}]{" "}
                      </span>{" "}
                      {log.msg}{" "}
                    </div>{" "}
                    {log.codeSnippet && (
                      <div
                        style={{
                          background: "#2d2d2d",
                          padding: "6px 8px",
                          borderRadius: 4,
                          marginTop: 4,
                          color: "#a9b7c6",
                          whiteSpace: "pre-wrap",
                          borderLeft: `2px solid ${color}`,
                          fontSize: 11,
                        }}
                      >
                        {" "}
                        {log.codeSnippet}{" "}
                      </div>
                    )}{" "}
                  </div>
                );
              })}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      </div>

      <Modal
        title={
          <span>
            {" "}
            <WarningOutlined
              style={{ color: "#faad14", marginRight: 8 }}
            />{" "}
            人工辅助请求{" "}
          </span>
        }
        open={isIdaHelpModalOpen}
        onOk={handleIdaCodeSubmit}
        onCancel={() => updateState({ isIdaHelpModalOpen: false })}
        okText="提交代码"
        cancelText="稍后"
        width={600}
        destroyOnClose
        centered
      >
        {" "}
        <Alert
          message="检测到复杂混淆 (OLLVM)"
          description="Agent 无法通过静态文本理解该 Native 函数。请协助：使用 IDA Pro 反编译目标函数，并将 F5 生成的伪代码粘贴在下方。"
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />{" "}
        <div style={{ marginBottom: 8, fontWeight: 500 }}>粘贴 IDA 伪代码:</div>{" "}
        <TextArea
          rows={10}
          value={idaCodeInput}
          onChange={(e) => updateState({ idaCodeInput: e.target.value })}
          placeholder="// int __fastcall sub_1234(int a1) { ... }"
          style={{
            fontFamily: "monospace",
            fontSize: 12,
            background: "#f5f5f5",
          }}
        />{" "}
      </Modal>
    </div>
  );
};

export default AiWorkbenchPage;
