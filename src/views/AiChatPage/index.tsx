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
  StopOutlined,
  CaretRightOutlined,
  CheckCircleFilled,
  SyncOutlined,
  CloseCircleFilled,
  ClockCircleOutlined,
  BulbOutlined,
} from "@ant-design/icons";
import {
  Input,
  Button,
  Avatar,
  List,
  theme,
  Card,
  Steps,
  Tag,
  Alert,
  Tooltip,
  Modal,
  Badge,
  Progress,
  message,
  Collapse,
  Space,
} from "antd";
import { useLiveQuery } from "dexie-react-hooks";
import { db, ChatMessage, TaskStep } from "@/db"; // 引入新的类型定义
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import ReactMarkdown from "react-markdown"; // 建议引入 markdown 渲染库，如未安装可暂时用 div

const { TextArea } = Input;

interface LogEntry {
  source: "Local" | "Cloud" | "Agent" | "Device";
  msg: string;
  codeSnippet?: string;
  type?: "info" | "success" | "warning" | "error";
}

interface AppFile {
  name: string;
  path: string;
}

// ============================================================================
// 🧩 子组件：消息气泡 (包含 步骤条、思考过程、正文)
// ============================================================================
const MessageBubble: React.FC<{ item: ChatMessage; primaryColor: string }> = ({
  item,
  primaryColor,
}) => {
  const isUser = item.role === "user";

  return (
    <div
      style={{
        display: "flex",
        marginBottom: 24,
        flexDirection: isUser ? "row-reverse" : "row",
        gap: 12,
        alignItems: "flex-start",
      }}
    >
      <Avatar
        size={36}
        style={{
          backgroundColor: isUser ? primaryColor : "#333",
          marginTop: 4,
        }}
        icon={isUser ? null : <RobotOutlined />}
      >
        {isUser && "Me"}
      </Avatar>

      <div
        style={{
          maxWidth: "85%",
          minWidth: "30%",
        }}
      >
        {/* 1. 任务执行计划 (仅 AI 且有步骤时显示) */}
        {!isUser && item.steps && item.steps.length > 0 && (
          <Card
            size="small"
            style={{
              marginBottom: 8,
              borderColor: "#e8e8e8",
              background: "#fafafa",
            }}
            styles={{ body: { padding: "12px 16px" } }}
          >
            <div style={{ fontSize: 12, color: "#999", marginBottom: 8 }}>
              ⚡ 执行计划
            </div>
            <Steps
              direction="vertical"
              size="small"
              current={item.steps.findIndex((s) => s.status === "process")}
              items={item.steps.map((step) => ({
                title: step.title,
                description: step.description,
                status: step.status as any,
                icon:
                  step.status === "process" ? (
                    <LoadingOutlined />
                  ) : step.status === "finish" ? (
                    <CheckCircleFilled />
                  ) : step.status === "error" ? (
                    <CloseCircleFilled />
                  ) : (
                    <ClockCircleOutlined />
                  ),
              }))}
            />
          </Card>
        )}

        {/* 2. 深度思考过程 (类似 DeepSeek 折叠面板) */}
        {!isUser && item.reasoning && (
          <Collapse
            ghost
            size="small"
            items={[
              {
                key: "1",
                label: (
                  <span style={{ color: "#888", fontSize: 12 }}>
                    <BulbOutlined style={{ marginRight: 4 }} /> 深度思考过程
                  </span>
                ),
                children: (
                  <div
                    style={{
                      fontSize: 12,
                      color: "#666",
                      borderLeft: "2px solid #ddd",
                      paddingLeft: 8,
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {item.reasoning}
                  </div>
                ),
              },
            ]}
            expandIcon={({ isActive }) => (
              <CaretRightOutlined
                rotate={isActive ? 90 : 0}
                style={{ fontSize: 10, color: "#999" }}
              />
            )}
            style={{ marginBottom: 8 }}
          />
        )}

        {/* 3. 正文内容 */}
        <div
          style={{
            background: isUser ? primaryColor : "#f4f6f8",
            color: isUser ? "#fff" : "#333",
            padding: "12px 16px",
            borderRadius: 12,
            borderTopLeftRadius: isUser ? 12 : 2,
            borderTopRightRadius: isUser ? 2 : 12,
            fontSize: 14,
            lineHeight: 1.6,
            boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
          }}
        >
          <div style={{ whiteSpace: "pre-wrap" }}>{item.content}</div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 🚀 主页面组件
// ============================================================================
const AiWorkbenchPage: React.FC<{ sessionId: string }> = ({
  sessionId = "default",
}) => {
  const { token } = theme.useToken();
  const [chatInput, setChatInput] = useState("");
  const [pendingFile, setPendingFile] = useState<AppFile | null>(null);

  // 状态管理
  const [isTaskPanelOpen, setIsTaskPanelOpen] = useState(false);
  const [activeApkName, setActiveApkName] = useState(""); // 当前上下文的文件名
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false); // 任务是否运行中

  const scrollRef = useRef<HTMLDivElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // 🔥 核心 Refs：记录当前正在流式接收的数据
  const currentStreamingMsgId = useRef<any>(null);
  const streamContentBuffer = useRef<string>("");
  const streamReasoningBuffer = useRef<string>("");
  const currentTaskSteps = useRef<TaskStep[]>([]); // 暂存当前的步骤，用于存入DB

  // Session Ref
  const currentSessionRef = useRef(sessionId);
  useEffect(() => {
    currentSessionRef.current = sessionId;
  }, [sessionId]);

  const messages =
    useLiveQuery(
      () => db.chatMessages.where({ sessionId }).toArray(),
      [sessionId]
    ) || [];

  // 自动滚动
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [
    messages.length,
    messages[messages.length - 1]?.content,
    messages[messages.length - 1]?.reasoning,
    messages[messages.length - 1]?.steps,
  ]);

  // 日志滚动
  useEffect(() => {
    if (logsEndRef.current)
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = (
    source: LogEntry["source"],
    msg: string,
    type: LogEntry["type"] = "info"
  ) => {
    setLogs((prev) => [...prev, { source, msg, type }]);
  };

  // ========================================================
  // 🎧 全局监听器 (流式响应、思考、任务计划)
  // ========================================================
  useEffect(() => {
    let unlistenChunk: () => void;
    let unlistenReasoning: () => void;
    let unlistenEnd: () => void;
    let unlistenPlan: () => void;

    const setupListeners = async () => {
      // 1. 监听内容块 (Content)
      unlistenChunk = await listen("ai_stream_chunk", (event: any) => {
        const chunk = event.payload;
        if (!currentStreamingMsgId.current) return;

        streamContentBuffer.current += chunk;

        // 更新数据库 (UI 会自动响应)
        db.chatMessages.update(currentStreamingMsgId.current, {
          content: streamContentBuffer.current,
        });
      });

      // 2. 监听思考块 (Reasoning - 假设后端会发这个事件，即便没发也不影响)
      unlistenReasoning = await listen("ai_reasoning_chunk", (event: any) => {
        const chunk = event.payload;
        if (!currentStreamingMsgId.current) return;

        streamReasoningBuffer.current += chunk;

        db.chatMessages.update(currentStreamingMsgId.current, {
          reasoning: streamReasoningBuffer.current,
        });
      });

      // 3. 监听任务计划更新 (Task Plan)
      unlistenPlan = await listen("agent_task_update", (event: any) => {
        const newSteps = event.payload;
        if (!currentStreamingMsgId.current) return;

        if (Array.isArray(newSteps)) {
          currentTaskSteps.current = newSteps;
          // 将步骤直接存入当前消息体中
          db.chatMessages.update(currentStreamingMsgId.current, {
            steps: newSteps,
          });
        }
      });

      // 4. 监听结束信号
      unlistenEnd = await listen("ai_stream_end", () => {
        if (currentStreamingMsgId.current) {
          // 最终确保一致性
          db.chatMessages.update(currentStreamingMsgId.current, {
            content: streamContentBuffer.current,
            reasoning: streamReasoningBuffer.current,
            steps: currentTaskSteps.current,
          });

          addLog("Agent", "回复生成完毕。", "success");
          setIsRunning(false);
        }
        // 重置 Ref
        currentStreamingMsgId.current = null;
        streamContentBuffer.current = "";
        streamReasoningBuffer.current = "";
        currentTaskSteps.current = [];
      });
    };

    setupListeners();

    return () => {
      if (unlistenChunk) unlistenChunk();
      if (unlistenReasoning) unlistenReasoning();
      if (unlistenEnd) unlistenEnd();
      if (unlistenPlan) unlistenPlan();
    };
  }, []);

  // ==========================================
  // 🔥 任务流程 (JADX -> Connect -> AI)
  // ==========================================
  const startPipeline = async (file: AppFile, userInstruction: string = "") => {
    setIsRunning(true);
    setLogs([]); // 清空日志
    setActiveApkName(file.name); // 设置当前上下文

    // 初始化步骤 (本地)
    currentTaskSteps.current = [
      {
        id: "local-1",
        title: "JADX 预处理",
        description: "正在反编译 APK...",
        status: "process",
      },
    ];

    addLog("Local", `开始处理文件: ${file.name}`, "info");

    let unlistenJadx: () => void = () => {};
    let unlistenConnect: () => void = () => {};

    try {
      // 1. 发送占位消息 (包含初始步骤)
      const aiMsgId = await db.chatMessages.add({
        sessionId,
        role: "ai",
        content: "",
        reasoning: "",
        steps: currentTaskSteps.current,
        time: new Date().toLocaleTimeString(),
      });

      // 绑定全局流指针
      currentStreamingMsgId.current = aiMsgId;
      streamContentBuffer.current = "";
      streamReasoningBuffer.current = "";

      // 2. 执行 JADX
      addLog("Local", "启动 JADX 引擎...", "info");
      const workspacePath = localStorage.getItem("retool_workspace_path");

      // 监听 JADX 进度 (可选：你可以把进度更新到 steps description 里)
      unlistenJadx = await listen("jadx-progress-tick", () => {});

      const outputDir = await invoke("jadx_decompile", {
        apkPath: file.path,
        outputDir: workspacePath || null,
      });

      unlistenJadx();
      addLog("Local", `反编译完成`, "success");

      // 更新步骤：JADX 完成，云端开始
      currentTaskSteps.current = [
        {
          id: "local-1",
          title: "JADX 预处理",
          description: "反编译完成",
          status: "finish",
        },
        {
          id: "cloud-1",
          title: "云端大脑",
          description: "正在连接并规划任务...",
          status: "process",
        },
      ];
      db.chatMessages.update(aiMsgId, { steps: currentTaskSteps.current });

      // 3. 连接云端
      addLog("Local", "正在连接云端大脑...", "info");
      await new Promise<void>(async (resolve, reject) => {
        const timeout = setTimeout(() => {
          reject("连接云端超时 (15s)，请检查网络");
        }, 15000);
        unlistenConnect = await listen("agent-connected-success", () => {
          clearTimeout(timeout);
          addLog("Agent", "✅ 云端连接成功！", "success");
          resolve();
        });
        invoke("connect_agent", { sessionId }).catch(reject);
      });
      unlistenConnect();

      // 4. 通知云端开始任务
      addLog("Local", `发送指令: ${userInstruction || "默认分析"}`, "info");
      await invoke("notify_cloud_job_start", {
        sessionId: sessionId,
        filePath: outputDir,
        instruction: userInstruction,
      });
    } catch (e) {
      unlistenJadx();
      if (unlistenConnect) unlistenConnect();
      setIsRunning(false);
      addLog("Local", `处理失败: ${e}`, "error");

      // 更新错误状态到消息
      if (currentStreamingMsgId.current) {
        const failedSteps = [...currentTaskSteps.current];
        if (failedSteps.length > 0)
          failedSteps[failedSteps.length - 1].status = "error";
        db.chatMessages.update(currentStreamingMsgId.current, {
          content: streamContentBuffer.current + `\n\n❌ **任务中断**: ${e}`,
          steps: failedSteps,
        });
        currentStreamingMsgId.current = null;
      }
    }
  };

  // ==========================================
  // 🔥 发送消息 / 停止生成
  // ==========================================
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

    const currentInput = chatInput;
    setChatInput("");

    if (pendingFile) {
      const file = pendingFile;
      setPendingFile(null);
      setTimeout(() => startPipeline(file, currentInput), 100);
    } else {
      if (!activeApkName) {
        message.warning("请先上传一个 APK 文件再开始对话");
        return;
      }

      // 纯对话模式：也需要初始化流状态
      setIsRunning(true);
      const aiMsgId = await db.chatMessages.add({
        sessionId,
        role: "ai",
        content: "",
        reasoning: "", // 预留
        time: new Date().toLocaleTimeString(),
      });
      currentStreamingMsgId.current = aiMsgId;
      streamContentBuffer.current = "";
      streamReasoningBuffer.current = "";

      try {
        await invoke("send_chat_message", {
          sessionId: sessionId,
          message: currentInput,
        });
      } catch (e) {
        message.error("发送失败: " + e);
        setIsRunning(false);
      }
    }
  };

  const handleStop = async () => {
    // 这里的停止目前只是前端断开监听，并重置 UI 状态
    // 理想情况下，应该发一个 cancel_task 指令给后端
    // await invoke("cancel_task", { sessionId });

    message.info("已停止接收");
    setIsRunning(false);
    currentStreamingMsgId.current = null;
    addLog("Local", "用户手动停止生成", "warning");
  };

  const handleSelectFile = async () => {
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "APK Files", extensions: ["apk"] }],
      });
      if (selected && typeof selected === "string") {
        const name = selected.split(/[\\/]/).pop() || "unknown.apk";
        setPendingFile({ name: name, path: selected });
      }
    } catch (err) {
      console.error(err);
    }
  };

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
          <Tooltip title={isTaskPanelOpen ? "收起日志" : "查看系统日志"}>
            <Button
              type={isTaskPanelOpen ? "primary" : "text"}
              icon={<FundViewOutlined />}
              onClick={() => setIsTaskPanelOpen(!isTaskPanelOpen)}
            />
          </Tooltip>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left: Chat Area */}
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            borderRight: "1px solid #e8e8e8",
            background: "#fff",
            maxWidth: isTaskPanelOpen ? "65%" : "100%",
            transition: "all 0.3s",
          }}
        >
          {/* Chat List */}
          <div
            ref={scrollRef}
            style={{ flex: 1, overflowY: "auto", padding: "20px" }}
          >
            <List
              dataSource={messages}
              split={false}
              renderItem={(item) => (
                <MessageBubble item={item} primaryColor={token.colorPrimary} />
              )}
            />
          </div>

          {/* Input Area */}
          <div style={{ padding: "20px", borderTop: "1px solid #f0f0f0" }}>
            {/* Context Tag (上方胶囊) */}
            {(activeApkName || pendingFile) && (
              <div style={{ marginBottom: 8, display: "flex", gap: 8 }}>
                {activeApkName && !pendingFile && (
                  <Tag
                    color="blue"
                    closeIcon
                    onClose={() => setActiveApkName("")}
                  >
                    📎 上下文: {activeApkName}
                  </Tag>
                )}
                {pendingFile && (
                  <Tag
                    color="orange"
                    closeIcon
                    onClose={() => setPendingFile(null)}
                  >
                    📂 待处理: {pendingFile.name}
                  </Tag>
                )}
              </div>
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
              <Tooltip title="上传新 APK">
                <Button
                  type="text"
                  shape="circle"
                  icon={<PaperClipOutlined />}
                  onClick={handleSelectFile}
                  style={{ marginBottom: 4 }}
                />
              </Tooltip>

              <TextArea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder={
                  activeApkName
                    ? `向 ${activeApkName} 提问...`
                    : "输入消息或上传 APK..."
                }
                autoSize={{ minRows: 1, maxRows: 4 }}
                bordered={false}
                style={{ padding: "4px 0", resize: "none" }}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  !e.shiftKey &&
                  (e.preventDefault(), handleSend())
                }
                disabled={isRunning}
              />

              {/* 动态切换 发送/停止 按钮 */}
              {isRunning ? (
                <Button
                  danger
                  type="primary"
                  shape="circle"
                  icon={<StopOutlined />}
                  onClick={handleStop}
                  style={{ marginBottom: 4 }}
                />
              ) : (
                <Button
                  type="primary"
                  shape="circle"
                  icon={<SendOutlined />}
                  onClick={handleSend}
                  style={{ marginBottom: 4 }}
                />
              )}
            </div>
          </div>
        </div>

        {/* Right: System Logs (简化版) */}
        <div
          style={{
            width: isTaskPanelOpen ? "35%" : 0,
            opacity: isTaskPanelOpen ? 1 : 0,
            overflow: "hidden",
            transition: "all 0.3s",
            background: "#1e1e1e",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              padding: "12px 16px",
              borderBottom: "1px solid #333",
              color: "#fff",
              fontWeight: 600,
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>系统日志</span>
            <CloseOutlined
              style={{ cursor: "pointer" }}
              onClick={() => setIsTaskPanelOpen(false)}
            />
          </div>
          <div
            style={{
              flex: 1,
              padding: "12px",
              overflowY: "auto",
              fontFamily: "monospace",
              fontSize: 12,
              color: "#a9b7c6",
            }}
          >
            {logs.map((log, idx) => (
              <div
                key={idx}
                style={{ marginBottom: 6, wordBreak: "break-all" }}
              >
                <span
                  style={{
                    color:
                      log.source === "Local"
                        ? "#faad14"
                        : log.source === "Agent"
                        ? "#52c41a"
                        : "#1890ff",
                    marginRight: 8,
                  }}
                >
                  [{log.source}]
                </span>
                <span>{log.msg}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default AiWorkbenchPage;
