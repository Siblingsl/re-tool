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
  CloseCircleFilled,
  ClockCircleOutlined,
  BulbOutlined,
  SettingOutlined,
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
  Select,
  Form,
  InputNumber,
  Dropdown,  // 🔥 新增
  Menu,      // 🔥 新增
} from "antd";
import { useLiveQuery } from "dexie-react-hooks";
import { db, ChatMessage, TaskStep, RecentProject } from "@/db"; // 🔥 添加 RecentProject
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { NetworkRequest } from "@/types";

const { TextArea } = Input;

interface LogEntry {
  source: "Local" | "Cloud" | "Agent" | "Device";
  msg: string;
  codeSnippet?: string;
  type?: "info" | "success" | "warning" | "error";
  isKeyResult?: boolean; // 🔥 标记是否为关键结果日志
}

// 🔥 判断日志是否为关键结果的函数
// ❗ 更严格的匹配规则，只有真正的签名/加密结果才标记为关键
const isKeyResultLog = (msg: string): boolean => {
  // 🔑 高优先级：真正的签名/加密结果
  const highPriorityPatterns = [
    /\[🔑签名结果\].*Result:/i,   // 必须有 Result 才算
    /\[🔑匹配成功\]/,              // 签名匹配成功
    /\[Digest\].*Result:\s*[a-f0-9]{16,}/i,  // MD5/SHA 结果
    /\[HMAC\].*Result:\s*[a-f0-9]{16,}/i,    // HMAC 结果
    /\[Cipher\].*(ENCRYPT|DECRYPT).*Result/i, // 加密结果
    /\[🔑Sign字段\].*sign.*=/i,   // HTTP 签名字段
  ];
  return highPriorityPatterns.some(pattern => pattern.test(msg));
};

// 🔥 签名捕获数据结构
interface SignCapture {
  id: string;
  timestamp: number;
  type: "HMAC" | "MD5" | "SHA1" | "HTTP";
  algo?: string;
  result: string;          // 签名结果
  input?: string;          // 输入参数
  key?: string;            // 密钥
  sourceClass?: string;    // 来源类
  url?: string;            // HTTP URL
  matched?: boolean;       // 是否匹配成功
}

// 🔥 从日志解析签名信息
const parseSignatureFromLog = (msg: string): SignCapture | null => {
  // 解析 HMAC/MD5 结果
  if (msg.includes("[🔑签名结果]")) {
    const resultMatch = msg.match(/Result:\s*([a-f0-9]+)/i);
    const algoMatch = msg.match(/HMAC-(\w+)|(MD5|SHA1|SHA-1)/i);
    const sourceMatch = msg.match(/来源类:\s*([\w\.]+)/i);
    const inputMatch = msg.match(/输入参数:\s*(.+)/i);
    const keyMatch = msg.match(/密钥:\s*([a-f0-9]+)/i);

    if (resultMatch) {
      return {
        id: `sig-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: Date.now(),
        type: algoMatch?.[1]?.includes("SHA") ? "HMAC" : "MD5",
        algo: algoMatch?.[1] || algoMatch?.[2] || "Unknown",
        result: resultMatch[1],
        sourceClass: sourceMatch?.[1],
        input: inputMatch?.[1],
        key: keyMatch?.[1],
      };
    }
  }

  // 解析 HTTP sign 字段
  if (msg.includes("[🔑Sign字段]")) {
    const signMatch = msg.match(/sign值:\s*([^\s]+)/i);
    const urlMatch = msg.match(/URL:\s*(.+)/i);

    if (signMatch) {
      return {
        id: `http-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: Date.now(),
        type: "HTTP",
        result: signMatch[1],
        url: urlMatch?.[1],
      };
    }
  }

  return null;
};

interface AppFile {
  name: string;
  path: string;
}

interface ModelConfig {
  provider?: string;
  apiKey?: string;
  baseURL?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
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
          display: "flex",
          flexDirection: "column",
          alignItems: isUser ? "flex-end" : "flex-start",
        }}
      >
        {/* 1. 任务执行计划 (仅 AI 且有步骤时显示) */}
        {!isUser && item.steps && item.steps.length > 0 && (
          <div style={{ width: "100%", marginBottom: 8 }}>
            <Card
              size="small"
              style={{
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
          </div>
        )}

        {/* 2. 深度思考过程 (类似 DeepSeek 折叠面板) */}
        {!isUser && item.reasoning && (
          <div style={{ width: "100%", marginBottom: 8 }}>
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
                        fontFamily: "monospace",
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
            />
          </div>
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
            wordBreak: "break-word",
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
  const [activeApkName, setActiveApkName] = useState("");
  // const [logs, setLogs] = useState<LogEntry[]>([]); // ❌ 移除本地状态
  const [logFilter, setLogFilter] = useState<"all" | "key">("all");
  const [signCaptures, setSignCaptures] = useState<SignCapture[]>([]);
  // const [httpRequests, setHttpRequests] = useState<NetworkRequest[]>([]); // ❌ 移除本地状态
  const [isRunning, setIsRunning] = useState(false);
  const [isMitmRunning, setIsMitmRunning] = useState(false); // 🔥 抓包服务状态

  // 🔥 新增：项目选择模态框状态
  const [isProjectModalOpen, setIsProjectModalOpen] = useState(false);
  const [pendingProjectPath, setPendingProjectPath] = useState<string | null>(null); // 🔥 新增：已选择的项目路径

  // 模型配置相关状态
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [modelConfig, setModelConfig] = useState<ModelConfig>({
    provider: "openai",
    apiKey: "",
    baseURL: "",
    model: "",
    temperature: 0.1,
    maxTokens: 1024
  });
  const [configForm] = Form.useForm();

  // 加载配置
  useEffect(() => {
    const saved = localStorage.getItem("retool_model_config");
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setModelConfig(parsed);
        configForm.setFieldsValue(parsed);
      } catch (e) {
        console.error("Failed to load model config", e);
      }
    }
  }, []);

  const handleSaveConfig = () => {
    configForm.validateFields().then((values) => {
      const newConfig = { ...modelConfig, ...values };
      setModelConfig(newConfig);
      localStorage.setItem("retool_model_config", JSON.stringify(newConfig));
      setIsSettingsOpen(false);
      message.success("模型配置已保存");
    });
  };

  const scrollRef = useRef<HTMLDivElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // 🔥 核心 Refs：记录当前正在流式接收的数据
  const currentStreamingMsgId = useRef<any>(null);
  const streamContentBuffer = useRef<string>("");
  const streamReasoningBuffer = useRef<string>("");
  const currentTaskSteps = useRef<TaskStep[]>([]); // 暂存当前的步骤，用于存入DB
  const sessionTaskStepsRef = useRef<TaskStep[]>([]);

  // Session Ref
  const currentSessionRef = useRef(sessionId);
  useEffect(() => {
    // Session 切换时，重置当前会话的状态
    if (currentSessionRef.current !== sessionId) {
      // setHttpRequests([]); // 由 useLiveQuery 自动处理
      setSignCaptures([]);
      setActiveApkName("");
      setPendingFile(null);
      setIsRunning(false);
      // 注意：mitmproxy 服务是全局的，切换会话不一定要停止它，
      // 但 UI 上显示的抓包列表应该清空 (已通过 setHttpRequests([]) 实现)
    }
    currentSessionRef.current = sessionId;
  }, [sessionId]);

  const messages =
    useLiveQuery(
      () => db.chatMessages.where({ sessionId }).toArray(),
      [sessionId]
    ) || [];

  // 🔥 实时查询日志
  const logs = useLiveQuery(
    () => db.sessionLogs.where({ sessionId }).toArray(),
    [sessionId]
  ) || [];

  // 🔥 实时查询网络抓包
  const httpRequests = useLiveQuery(
    () => db.networkCaptures.where({ sessionId }).toArray(),
    [sessionId]
  ) || [];

  // 🔥 新增：实时查询历史项目（按最后使用时间倒序）
  const recentProjects = useLiveQuery(
    () => db.recentProjects.orderBy('lastUsed').reverse().limit(10).toArray(),
    []
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

  // 🔥 组件卸载时自动停止 mitmproxy 服务
  useEffect(() => {
    return () => {
      // 组件卸载时停止抓包服务
      invoke("stop_mitmproxy").catch(() => { });
    };
  }, []);

  // 🔥 去重：记录最近添加的日志 (用于防止重复)
  const recentLogsRef = useRef<Map<string, number>>(new Map());

  // 🔥 日志条数限制
  const MAX_LOGS_PER_SESSION = 1000;

  const addLog = async (
    source: LogEntry["source"],
    msg: string,
    type: LogEntry["type"] = "info"
  ) => {
    // 🔥 优化去重逻辑：只对完全相同的源+消息在 500ms 内去重 (缩短时间窗口)
    const dedupKey = `${source}:${msg}`;
    const now = Date.now();
    const lastTime = recentLogsRef.current.get(dedupKey);

    // 🔥 核心修复：500ms 内的相同日志才去重，避免丢失有价值的重复数据
    if (lastTime && now - lastTime < 500) {
      return; // 跳过重复日志
    }
    recentLogsRef.current.set(dedupKey, now);

    // 清理过期的去重记录 (保持 Map 不会无限增长)
    if (recentLogsRef.current.size > 200) {
      const cutoff = now - 3000;
      for (const [key, time] of recentLogsRef.current.entries()) {
        if (time < cutoff) recentLogsRef.current.delete(key);
      }
    }

    const isKey = isKeyResultLog(msg); // 🔥 自动识别关键日志

    // 🔥 写入数据库持久化
    const activeSessionId = currentSessionRef.current;

    await db.sessionLogs.add({
      sessionId: activeSessionId,
      source,
      msg,
      type,
      isKeyResult: isKey,
      time: Date.now()
    });

    // 🔥 日志条数限制：超过上限时删除最早的日志
    const count = await db.sessionLogs.where({ sessionId: activeSessionId }).count();
    if (count > MAX_LOGS_PER_SESSION) {
      const oldest = await db.sessionLogs
        .where({ sessionId: activeSessionId })
        .sortBy('time');
      const toDelete = oldest.slice(0, count - MAX_LOGS_PER_SESSION);
      await db.sessionLogs.bulkDelete(toDelete.map(l => l.id!));
    }

    // 🔥 尝试解析签名信息
    const signInfo = parseSignatureFromLog(msg);
    if (signInfo) {
      setSignCaptures((prev) => {
        // 避免重复添加相同结果
        const exists = prev.some(s => s.result === signInfo.result);
        if (exists) return prev;
        return [...prev, signInfo].slice(-20); // 最多保留 20 条
      });
    }
  };


  // ========================================================
  // 🎧 全局监听器 (流式响应、思考、任务计划)
  // 🔥🔥🔥 核心修复：防止 React StrictMode 导致的双重监听 (口吃问题) 🔥🔥🔥
  // ========================================================
  useEffect(() => {
    // 收集所有的 unlisten Promise
    const unlistenPromises: Promise<UnlistenFn>[] = [];

    const setupListeners = async () => {
      // 1. 监听内容块 (Content)
      unlistenPromises.push(
        listen("ai_stream_chunk", (event: any) => {
          const chunk = event.payload;
          if (!currentStreamingMsgId.current) return;

          streamContentBuffer.current += chunk;

          // 更新数据库 (UI 会自动响应)
          db.chatMessages.update(currentStreamingMsgId.current, {
            content: streamContentBuffer.current,
          });
        })
      );

      // 2. 监听思考块 (Reasoning)
      unlistenPromises.push(
        listen("ai_reasoning_chunk", (event: any) => {
          const chunk = event.payload;
          if (!currentStreamingMsgId.current) return;

          streamReasoningBuffer.current += chunk;

          db.chatMessages.update(currentStreamingMsgId.current, {
            reasoning: streamReasoningBuffer.current,
          });
        })
      );

      // 3. 监听任务计划更新 (Task Plan)
      listen("agent_task_update", (event: any) => {
        const newSteps = event.payload;
        if (!Array.isArray(newSteps)) return;

        // ✅ 永远更新会话级任务
        sessionTaskStepsRef.current = newSteps;

        // 1️⃣ 如果当前有正在流的消息，绑定到它
        if (currentStreamingMsgId.current) {
          currentTaskSteps.current = newSteps;
          db.chatMessages.update(currentStreamingMsgId.current, {
            steps: newSteps,
          });
          return;
        }

        // 2️⃣ 如果没有流式消息（比如已经分析完），
        //    绑定到“最近一条 AI 消息”
        db.chatMessages
          .where({ sessionId, role: "ai" })
          .last()
          .then((lastMsg) => {
            if (lastMsg?.id) {
              db.chatMessages.update(lastMsg.id, {
                steps: newSteps,
              });
            }
          });
      });

      // 4. 监听结束信号
      unlistenPromises.push(
        listen("ai_stream_end", () => {
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
        })
      );

      // 5. 监听 Frida 实时日志
      // 这是 Rust 传来的真机运行日志
      unlistenPromises.push(
        listen("frida-log", (event: any) => {
          const msg = event.payload as string;
          // 将日志添加到右侧面板，来源标记为 "Device"
          addLog("Device", msg, msg.includes("Error") ? "error" : "success");
        })
      );

      // 🔥 7. 监听云端日志 (cloud-log)
      unlistenPromises.push(
        listen("cloud-log", (event: any) => {
          const payload = event.payload as { source: string; msg: string; type: string };
          addLog(
            (payload.source as LogEntry["source"]) || "Cloud",
            payload.msg,
            (payload.type as LogEntry["type"]) || "info"
          );
        })
      );

      // 🔥 8. 监听 Frida 就绪信号
      unlistenPromises.push(
        listen("frida-ready", () => {
          addLog("Device", "✅ Frida 注入就绪，开始监控...", "success");
        })
      );


      // 🔥 6. 监听 HTTP 网络抓包 (mitmproxy)
      unlistenPromises.push(
        listen("mitm-traffic", (event: any) => {
          const rawMsg = (event.payload as string).trim();
          if (!rawMsg.startsWith("{")) return;

          try {
            const traffic = JSON.parse(rawMsg);

            // Simple ID generator if uuidv4 is missing
            const genId = () => Math.random().toString(36).substring(2) + Date.now().toString(36);

            const newReq = {
              id: traffic.id || genId(),
              sessionId: currentSessionRef.current, // Fix: Use ref
              method: traffic.method,
              url: traffic.url,
              host: traffic.host,
              path: traffic.path,
              status: traffic.status,
              duration: traffic.duration,
              requestHeaders: traffic.request_headers,
              responseHeaders: traffic.response_headers,
              requestBody: traffic.request_body,
              responseBody: traffic.response_body,
              timestamp: Date.now(),
            };

            db.networkCaptures.put(newReq).catch(console.error);
          } catch (e) {
            console.error("Failed to parse mitm-traffic:", e);
          }
        })
      );
    };

    setupListeners();

    // ✅ 正确的清理逻辑：等待 Promise 解析后调用 unlisten 函数
    return () => {
      unlistenPromises.forEach((p) => {
        p.then((unlisten) => unlisten());
      });
    };
  }, []);

  // ==========================================
  // 🔥 任务流程 (JADX -> Connect -> AI)
  // ==========================================
  const startPipeline = async (
    file: AppFile,
    userInstruction: string = "",
    existingProjectPath?: string  // 🔥 新增：已有项目路径，传入则跳过 JADX
  ) => {
    setIsRunning(true);
    // setLogs([]); // ❌ 不要清空日志，用户希望保留历史
    // setHttpRequests([]); // 🔥 不需要清空，由 DB 管理
    setActiveApkName(file.name); // 设置当前上下文

    // 🔥 自动启动 mitmproxy 抓包服务
    try {
      addLog("Local", "正在启动抓包服务...", "info");
      await invoke("start_mitmproxy", { port: 10086 });
      addLog("Local", "✅ 抓包服务已启动 (端口:10086)", "success");
      setIsMitmRunning(true); // 🔥 更新抓包服务状态
    } catch (e: any) {
      // 如果是端口已占用 (服务已启动)，忽略错误继续执行
      if (!e.toString().includes("already") && !e.toString().includes("占用")) {
        addLog("Local", `⚠️ 抓包服务启动失败: ${e}`, "warning");
      } else {
        addLog("Local", "✅ 抓包服务已在运行中", "success");
        setIsMitmRunning(true); // 🔥 更新抓包服务状态
      }
    }

    // 初始化步骤 (本地)
    currentTaskSteps.current = [
      {
        id: "local-1",
        title: existingProjectPath ? "加载已有项目" : "JADX 预处理",
        description: existingProjectPath ? "跳过解包，直接使用已有项目..." : "正在反编译 APK...",
        status: "process",
      },
    ];

    // 添加 AI 消息占位
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

    let outputDir: string;
    let unlistenJadx: UnlistenFn | null = null;
    let unlistenConnect: UnlistenFn | null = null;

    try {
      // 🔥 根据是否有已有项目路径决定是否执行 JADX

      if (existingProjectPath) {
        // 使用已有项目，跳过 JADX
        addLog("Local", `📂 使用已有项目: ${existingProjectPath}`, "success");
        outputDir = existingProjectPath;

        // 更新项目最后使用时间
        await db.recentProjects.where({ path: existingProjectPath }).modify({ lastUsed: Date.now() });
      } else {
        // 2. 执行 JADX
        addLog("Local", "启动 JADX 引擎...", "info");
        const workspacePath = localStorage.getItem("retool_workspace_path");

        // 监听 JADX 进度
        unlistenJadx = await listen("jadx-progress-tick", () => { });

        outputDir = (await invoke("jadx_decompile", {
          apkPath: file.path,
          outputDir: workspacePath || null,
        })) as string;

        if (unlistenJadx) unlistenJadx();
        addLog("Local", `反编译完成`, "success");

        // 🔥 保存新项目到数据库
        const existingProject = await db.recentProjects.where({ path: outputDir }).first();
        if (!existingProject) {
          await db.recentProjects.add({
            name: file.name,
            path: outputDir,
            apkPath: file.path,
            lastUsed: Date.now(),
            createdAt: Date.now(),
          });
          addLog("Local", "📌 项目已保存，下次可直接选择", "info");
        }
      }


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
      unlistenConnect = await listen("agent-connected-success", () => {
        // 事件触发时会调用 resolve
      });
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject("连接云端超时 (15s)，请检查网络");
        }, 15000);

        // 重新注册一个监听器来处理成功回调
        listen("agent-connected-success", () => {
          clearTimeout(timeout);
          addLog("Agent", "✅ 云端连接成功！", "success");
          resolve();
        });
        invoke("connect_agent", { sessionId }).catch(reject);
      });
      if (unlistenConnect) unlistenConnect();

      // 🔍 补充：获取文件树和 Manifest (Handshake Phase)
      addLog("Local", "🔍 正在构建上下文 (Manifest + FileTree)...", "info");

      let fileTree: any = [];
      let manifestContent = "";

      try {
        // 1. 获取文件树
        fileTree = await invoke("scan_local_dir", { path: outputDir });

        // 2. 尝试读取 AndroidManifest.xml
        // 改进：如果根目录没有，尝试在 fileTree 里找
        const separator = outputDir.includes("\\") ? "\\" : "/";
        let manifestPath = `${outputDir}${separator}AndroidManifest.xml`;

        try {
          manifestContent = await invoke("read_local_file", { path: manifestPath }) as string;
          addLog("Local", "📦 已提取 AndroidManifest.xml", "success");
        } catch (e) {
          // 🔥 尝试深度查找
          addLog("Local", "⚠️ 根目录未找到 Manifest，正在深度搜索...", "warning");

          const findManifest = (nodes: any[]): string | null => {
            for (const node of nodes) {
              if (node.title === "AndroidManifest.xml") return node.key;
              if (node.children) {
                const found = findManifest(node.children);
                if (found) return found;
              }
            }
            return null;
          };

          const deepPath = findManifest(fileTree);
          if (deepPath) {
            addLog("Local", `🔍 已定位 Manifest: ${deepPath}`, "success");
            try {
              manifestContent = await invoke("read_local_file", { path: deepPath }) as string;
            } catch (err) {
              addLog("Local", `❌ 读取 Manifest 失败: ${err}`, "error");
            }
          } else {
            addLog("Local", "❌ 彻底未找到 AndroidManifest.xml", "error");
          }
        }
      } catch (e) {
        addLog("Local", `上下文构建失败: ${e}`, "warning");
      }

      // 4. 通知云端开始任务
      addLog("Local", `发送指令: ${userInstruction || "默认分析"}`, "info");

      // 🔥 传递 ModelConfig + Context + NetworkCaptures
      await invoke("notify_cloud_job_start", {
        sessionId: sessionId,
        filePath: outputDir,
        instruction: userInstruction,
        modelConfig: modelConfig,
        manifest: manifestContent, // 🔥 Handshake Payload
        fileTree: fileTree,        // 🔥 Handshake Payload
        networkCaptures: httpRequests // 🔥 新增：发送网络抓包数据给 AI 分析
      });
    } catch (e) {
      if (unlistenJadx) unlistenJadx();
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
      const projectPath = pendingProjectPath; // 🔥 获取已选项目路径（如有）
      setPendingFile(null);
      setPendingProjectPath(null); // 🔥 清除项目路径
      setTimeout(() => startPipeline(file, currentInput, projectPath || undefined), 100);
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
        reasoning: "",
        time: new Date().toLocaleTimeString(),
      });
      currentStreamingMsgId.current = aiMsgId;
      streamContentBuffer.current = "";
      streamReasoningBuffer.current = "";

      try {
        // 🔥 传递 ModelConfig
        await invoke("send_chat_message", {
          sessionId: sessionId,
          message: currentInput,
          modelConfig: modelConfig, // Pass config
        });
      } catch (e) {
        message.error("发送失败: " + e);
        setIsRunning(false);
      }
    }
  };

  const handleStop = async () => {
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
      {/* Settings Modal */}
      <Modal
        title="🤖 AI 模型配置"
        open={isSettingsOpen}
        onOk={handleSaveConfig}
        onCancel={() => setIsSettingsOpen(false)}
        okText="保存配置"
        cancelText="取消"
      >
        <Form
          form={configForm}
          layout="vertical"
          initialValues={modelConfig}
        >
          <Form.Item name="provider" label="Provider (服务商)">
            <Select>
              <Select.Option value="openai">OpenAI (Standard)</Select.Option>
              <Select.Option value="deepseek">DeepSeek</Select.Option>
              <Select.Option value="gemini">Google Gemini</Select.Option>
              <Select.Option value="nvidia">Nvidia NIM</Select.Option>
              <Select.Option value="custom">Custom (Ollama/LocalAI)</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item name="apiKey" label="API Key">
            <Input.Password placeholder="sk-..." />
          </Form.Item>

          <Form.Item name="model" label="Model Name (模型名称)">
            <Input placeholder="gpt-4o / deepseek-chat / gemini-1.5-flash" />
          </Form.Item>

          <Form.Item name="baseURL" label="Base URL (可选)">
            <Input placeholder="https://api.openai.com/v1" />
          </Form.Item>

          <div style={{ display: 'flex', gap: 16 }}>
            <Form.Item name="temperature" label="Temperature">
              <InputNumber min={0} max={2} step={0.1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="maxTokens" label="Max Tokens">
              <InputNumber min={100} max={32000} step={100} style={{ width: '100%' }} />
            </Form.Item>
          </div>
        </Form>
      </Modal>

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
          <Tooltip title="模型设置">
            <Button
              icon={<SettingOutlined />}
              onClick={() => setIsSettingsOpen(true)}
            />
          </Tooltip>
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
              {/* 🔥 改进：下拉菜单选择上传新APK或选择已有项目 */}
              <Dropdown
                menu={{
                  items: [
                    {
                      key: 'upload',
                      icon: <PaperClipOutlined />,
                      label: '上传新 APK',
                      onClick: handleSelectFile,
                    },
                    {
                      key: 'existing',
                      icon: <FileZipOutlined />,
                      label: '选择已有项目',
                      onClick: () => setIsProjectModalOpen(true),
                      disabled: recentProjects.length === 0,
                    },
                  ],
                }}
                trigger={['click']}
              >
                <Button
                  type="text"
                  shape="circle"
                  icon={<PaperClipOutlined />}
                  style={{ marginBottom: 4 }}
                />
              </Dropdown>

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

        {/* Right: 两个独立卡片面板 */}
        <div
          style={{
            width: isTaskPanelOpen ? "38%" : 0,
            opacity: isTaskPanelOpen ? 1 : 0,
            overflow: "hidden",
            transition: "all 0.3s",
            background: "#f0f2f5",
            display: "flex",
            flexDirection: "column",
            gap: 12,
            padding: isTaskPanelOpen ? 12 : 0,
          }}
        >
          {/* 顶部：关闭按钮 */}
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <CloseOutlined
              style={{ cursor: "pointer", color: "#666", fontSize: 16 }}
              onClick={() => setIsTaskPanelOpen(false)}
            />
          </div>

          {/* 🌐 卡片1：网络抓包 (浅色背景 - 类似 Charles/Fiddler) */}
          <div
            style={{
              background: "#fff",
              borderRadius: 8,
              boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
              flex: "0 0 45%",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            {/* 卡片头部 */}
            <div
              style={{
                padding: "12px 16px",
                borderBottom: "1px solid #f0f0f0",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontWeight: 600, color: "#333" }}>
                🌐 网络抓包 <Tag color="blue">{httpRequests.length}</Tag>
              </span>
              {httpRequests.length > 0 && (
                <Button size="small" type="text" onClick={() => db.networkCaptures.where({ sessionId }).delete()}>
                  清空
                </Button>
              )}
            </div>
            {/* 卡片内容 - 请求列表 */}
            <div style={{ flex: 1, overflowY: "auto" }}>
              {httpRequests.length === 0 ? (
                <div style={{ color: "#999", textAlign: "center", padding: 30 }}>
                  暂无网络请求<br />
                  {!isMitmRunning ? (
                    <Button
                      type="primary"
                      size="small"
                      style={{ marginTop: 12 }}
                      onClick={async () => {
                        try {
                          await invoke("start_mitmproxy", { port: 10086 });
                          setIsMitmRunning(true);
                          message.success("抓包服务已启动");
                        } catch (e: any) {
                          if (e.toString().includes("already") || e.toString().includes("占用")) {
                            setIsMitmRunning(true);
                            message.info("抓包服务已在运行中");
                          } else {
                            message.error("启动失败: " + e);
                          }
                        }
                      }}
                    >
                      🔄 启动抓包服务
                    </Button>
                  ) : (
                    <span style={{ fontSize: 12 }}>抓包服务运行中，等待网络请求...</span>
                  )}
                </div>
              ) : (
                httpRequests.slice().reverse().map((req) => (
                  <div
                    key={req.id}
                    style={{
                      padding: "10px 16px",
                      borderBottom: "1px solid #f5f5f5",
                      cursor: "pointer",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "#fafafa")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    {/* 第一行：Method + Status + Host */}
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <Tag
                        color={req.method === "GET" ? "blue" : req.method === "POST" ? "green" : "orange"}
                        style={{ margin: 0 }}
                      >
                        {req.method}
                      </Tag>
                      {req.status && (
                        <Tag
                          color={req.status >= 200 && req.status < 300 ? "success" : req.status >= 400 ? "error" : "warning"}
                          style={{ margin: 0 }}
                        >
                          {req.status}
                        </Tag>
                      )}
                      <span style={{ fontSize: 12, color: "#666", fontWeight: 500 }}>
                        {req.host}
                      </span>
                    </div>

                    {/* 第二行：Path - 可横向滚动 */}
                    <div
                      style={{
                        fontSize: 11,
                        color: "#1890ff",
                        overflowX: "auto",
                        whiteSpace: "nowrap",
                        fontFamily: "monospace",
                      }}
                    >
                      {req.path}
                    </div>

                    {/* 第三行：如果 URL 包含 sign 参数则高亮显示 */}
                    {req.url?.toLowerCase().includes("sign=") && (
                      <div style={{ marginTop: 4 }}>
                        <Tag color="gold" style={{ fontSize: 10 }}>🔐 包含 sign 参数</Tag>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* 📋 卡片2：系统日志 (深色背景) */}
          <div
            style={{
              background: "#1e1e1e",
              borderRadius: 8,
              boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
              flex: 1,
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            {/* 卡片头部 */}
            <div
              style={{
                padding: "10px 16px",
                borderBottom: "1px solid #333",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontWeight: 600, color: "#fff" }}>📋 系统日志</span>
              <div style={{ display: "flex", gap: 4 }}>
                <Button
                  size="small"
                  type={logFilter === "all" ? "primary" : "text"}
                  onClick={() => setLogFilter("all")}
                  style={{
                    fontSize: 11,
                    color: logFilter === "all" ? "#fff" : "#888",
                    background: logFilter === "all" ? "#1890ff" : "transparent",
                  }}
                >
                  全部
                </Button>
                <Button
                  size="small"
                  type={logFilter === "key" ? "primary" : "text"}
                  onClick={() => setLogFilter("key")}
                  style={{
                    fontSize: 11,
                    color: logFilter === "key" ? "#fff" : "#888",
                    background: logFilter === "key" ? "#52c41a" : "transparent",
                  }}
                >
                  🔑 关键
                </Button>
                <Button
                  size="small"
                  type="text"
                  onClick={() => db.sessionLogs.where({ sessionId }).delete()}
                  style={{ fontSize: 11, color: "#888" }}
                >
                  清空
                </Button>
              </div>
            </div>
            {/* 卡片内容 */}
            <div
              style={{
                flex: 1,
                padding: 12,
                overflowY: "auto",
                fontFamily: "monospace",
                fontSize: 11,
                color: "#a9b7c6",
              }}
            >
              {logs
                .filter(log => logFilter === "all" || log.isKeyResult)
                .filter(log => !/[\x00-\x1F]/.test(log.msg)) // 🔥 过滤乱码控制字符
                .map((log, idx) => (
                  <div
                    key={idx}
                    style={{
                      marginBottom: 4,
                      padding: "4px 8px",
                      borderRadius: 4,
                      background: log.isKeyResult ? "rgba(82, 196, 26, 0.1)" : "transparent",
                      borderLeft: log.isKeyResult ? "2px solid #52c41a" : "2px solid transparent",
                    }}
                  >
                    <span
                      style={{
                        color:
                          log.source === "Local" ? "#faad14" :
                            log.source === "Agent" ? "#52c41a" :
                              log.source === "Device" ? "#1890ff" :
                                log.source === "Cloud" ? "#eb2f96" : "#888",
                        marginRight: 6,
                        fontSize: 10,
                      }}
                    >
                      {/* 🔥 日志来源图标区分 */}
                      {log.source === "Local" ? "💻" :
                        log.source === "Agent" ? "🤖" :
                          log.source === "Device" ? "📱" :
                            log.source === "Cloud" ? "☁️" : "📋"} [{log.source}]
                    </span>
                    <span style={{ color: log.isKeyResult ? "#fff" : "#a9b7c6" }}>
                      {log.msg.replace(/[\x00-\x1F]/g, "")}
                    </span>
                  </div>

                ))}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      </div>

      {/* 🔥 新增：项目选择模态框 */}
      <Modal
        title="📂 选择已有项目"
        open={isProjectModalOpen}
        onCancel={() => setIsProjectModalOpen(false)}
        footer={null}
        width={600}
      >
        <List
          dataSource={recentProjects}
          locale={{ emptyText: '暂无历史项目' }}
          renderItem={(project) => (
            <List.Item
              style={{ cursor: 'pointer', padding: '12px 16px', borderRadius: 8 }}
              onClick={() => {
                setIsProjectModalOpen(false);
                // 🔥 修复：只设置待处理状态，等用户点击发送再启动
                const virtualFile: AppFile = {
                  name: project.name,
                  path: project.apkPath || project.path,
                };
                setPendingFile(virtualFile);
                setPendingProjectPath(project.path); // 记住项目路径，发送时传入
                message.info(`已选择项目：${project.name}，请输入分析指令后发送`);
              }}
            >

              <List.Item.Meta
                avatar={<FileZipOutlined style={{ fontSize: 24, color: '#1890ff' }} />}
                title={project.name}
                description={
                  <div>
                    <div style={{ fontSize: 11, color: '#888' }}>
                      📁 {project.path}
                    </div>
                    <div style={{ fontSize: 11, color: '#888' }}>
                      🕐 {new Date(project.lastUsed).toLocaleString()}
                    </div>
                  </div>
                }
              />
            </List.Item>
          )}
        />
      </Modal>
    </div>
  );
};

export default AiWorkbenchPage;
