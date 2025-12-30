import React, { useState, useRef, useEffect } from "react";
import {
  SendOutlined,
  RobotOutlined,
  UserOutlined,
  DeleteOutlined,
  CopyOutlined,
  BulbOutlined,
  CodeOutlined,
  BugOutlined,
  DownOutlined,
  CheckOutlined,
  LoadingOutlined, // 新增
} from "@ant-design/icons";
import {
  Input,
  Button,
  Avatar,
  List,
  theme,
  Tooltip,
  message,
  Empty,
  Dropdown,
  MenuProps,
} from "antd";
import { useLiveQuery } from "dexie-react-hooks";
import { db } from "@/db";

const { TextArea } = Input;

// 扩展 Message 接口以支持 reasoning
interface Message {
  id?: number;
  sessionId: string;
  role: "user" | "ai";
  content: string;
  reasoning?: string; // 新增推理字段
  time: string;
}

interface AiChatPageProps {
  sessionId?: string;
}

const QUICK_PROMPTS = [
  { icon: <CodeOutlined />, text: "生成 Frida Hook 模板" },
  { icon: <BulbOutlined />, text: "解释这段 Smali 代码" },
  { icon: <BugOutlined />, text: "分析网络请求加密" },
];

const AiChatPage: React.FC<AiChatPageProps> = ({ sessionId = "default" }) => {
  const { token } = theme.useToken();
  const [inputValue, setInputValue] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const initLockRef = useRef<string | null>(null);

  // 1. 实时获取消息
  const messages =
    useLiveQuery(async () => {
      // 强制确保 sessionId 是字符串，防止 undefined 传给 IndexedDB
      const currentSid = sessionId || "default";

      return await db.chatMessages
        .where("sessionId")
        .equals(currentSid)
        .toArray();
    }, [sessionId]) || [];

  // 2. 获取当前激活配置
  const activeConfig = useLiveQuery(async () => {
    const allConfigs = await db.aiConfigs.toArray();
    // 在内存中查找，避免底层 IndexedDB 的 key range 错误
    return allConfigs.find((c) => c.isActive === true);
  });

  // 初始化欢迎语
  useEffect(() => {
    const initChat = async () => {
      if (!sessionId) return;
      if (initLockRef.current === sessionId) return;
      initLockRef.current = sessionId;

      try {
        const count = await db.chatMessages.where({ sessionId }).count();
        if (count === 0) {
          await db.chatMessages.add({
            sessionId,
            role: "ai",
            content: "你好！我是你的逆向工程 AI 助手。请问有什么可以帮你的？",
            time: new Date().toLocaleTimeString(),
          });
        }
      } catch (error) {
        console.error(error);
      }
    };
    initChat();
  }, [sessionId]);

  // 自动滚动
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  // 🔥 核心：处理流式发送
  const handleSend = async () => {
    if (!inputValue.trim()) return;
    if (!activeConfig) {
      message.error("请先在设置中配置并启用 AI 模型！");
      return;
    }

    const userContent = inputValue;
    setInputValue("");
    setLoading(true);

    try {
      // 1. 用户消息入库
      await db.chatMessages.add({
        sessionId,
        role: "user",
        content: userContent,
        time: new Date().toLocaleTimeString(),
      });

      // 2. 预先创建一条空的 AI 消息占位 (用于流式更新)
      const aiMsgId = await db.chatMessages.add({
        sessionId,
        role: "ai",
        content: "",
        reasoning: "", // 初始为空
        time: new Date().toLocaleTimeString(),
      });

      // 3. 准备请求体
      const historyContext = messages.slice(-10).map((m) => ({
        role: m.role === "user" ? "user" : "assistant",
        content: m.content,
      }));

      const requestBody: any = {
        model: activeConfig.modelId,
        messages: [
          {
            role: "system",
            content: "你是一个精通 Android 逆向工程的安全专家。",
          },
          ...historyContext,
          { role: "user", content: userContent },
        ],
        temperature: 0.6,
        top_p: 0.7,
        max_tokens: 8192,
        stream: true, // ✅ 开启流式
      };

      // ✅ 针对 NVIDIA / DeepSeek 的特殊处理
      if (
        activeConfig.baseUrl?.includes("nvidia") ||
        activeConfig.modelId.includes("deepseek")
      ) {
        requestBody.chat_template_kwargs = { thinking: true };
      }

      // 4. 发起请求
      const response = await fetch(`${activeConfig.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${activeConfig.apiKey}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
      if (!response.body) throw new Error("ReadableStream not supported");

      // 5. 处理流式响应
      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let done = false;
      let fullContent = "";
      let fullReasoning = "";

      while (!done) {
        const { value, done: doneReading } = await reader.read();
        done = doneReading;
        const chunkValue = decoder.decode(value, { stream: true });

        // 处理 SSE 数据包 (例如: data: {...})
        const lines = chunkValue
          .split("\n")
          .filter((line) => line.trim() !== "");

        for (const line of lines) {
          if (line.includes("[DONE]")) continue;
          if (line.startsWith("data: ")) {
            try {
              const jsonStr = line.replace("data: ", "");
              const data = JSON.parse(jsonStr);
              const delta = data.choices[0]?.delta;

              if (delta) {
                // ✅ 捕获推理内容 (DeepSeek/NVIDIA 特有)
                if (delta.reasoning_content) {
                  fullReasoning += delta.reasoning_content;
                }
                // 捕获普通内容
                if (delta.content) {
                  fullContent += delta.content;
                }

                // 实时更新数据库 -> 驱动 UI 刷新
                // 注意：为了性能，实际生产中通常会节流更新，这里直接更新方便演示
                await db.chatMessages.update(aiMsgId, {
                  content: fullContent,
                  reasoning: fullReasoning,
                });
              }
            } catch (e) {
              console.warn("Parse error", e);
            }
          }
        }
      }

      // 更新会话摘要
      await db.chatSessions.update(sessionId, {
        lastUpdated: Date.now(),
        title: messages.length < 2 ? userContent.slice(0, 15) : undefined,
      });
    } catch (error: any) {
      console.error(error);
      await db.chatMessages.add({
        sessionId,
        role: "ai",
        content: `❌ 请求出错: ${error.message}`,
        time: new Date().toLocaleTimeString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClear = async () => {
    await db.chatMessages.where({ sessionId }).delete();
    message.success("对话记录已清空");
  };

  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content);
    message.success("已复制内容");
  };

  const modelMenuProps: MenuProps = {
    items: activeConfig
      ? [
          {
            key: activeConfig.modelId,
            label: (
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 12,
                  minWidth: 120,
                }}
              >
                <span>{activeConfig.name}</span>
                <CheckOutlined
                  style={{ color: token.colorPrimary, fontSize: 12 }}
                />
              </div>
            ),
          },
        ]
      : [{ key: "none", label: "未配置模型", disabled: true }],
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        backgroundColor: "#fff",
        position: "relative",
      }}
    >
      {/* 顶部栏 */}
      <div
        className="content-header"
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Avatar
            shape="square"
            size="large"
            icon={<RobotOutlined />}
            style={{ backgroundColor: token.colorPrimary }}
          />
          <div>
            <div style={{ fontWeight: 600, fontSize: 16 }}>智能逆向助手</div>
            <Dropdown menu={modelMenuProps} trigger={["click"]}>
              <div
                style={{
                  fontSize: 12,
                  color: "#666",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  cursor: "pointer",
                  marginTop: 2,
                  userSelect: "none",
                }}
              >
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: activeConfig ? "#52c41a" : "#ccc",
                    display: "inline-block",
                  }}
                ></span>
                <span>{activeConfig ? activeConfig.name : "未配置"}</span>
                <DownOutlined style={{ fontSize: 10, color: "#999" }} />
              </div>
            </Dropdown>
          </div>
        </div>
        <Tooltip title="清空对话">
          <Button type="text" icon={<DeleteOutlined />} onClick={handleClear} />
        </Tooltip>
      </div>

      {/* 消息列表 */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "20px 24px",
          backgroundColor: "#fafafa",
        }}
      >
        {messages.length === 0 ? (
          <div
            style={{
              height: "100%",
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "center",
              opacity: 0.6,
            }}
          >
            <Empty description="暂无对话，开始提问吧" />
            <div
              style={{
                marginTop: 20,
                display: "flex",
                gap: 10,
                flexWrap: "wrap",
                justifyContent: "center",
              }}
            >
              {QUICK_PROMPTS.map((item, idx) => (
                <Button
                  key={idx}
                  icon={item.icon}
                  onClick={() => setInputValue(item.text)}
                >
                  {item.text}
                </Button>
              ))}
            </div>
          </div>
        ) : (
          <List
            itemLayout="horizontal"
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
                <Avatar
                  icon={
                    item.role === "user" ? <UserOutlined /> : <RobotOutlined />
                  }
                  style={{
                    backgroundColor:
                      item.role === "user"
                        ? token.colorInfo
                        : token.colorPrimary,
                    flexShrink: 0,
                  }}
                />
                <div style={{ maxWidth: "80%" }}>
                  {/* ✅ 展示推理过程 (深度思考) */}
                  {item.reasoning && (
                    <div
                      style={{
                        marginBottom: 8,
                        padding: "8px 12px",
                        backgroundColor: "#f5f5f5",
                        borderLeft: "3px solid #d9d9d9",
                        borderRadius: 4,
                        fontSize: 12,
                        color: "#666",
                        whiteSpace: "pre-wrap",
                      }}
                    >
                      <div
                        style={{
                          fontWeight: "bold",
                          marginBottom: 4,
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        <BulbOutlined /> 深度思考过程:
                      </div>
                      {item.reasoning}
                    </div>
                  )}

                  <div
                    style={{
                      backgroundColor:
                        item.role === "user" ? token.colorPrimary : "#fff",
                      color: item.role === "user" ? "#fff" : "rgba(0,0,0,0.85)",
                      padding: "10px 16px",
                      borderRadius:
                        item.role === "user"
                          ? "12px 0 12px 12px"
                          : "0 12px 12px 12px",
                      boxShadow: "0 2px 5px rgba(0,0,0,0.05)",
                      whiteSpace: "pre-wrap",
                      border: item.role === "ai" ? "1px solid #f0f0f0" : "none",
                    }}
                  >
                    {item.content}
                    {/* 如果正在加载且内容为空，显示 Loading */}
                    {loading &&
                      item.role === "ai" &&
                      !item.content &&
                      !item.reasoning && <LoadingOutlined />}
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color: "#ccc",
                      marginTop: 4,
                      textAlign: item.role === "user" ? "right" : "left",
                      paddingLeft: 4,
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      justifyContent:
                        item.role === "user" ? "flex-end" : "flex-start",
                    }}
                  >
                    <span>{item.time}</span>
                    {item.role === "ai" && (
                      <CopyOutlined
                        style={{ cursor: "pointer" }}
                        onClick={() => handleCopy(item.content)}
                      />
                    )}
                  </div>
                </div>
              </div>
            )}
          />
        )}
      </div>

      {/* 底部输入框 */}
      <div
        style={{
          padding: "16px 24px",
          borderTop: "1px solid #f0f0f0",
          backgroundColor: "#fff",
        }}
      >
        <div
          style={{
            display: "flex",
            gap: 10,
            alignItems: "flex-end",
            border: `1px solid ${token.colorBorder}`,
            borderRadius: 8,
            padding: "8px 12px",
            boxShadow: "0 2px 8px rgba(0,0,0,0.02)",
            transition: "border 0.2s",
          }}
          onFocus={(e) =>
            (e.currentTarget.style.borderColor = token.colorPrimary)
          }
          onBlur={(e) =>
            (e.currentTarget.style.borderColor = token.colorBorder)
          }
        >
          <TextArea
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={
              activeConfig
                ? `正在询问 ${activeConfig.name}... (Shift + Enter 换行)`
                : "请配置 AI 模型"
            }
            autoSize={{ minRows: 1, maxRows: 6 }}
            bordered={false}
            disabled={!activeConfig || loading}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            style={{ padding: 0, resize: "none" }}
          />
          <Button
            type="primary"
            shape="circle"
            icon={loading ? <LoadingOutlined /> : <SendOutlined />}
            onClick={handleSend}
            loading={loading}
            disabled={!inputValue.trim() || !activeConfig}
          />
        </div>
        <div
          style={{
            marginTop: 8,
            fontSize: 12,
            color: "#999",
            textAlign: "center",
          }}
        >
          {activeConfig ? (
            `当前模型: ${activeConfig.name}`
          ) : (
            <span style={{ color: "#ff4d4f" }}>未配置模型</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default AiChatPage;
