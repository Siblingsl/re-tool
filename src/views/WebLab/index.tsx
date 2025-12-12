import React, { useState, useEffect, useRef } from "react"; // 🔥 引入 useRef
import {
  Layout,
  Card,
  Button,
  Input,
  Switch,
  Checkbox,
  Typography,
  message,
  Tabs,
  Space,
  Select,
} from "antd";
import {
  BugOutlined,
  RocketOutlined,
  PlayCircleOutlined,
  StopOutlined,
  ConsoleSqlOutlined,
  CodeOutlined,
  ClearOutlined,
  SettingOutlined,
} from "@ant-design/icons";
import Editor from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const { Content, Sider } = Layout;
const { Text } = Typography;

const WebLab: React.FC = () => {
  const [logs, setLogs] = useState<string>("");
  const [url, setUrl] = useState("");
  const [config, setConfig] = useState({
    browserType: "firefox",
    stealth: true,
    headless: false,
    hooks: [""],
  });

  const [engineStatus, setEngineStatus] = useState("Stopped");
  const [activeTab, setActiveTab] = useState("code");
  const [code, setCode] = useState(
    "// 在此处输入 Playwright 代码\n// const title = await page.title();\n// console.log(title);"
  );

  // 🔥🔥🔥 核心修复 1: 停止锁 Ref 🔥🔥🔥
  // 用于解决：点击停止后，后端延迟传来的“运行中”消息把状态改回去的问题
  const isManuallyStopping = useRef(false);

  // 🔥🔥🔥 核心修复 2: 状态判断改为白名单模式 (更稳健) 🔥🔥🔥
  // 只有明确包含 "Launch" 关键字的状态才认为是运行中，其他一律视为停止
  const isRunning =
    engineStatus.includes("Launch") || engineStatus.includes("Running");

  useEffect(() => {
    const unlisten = listen("weblab-event", (event: any) => {
      const { type, payload } = event.payload;

      // 1. 处理状态变更
      if (type === "status") {
        // 🔥 如果正在手动停止中，且收到的消息不是“已停止”，则直接忽略
        // 防止：点击停止 -> UI变绿 -> 后端延迟传来 "Browser Launched" -> UI又变红
        if (
          isManuallyStopping.current &&
          payload !== "Stopped" &&
          payload !== "Browser Closed"
        ) {
          console.log("忽略延迟状态:", payload);
          return;
        }

        if (
          payload === "Browser Closed" ||
          payload === "Browser Force Closed" ||
          payload === "Stopped"
        ) {
          setEngineStatus("Stopped");
          // 收到后端确认停止的消息后，解锁
          isManuallyStopping.current = false;
          if (payload === "Browser Closed") message.info("浏览器已关闭");
        } else {
          setEngineStatus(payload);
        }
      }

      // 2. 处理错误消息
      if (type === "error") {
        if (
          payload.includes("Launch Failed") ||
          payload.includes("Navigation failed")
        ) {
          setEngineStatus("Stopped");
          isManuallyStopping.current = false;
        }
        const time = new Date().toLocaleTimeString();
        setLogs((prev) => prev + `\n[${time}] [ERROR] ${payload}`);
        return;
      }

      // 3. 处理日志
      const time = new Date().toLocaleTimeString();
      let logLine = `[${time}] [${type}] `;
      if (typeof payload === "object") {
        logLine += JSON.stringify(payload);
      } else {
        logLine += payload;
      }
      setLogs((prev) => prev + "\n" + logLine);
    });

    return () => {
      unlisten.then((f) => f());
    };
  }, []);

  const startEngine = async () => {
    // 启动前重置锁
    isManuallyStopping.current = false;

    if (!url || !url.trim()) {
      message.warning("请输入有效的目标 URL");
      return;
    }
    if (!url.startsWith("http")) {
      message.warning("URL 必须以 http:// 或 https:// 开头");
      return;
    }

    try {
      // 先把状态设为启动中，防止用户连点
      setEngineStatus("Launching...");

      await invoke("start_web_engine");
      setTimeout(async () => {
        await invoke("send_web_command", {
          action: "launch",
          data: {
            url: url,
            browserType: config.browserType,
            headless: config.headless,
            hooks: config.hooks,
          },
        });
        message.success("发送启动指令...");
      }, 500);
    } catch (e) {
      message.error("启动失败: " + e);
      setEngineStatus("Stopped");
    }
  };

  const stopEngine = async () => {
    // 🔥🔥🔥 核心修复 3: 立即上锁并更新 UI 🔥🔥🔥
    isManuallyStopping.current = true;
    setEngineStatus("Stopped");
    message.info("正在强制停止引擎...");

    try {
      await invoke("stop_web_engine");
      // 1秒后自动解锁（兜底，防止万一后端没发回 Stopped 消息）
      setTimeout(() => {
        isManuallyStopping.current = false;
      }, 1000);
    } catch (e) {
      console.error("停止失败:", e);
      isManuallyStopping.current = false;
    }
  };

  const runEval = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器引擎");
      return;
    }
    await invoke("send_web_command", {
      action: "eval",
      data: code,
    });
    setActiveTab("console");
  };

  const ConfigPanel = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div
        style={{
          padding: "12px",
          background: !isRunning ? "#fff1f0" : "#f6ffed",
          border: `1px solid ${!isRunning ? "#ffa39e" : "#b7eb8f"}`,
          borderRadius: 6,
          textAlign: "center",
          color: !isRunning ? "#cf1322" : "#389e0d",
          fontWeight: "bold",
        }}
      >
        {!isRunning ? "🔴 引擎未运行" : "🟢 引擎运行中"}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <Text strong>目标 URL</Text>
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="请输入有效 URL 地址"
          allowClear
        />
      </div>

      <Card
        size="small"
        title={
          <span>
            <SettingOutlined /> 环境伪造
          </span>
        }
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              浏览器内核
            </Text>
            <Select
              value={config.browserType}
              onChange={(v) => setConfig({ ...config, browserType: v })}
              options={[
                { value: "chromium", label: "Chromium (Chrome/Edge)" },
                { value: "firefox", label: "Firefox (Gecko)" },
                { value: "webkit", label: "WebKit (Safari)" },
              ]}
            />
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>隐身模式 (Stealth)</span>
            <Switch
              checked={config.stealth}
              onChange={(v) => setConfig({ ...config, stealth: v })}
            />
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>无头模式 (Headless)</span>
            <Switch
              checked={config.headless}
              onChange={(v) => setConfig({ ...config, headless: v })}
            />
          </div>
        </div>
      </Card>

      <Card
        size="small"
        title={
          <span>
            <BugOutlined /> 注入 Hook
          </span>
        }
      >
        <Checkbox.Group
          style={{ display: "flex", flexDirection: "column", gap: 8 }}
          options={[
            { label: "JSON.parse/stringify 监控", value: "json_hook" },
            { label: "XHR/Fetch 网络请求监控", value: "network_hook" },
            { label: "Cookie 变化监控", value: "cookie_hook" },
            { label: "WebSocket 消息监控", value: "websocket_hook" },
            { label: "Web Crypto 加密监控", value: "crypto_hook" },
            { label: "Debugger 反调试绕过", value: "anti_debug" },
          ]}
          value={config.hooks}
          onChange={(v) => setConfig({ ...config, hooks: v as string[] })}
        />
      </Card>

      <div
        style={{
          marginTop: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        {!isRunning ? (
          <Button
            type="primary"
            size="large"
            icon={<RocketOutlined />}
            onClick={startEngine}
            block
          >
            启动浏览器
          </Button>
        ) : (
          <Button
            danger
            size="large"
            icon={<StopOutlined />}
            onClick={stopEngine}
            block
          >
            停止引擎
          </Button>
        )}
      </div>
    </div>
  );

  return (
    <Layout style={{ height: "100%", background: "#fff" }}>
      <Sider
        width={280}
        theme="light"
        style={{
          borderRight: "1px solid #f0f0f0",
          padding: "16px",
          overflowY: "auto",
        }}
      >
        <ConfigPanel />
      </Sider>

      <Content
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "8px 16px",
            borderBottom: "1px solid #f0f0f0",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "#fafafa",
          }}
        >
          <Space>
            <Button
              type={activeTab === "code" ? "primary" : "default"}
              icon={<CodeOutlined />}
              onClick={() => setActiveTab("code")}
            >
              代码编辑
            </Button>
            <Button
              type={activeTab === "console" ? "primary" : "default"}
              icon={<ConsoleSqlOutlined />}
              onClick={() => setActiveTab("console")}
            >
              超级控制台
            </Button>
          </Space>

          <Space>
            {activeTab === "code" && (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={runEval}
              >
                运行片段
              </Button>
            )}
            {activeTab === "console" && (
              <Button icon={<ClearOutlined />} onClick={() => setLogs("")}>
                清空日志
              </Button>
            )}
          </Space>
        </div>

        <div style={{ flex: 1, position: "relative" }}>
          <div
            style={{
              display: activeTab === "code" ? "block" : "none",
              height: "100%",
            }}
          >
            <Editor
              height="100%"
              defaultLanguage="javascript"
              value={code}
              onChange={(val) => setCode(val || "")}
              theme="vs-light"
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                scrollBeyondLastLine: false,
                automaticLayout: true,
              }}
            />
          </div>

          <div
            style={{
              display: activeTab === "console" ? "block" : "none",
              height: "100%",
              background: "#1e1e1e",
              color: "#d4d4d4",
              padding: "12px",
              overflowY: "auto",
              fontFamily: "Consolas, monospace",
              fontSize: "13px",
              whiteSpace: "pre-wrap",
            }}
          >
            {logs || "// 等待日志输出..."}
          </div>
        </div>
      </Content>
    </Layout>
  );
};

export default WebLab;
