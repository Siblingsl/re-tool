import React, { useState, useEffect, useRef } from "react";
import {
  Layout,
  Card,
  Button,
  Input,
  Switch,
  Checkbox,
  Typography,
  message,
  Space,
  Select,
  Collapse,
  Badge,
  Tooltip,
  InputNumber,
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
  ApiOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import Editor from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const { Content, Sider } = Layout;
const { Text } = Typography;
const { Panel } = Collapse;

const WebLab: React.FC = () => {
  const [logs, setLogs] = useState<string>("");
  const [url, setUrl] = useState("https://www.whoer.net");
  const [config, setConfig] = useState({
    browserType: "firefox",
    stealth: true,
    headless: false,
    hooks: ["json_hook", "rpc_inject"], // 默认开启 RPC 注入
  });

  // RPC 状态
  const [rpcPort, setRpcPort] = useState(9999);
  const [rpcRunning, setRpcRunning] = useState(false);

  const [engineStatus, setEngineStatus] = useState("Stopped");
  const [activeTab, setActiveTab] = useState("code");
  const [code, setCode] = useState(
    `/**
 * ✨ Playwright 自动化脚本编辑器
 * * 🚀 支持 Node.js 环境下 Playwright API
 * * 💡 提示：使用 await page.evaluate(() => {...}) 在浏览器内执行 JS
 */

try {
  console.log(">>> 开始执行...");
  const title = await page.title();
  console.log(\`页面标题: \${title}\`);
  return "Success";
} catch (err) {
  console.error(err.message);
}`
  );

  const isManuallyStopping = useRef(false);

  const isRunning =
    engineStatus.includes("Launch") ||
    engineStatus.includes("Running") ||
    engineStatus.includes("Launched");

  useEffect(() => {
    const unlisten = listen("weblab-event", (event: any) => {
      const { type, payload } = event.payload;

      // 状态处理
      if (type === "status") {
        if (
          isManuallyStopping.current &&
          payload !== "Stopped" &&
          payload !== "Browser Closed"
        )
          return;

        if (
          payload === "Browser Closed" ||
          payload === "Browser Force Closed" ||
          payload === "Stopped"
        ) {
          setEngineStatus("Stopped");
          setRpcRunning(false); // 浏览器关了，RPC 也就断了
          isManuallyStopping.current = false;
          if (payload === "Browser Closed") message.info("浏览器已关闭");
        } else {
          setEngineStatus(payload);
        }
      }

      if (type === "error") {
        if (payload.includes("Launch Failed")) {
          setEngineStatus("Stopped");
          isManuallyStopping.current = false;
        }
        const time = new Date().toLocaleTimeString();
        setLogs((prev) => prev + `\n[${time}] [ERROR] ${payload}`);
        return;
      }

      // RPC 日志特殊处理
      if (type === "rpc_log") {
        const time = new Date().toLocaleTimeString();
        if (payload.includes("已启动")) setRpcRunning(true);
        if (payload.includes("已停止")) setRpcRunning(false);
        setLogs((prev) => prev + `\n[${time}] [RPC] ${payload}`);
        return;
      }

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
    isManuallyStopping.current = false;
    if (!url || !url.startsWith("http")) {
      message.warning("请输入有效的 HTTP/HTTPS URL");
      return;
    }

    try {
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
        message.success("启动指令已发送");
      }, 500);
    } catch (e) {
      message.error("启动失败: " + e);
      setEngineStatus("Stopped");
    }
  };

  const stopEngine = async () => {
    isManuallyStopping.current = true;
    setEngineStatus("Stopped");
    setRpcRunning(false);
    try {
      await invoke("stop_web_engine");
      setTimeout(() => {
        isManuallyStopping.current = false;
      }, 1000);
    } catch (e) {
      console.error(e);
    }
  };

  // 控制 RPC 服务
  const toggleRpc = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器");
      return;
    }
    const action = rpcRunning ? "stop" : "start";
    await invoke("send_web_command", {
      action: "rpc_ctrl",
      data: { action, port: rpcPort },
    });
  };

  const runEval = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器");
      return;
    }
    await invoke("send_web_command", { action: "eval", data: code });
    setActiveTab("console");
  };

  // 左侧配置面板 (使用 Collapse 优化结构)
  const ConfigPanel = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* 状态栏 */}
      <div
        style={{
          padding: "12px",
          background: !isRunning ? "#fff1f0" : "#f6ffed",
          border: `1px solid ${!isRunning ? "#ffa39e" : "#b7eb8f"}`,
          borderRadius: 6,
          textAlign: "center",
          color: !isRunning ? "#cf1322" : "#389e0d",
          fontWeight: "bold",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          gap: 8,
        }}
      >
        <Badge status={!isRunning ? "error" : "processing"} />
        {!isRunning ? "引擎未运行" : "引擎运行中"}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <Text strong>目标 URL</Text>
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          status={!url ? "error" : ""}
        />
      </div>

      <Collapse defaultActiveKey={["rpc", "env"]} ghost size="small">
        {/* 1. RPC 桥接 (核心功能) */}
        <Panel
          header={
            <span>
              <ApiOutlined /> RPC 桥接服务
            </span>
          }
          key="rpc"
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <Text>端口 (WS)</Text>
              <InputNumber
                value={rpcPort}
                onChange={(v) => setRpcPort(v || 9999)}
                disabled={rpcRunning}
              />
            </div>
            <Button
              type={rpcRunning ? "default" : "primary"}
              danger={rpcRunning}
              icon={<ThunderboltOutlined />}
              onClick={toggleRpc}
              block
              disabled={!isRunning}
            >
              {rpcRunning ? "关闭 RPC 服务" : "开启 RPC 服务"}
            </Button>
            {rpcRunning && (
              <div
                style={{
                  fontSize: 12,
                  color: "#10b981",
                  background: "#ecfdf5",
                  padding: 8,
                  borderRadius: 4,
                }}
              >
                服务地址: ws://127.0.0.1:{rpcPort}
              </div>
            )}
          </div>
        </Panel>

        {/* 2. 环境伪造 */}
        <Panel
          header={
            <span>
              <SettingOutlined /> 环境伪造
            </span>
          }
          key="env"
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Select
              value={config.browserType}
              onChange={(v) => setConfig({ ...config, browserType: v })}
              options={[
                { value: "firefox", label: "Firefox (Gecko)" },
                { value: "chromium", label: "Chromium (Chrome)" },
                { value: "webkit", label: "WebKit (Safari)" },
              ]}
              style={{ width: "100%" }}
            />
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>隐身模式 (Stealth)</span>
              <Switch
                checked={config.stealth}
                onChange={(v) => setConfig({ ...config, stealth: v })}
              />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>无头模式 (Headless)</span>
              <Switch
                checked={config.headless}
                onChange={(v) => setConfig({ ...config, headless: v })}
              />
            </div>
          </div>
        </Panel>

        {/* 3. Hook 注入 */}
        <Panel
          header={
            <span>
              <BugOutlined /> 注入 Hook
            </span>
          }
          key="hooks"
        >
          <Checkbox.Group
            style={{ display: "flex", flexDirection: "column", gap: 8 }}
            options={[
              { label: "RPC 注入 (必需)", value: "rpc_inject", disabled: true },
              { label: "JSON.parse 监控", value: "json_hook" },
              { label: "XHR/Fetch 监控", value: "network_hook" },
              { label: "Cookie 变化监控", value: "cookie_hook" },
              { label: "Debugger 绕过", value: "anti_debug" },
            ]}
            value={config.hooks}
            onChange={(v) => setConfig({ ...config, hooks: v as string[] })}
          />
        </Panel>
      </Collapse>

      <div style={{ marginTop: "auto" }}>
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
                清空
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
