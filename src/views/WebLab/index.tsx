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
  Tabs,
  Space,
  Select,
  Collapse,
  Badge,
  Tooltip,
  InputNumber,
  List,
  Modal,
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
  GlobalOutlined,
  PlusOutlined,
  DeleteOutlined,
  EditOutlined,
} from "@ant-design/icons";
import Editor from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const { Content, Sider } = Layout;
const { Text } = Typography;
const { Panel } = Collapse;
const { TextArea } = Input;

// 定义拦截规则接口
interface InterceptRule {
  id: string;
  enabled: boolean;
  urlPattern: string; // 譬如 "**/*.js" 或 "https://api.example.com/v1/user"
  resourceType: string; // "Script", "XHR", "All"
  action: "Abort" | "MockBody" | "MockFile";
  payload: string; // 响应体内容 或 文件路径
}

const WebLab: React.FC = () => {
  // ... (保留原有的 logs, url, config, engineStatus 等状态) ...
  const [logs, setLogs] = useState<string>("");
  const [url, setUrl] = useState("https://www.whoer.net");
  const [config, setConfig] = useState({
    browserType: "firefox",
    stealth: true,
    headless: false,
    hooks: ["rpc_inject"],
  });

  // RPC 状态
  const [rpcPort, setRpcPort] = useState(9999);
  const [rpcRunning, setRpcRunning] = useState(false);

  // 拦截规则状态
  const [interceptRules, setInterceptRules] = useState<InterceptRule[]>([]);
  const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
  const [currentRule, setCurrentRule] = useState<InterceptRule>({
    id: "",
    enabled: true,
    urlPattern: "",
    resourceType: "Script",
    action: "MockBody",
    payload: "",
  });

  const [engineStatus, setEngineStatus] = useState("Stopped");
  const [activeTab, setActiveTab] = useState("code");
  const [code, setCode] = useState(
    `/**
 * ✨ Playwright 自动化脚本编辑器
 * * ✅ 全局预置对象 (无需 import，直接使用):
 * - page:    当前页面对象 (Playwright Page)
 * - context: 浏览器上下文 (BrowserContext)
 * - browser: 浏览器实例 (Browser)
 * * 🚀 支持 Top-level await，请在下方直接编写业务逻辑
 */

try {
  console.log(">>> 开始执行脚本...");

  // 1. 获取当前页面信息
  const title = await page.title();
  const url = page.url();
  console.log(\`📄 标题: \${title}\`);
  console.log(\`🔗 地址: \${url}\`);

  console.log("<<< 脚本执行完毕");
  return "Success";
} catch (err) {
  console.error("❌ 执行出错:", err.message);
}`
  );

  const isManuallyStopping = useRef(false);
  const isRunning =
    engineStatus.includes("Launch") ||
    engineStatus.includes("Running") ||
    engineStatus.includes("Launched");

  // ... (保留 useEffect, listen 逻辑不变) ...
  useEffect(() => {
    const unlisten = listen("weblab-event", (event: any) => {
      const { type, payload } = event.payload;
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
          setRpcRunning(false);
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

  // ... (保留 startEngine, stopEngine, runEval, toggleRpc 等函数不变) ...
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
            // 🔥🔥🔥 传递拦截规则给后端 🔥🔥🔥
            intercepts: interceptRules.filter((r) => r.enabled),
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

  // 规则管理函数
  const addRule = () => {
    setCurrentRule({
      id: Date.now().toString(),
      enabled: true,
      urlPattern: "**/*.js",
      resourceType: "Script",
      action: "MockBody",
      payload: '// Hooked Code\nconsole.log("Script Intercepted!");',
    });
    setIsRuleModalOpen(true);
  };

  const saveRule = () => {
    setInterceptRules((prev) => {
      const idx = prev.findIndex((r) => r.id === currentRule.id);
      if (idx > -1) {
        const next = [...prev];
        next[idx] = currentRule;
        return next;
      }
      return [...prev, currentRule];
    });
    setIsRuleModalOpen(false);
  };

  const deleteRule = (id: string) => {
    setInterceptRules((prev) => prev.filter((r) => r.id !== id));
  };

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
        {/* 1. RPC 桥接 */}
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

        {/* 3. 请求拦截 (新增) */}
        <Panel
          header={
            <span>
              <GlobalOutlined /> 请求拦截 & 替换
            </span>
          }
          key="intercept"
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <Button
              type="dashed"
              icon={<PlusOutlined />}
              block
              onClick={addRule}
            >
              添加拦截规则
            </Button>
            <List
              size="small"
              dataSource={interceptRules}
              renderItem={(item) => (
                <List.Item
                  actions={[
                    <DeleteOutlined
                      onClick={() => deleteRule(item.id)}
                      style={{ color: "#ff4d4f" }}
                    />,
                    <Switch
                      size="small"
                      checked={item.enabled}
                      onChange={(v) => {
                        const newRules = interceptRules.map((r) =>
                          r.id === item.id ? { ...r, enabled: v } : r
                        );
                        setInterceptRules(newRules);
                      }}
                    />,
                  ]}
                >
                  <div style={{ width: "100%", overflow: "hidden" }}>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>
                      {item.urlPattern}
                    </div>
                    <div style={{ fontSize: 12, color: "#999" }}>
                      {item.action} • {item.resourceType}
                    </div>
                  </div>
                </List.Item>
              )}
            />
          </div>
        </Panel>

        {/* 4. Hook 注入 */}
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

      {/* 规则编辑弹窗 */}
      <Modal
        title="编辑拦截规则"
        open={isRuleModalOpen}
        onOk={saveRule}
        onCancel={() => setIsRuleModalOpen(false)}
        width={600}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div>
            <Text>URL 匹配模式 (支持通配符 *)</Text>
            <Input
              value={currentRule.urlPattern}
              onChange={(e) =>
                setCurrentRule({ ...currentRule, urlPattern: e.target.value })
              }
              placeholder="例如: **/api/v1/login 或 **/*.js"
            />
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <div style={{ flex: 1 }}>
              <Text>资源类型</Text>
              <Select
                value={currentRule.resourceType}
                onChange={(v) =>
                  setCurrentRule({ ...currentRule, resourceType: v })
                }
                options={[
                  { value: "Script", label: "JS 脚本" },
                  { value: "XHR", label: "XHR/Fetch" },
                  { value: "Image", label: "图片" },
                  { value: "All", label: "所有" },
                ]}
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <Text>动作</Text>
              <Select
                value={currentRule.action}
                onChange={(v) => setCurrentRule({ ...currentRule, action: v })}
                options={[
                  { value: "MockBody", label: "修改响应体" },
                  { value: "Abort", label: "阻断请求" },
                ]}
                style={{ width: "100%" }}
              />
            </div>
          </div>
          {currentRule.action === "MockBody" && (
            <div>
              <Text>响应体内容 (JS代码或JSON)</Text>
              <TextArea
                rows={6}
                value={currentRule.payload}
                onChange={(e) =>
                  setCurrentRule({ ...currentRule, payload: e.target.value })
                }
                placeholder="// 在这里输入你要替换的 JS 代码..."
                style={{ fontFamily: "monospace" }}
              />
            </div>
          )}
        </div>
      </Modal>
    </Layout>
  );
};

export default WebLab;
