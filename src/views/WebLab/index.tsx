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
  InputNumber,
  List,
  Modal,
  Tag,
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
  EyeOutlined,
  RobotOutlined,
  EditOutlined,
  FileAddOutlined,
  UserAddOutlined,
} from "@ant-design/icons";
import Editor from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const { Content, Sider } = Layout;
const { Text } = Typography;
const { Panel } = Collapse;
const { TextArea } = Input;

interface InterceptRule {
  id: string;
  enabled: boolean;
  urlPattern: string;
  resourceType: string;
  action: "Abort" | "MockBody" | "MockFile";
  payload: string;
}

// 🔥🔥🔥 新增：自定义脚本接口 🔥🔥🔥
interface CustomScript {
  id: string;
  name: string;
  code: string;
  enabled: boolean;
}

const WebLab: React.FC = () => {
  const [logs, setLogs] = useState<string>("");
  const [url, setUrl] = useState("https://www.whoer.net");
  const [config, setConfig] = useState({
    browserType: "firefox",
    stealth: true,
    headless: false,
    hooks: ["json_hook", "rpc_inject"],
  });

  const [rpcPort, setRpcPort] = useState(9999);
  const [rpcRunning, setRpcRunning] = useState(false);

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

  // 🔥🔥🔥 新增：自定义脚本状态 🔥🔥🔥
  const [customScripts, setCustomScripts] = useState<CustomScript[]>([]);
  const [isScriptModalOpen, setIsScriptModalOpen] = useState(false);
  const [currentScript, setCurrentScript] = useState<CustomScript>({
    id: "",
    name: "New Script",
    code: '// 在此编写要在页面加载前注入的 JS 代码\nconsole.log("Custom script loaded!");',
    enabled: true,
  });

  const [engineStatus, setEngineStatus] = useState("Stopped");
  const [activeTab, setActiveTab] = useState("code");
  const [code, setCode] = useState(
    `/**
 * ✨ Playwright 自动化脚本编辑器
 * * 👁️ 点击 "拾取元素" 生成点击代码
 * * 🤖 点击 "AI 验证码" 自动识别图片验证码
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
  const isPickingCaptcha = useRef(false);
  const [aiLoading, setAiLoading] = useState(false);

  const isRunning =
    engineStatus.includes("Launch") ||
    engineStatus.includes("Running") ||
    engineStatus.includes("Launched");

  // 初始化：从 LocalStorage 加载脚本
  useEffect(() => {
    const savedScripts = localStorage.getItem("weblab_custom_scripts");
    if (savedScripts) {
      try {
        setCustomScripts(JSON.parse(savedScripts));
      } catch (e) {}
    }
  }, []);

  // 监听后端事件
  useEffect(() => {
    const unlisten = listen("weblab-event", (event: any) => {
      const { type, payload } = event.payload;

      if (type === "inspector_picked") {
        const selector = payload;
        if (isPickingCaptcha.current) {
          message.loading("正在截取验证码...", 1);
          invoke("send_web_command", {
            action: "screenshot_element",
            data: { selector: selector },
          });
        } else {
          message.success(`已拾取: ${selector}`);
          const insertCode = `\n// 🎯 自动拾取\nawait page.click('${selector}');`;
          setCode((prev) => prev + insertCode);
          setActiveTab("code");
        }
        return;
      }

      if (type === "element_screenshot") {
        const { selector, image } = payload;
        handleAiRecognition(selector, image);
        return;
      }

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
        setAiLoading(false);
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

  const handleAiRecognition = async (selector: string, base64Image: string) => {
    setAiLoading(true);
    message.loading("正在请求 Gemini 识别...", 0);
    try {
      const result = await invoke<string>("call_gemini_service", {
        prompt:
          "Please recognize the text or answer in this captcha image. Return ONLY the result text/numbers, do not include any explanation.",
        image: base64Image,
      });
      message.destroy();
      message.success(`AI 识别结果: ${result}`);
      const insertCode = `\n// 🤖 AI 识别验证码\n// 目标: ${selector}\nconst captchaResult = "${result.trim()}";\nconsole.log("验证码识别结果:", captchaResult);\n// await page.fill('input[name="captcha"]', captchaResult);`;
      setCode((prev) => prev + insertCode);
      setActiveTab("code");
    } catch (e: any) {
      message.destroy();
      message.error("AI 识别失败: " + e);
    } finally {
      setAiLoading(false);
      isPickingCaptcha.current = false;
    }
  };

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
            intercepts: interceptRules.filter((r) => r.enabled),
            // 🔥🔥🔥 传递自定义脚本 🔥🔥🔥
            customScripts: customScripts
              .filter((s) => s.enabled)
              .map((s) => s.code),
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

  // 拦截规则 CRUD
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

  // 🔥🔥🔥 自定义脚本 CRUD 🔥🔥🔥
  const addScript = () => {
    setCurrentScript({
      id: Date.now().toString(),
      name: `Script ${customScripts.length + 1}`,
      code: '// 在此输入代码，将在页面加载前(document-start)执行\n// 例如: window.myVar = 123;\nconsole.log("My Custom Script Injected!");',
      enabled: true,
    });
    setIsScriptModalOpen(true);
  };
  const saveScript = () => {
    const newScripts = [...customScripts];
    const idx = newScripts.findIndex((s) => s.id === currentScript.id);
    if (idx > -1) {
      newScripts[idx] = currentScript;
    } else {
      newScripts.push(currentScript);
    }
    setCustomScripts(newScripts);
    localStorage.setItem("weblab_custom_scripts", JSON.stringify(newScripts));
    setIsScriptModalOpen(false);
  };
  const deleteScript = (id: string) => {
    const newScripts = customScripts.filter((s) => s.id !== id);
    setCustomScripts(newScripts);
    localStorage.setItem("weblab_custom_scripts", JSON.stringify(newScripts));
  };
  const editScript = (script: CustomScript) => {
    setCurrentScript(script);
    setIsScriptModalOpen(true);
  };

  const startInspector = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器");
      return;
    }
    isPickingCaptcha.current = false;
    await invoke("send_web_command", { action: "toggle_inspector", data: {} });
    message.loading("已进入拾取模式，请点击元素...", 1);
  };

  const startCaptchaInspector = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器");
      return;
    }
    isPickingCaptcha.current = true;
    await invoke("send_web_command", { action: "toggle_inspector", data: {} });
    message.loading("请点击【验证码图片】进行识别...", 2);
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

      <Collapse defaultActiveKey={["hooks"]} ghost size="small">
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

        {/* 🔥🔥🔥 新增：自定义脚本工坊 🔥🔥🔥 */}
        <Panel
          header={
            <span>
              <UserAddOutlined /> 我的脚本工坊
            </span>
          }
          key="scripts"
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <Button
              type="dashed"
              icon={<FileAddOutlined />}
              block
              onClick={addScript}
            >
              新建脚本
            </Button>
            <List
              size="small"
              dataSource={customScripts}
              renderItem={(item) => (
                <List.Item
                  actions={[
                    <EditOutlined
                      onClick={() => editScript(item)}
                      style={{ color: "#1890ff" }}
                    />,
                    <DeleteOutlined
                      onClick={() => deleteScript(item.id)}
                      style={{ color: "#ff4d4f" }}
                    />,
                    <Switch
                      size="small"
                      checked={item.enabled}
                      onChange={(v) => {
                        const newScripts = customScripts.map((s) =>
                          s.id === item.id ? { ...s, enabled: v } : s
                        );
                        setCustomScripts(newScripts);
                        localStorage.setItem(
                          "weblab_custom_scripts",
                          JSON.stringify(newScripts)
                        );
                      }}
                    />,
                  ]}
                >
                  <div style={{ width: "100%", overflow: "hidden" }}>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>
                      {item.name}
                    </div>
                    <div style={{ fontSize: 10, color: "#999" }}>
                      {item.code.length > 30
                        ? item.code.substring(0, 30) + "..."
                        : item.code}
                    </div>
                  </div>
                </List.Item>
              )}
            />
          </div>
        </Panel>

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
            <Button
              icon={<EyeOutlined />}
              onClick={startInspector}
              disabled={!isRunning || aiLoading}
            >
              拾取
            </Button>
            <Button
              type="dashed"
              icon={<RobotOutlined />}
              style={{ color: "#722ed1", borderColor: "#722ed1" }}
              onClick={startCaptchaInspector}
              loading={aiLoading}
              disabled={!isRunning}
            >
              AI 验证码
            </Button>
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

      {/* 🔥🔥🔥 新增：脚本编辑弹窗 🔥🔥🔥 */}
      <Modal
        title="编辑自定义脚本"
        open={isScriptModalOpen}
        onOk={saveScript}
        onCancel={() => setIsScriptModalOpen(false)}
        width={800}
        styles={{ body: { height: "500px" } }}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            height: "100%",
            gap: 10,
          }}
        >
          <Input
            addonBefore="脚本名称"
            value={currentScript.name}
            onChange={(e) =>
              setCurrentScript({ ...currentScript, name: e.target.value })
            }
          />
          <div style={{ flex: 1, border: "1px solid #d9d9d9" }}>
            <Editor
              height="100%"
              defaultLanguage="javascript"
              value={currentScript.code}
              onChange={(v) =>
                setCurrentScript({ ...currentScript, code: v || "" })
              }
              theme="vs-light"
              options={{ minimap: { enabled: false }, fontSize: 14 }}
            />
          </div>
          <div style={{ fontSize: 12, color: "#999" }}>
            * 此代码将在浏览器环境(Page Context)中执行，可以访问 window,
            document 等对象。
          </div>
        </div>
      </Modal>
    </Layout>
  );
};

export default WebLab;
