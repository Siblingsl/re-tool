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
  Spin,
  Segmented,
  Dropdown,
  MenuProps,
  Tag,
  Radio, // 🔥 新增组件
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
  ToolOutlined,
  ArrowRightOutlined,
  DownOutlined,
  ExperimentOutlined,
  ClockCircleOutlined,
  QuestionCircleOutlined,
  ClusterOutlined,
  DeploymentUnitOutlined,
  ChromeOutlined, // 🔥 新增图标
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
  action: "Abort" | "MockBody" | "AST_Transform";
  payload: string;
}

// 🔥🔥🔥 更新：增加 timing 字段 🔥🔥🔥
interface CustomScript {
  id: string;
  name: string;
  code: string;
  enabled: boolean;
  timing: "start" | "load"; // start=加载前, load=加载后
}

const WebLab: React.FC = () => {
  const [logs, setLogs] = useState<string>("");
  const [url, setUrl] = useState("https://www.whoer.net");
  const [config, setConfig] = useState({
    hooks: ["json_hook", "rpc_inject"],
  });



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

  const [customScripts, setCustomScripts] = useState<CustomScript[]>([]);
  const [isScriptModalOpen, setIsScriptModalOpen] = useState(false);
  // 🔥🔥🔥 更新默认值 🔥🔥🔥
  const [currentScript, setCurrentScript] = useState<CustomScript>({
    id: "",
    name: "New Script",
    code: "",
    enabled: true,
    timing: "start",
  });

  const [engineStatus, setEngineStatus] = useState("Stopped");
  const [activeTab, setActiveTab] = useState<string | number>("code");
  const [code, setCode] = useState(
    `/**\n * ✨ Playwright 自动化脚本编辑器\n */\n\ntry {\n  console.log(">>> 开始执行...");\n  const title = await page.title();\n  console.log(\`页面标题: \${title}\`);\n  return "Success";\n} catch (err) {\n  console.error(err.message);\n}`
  );

  const [isAstModalOpen, setIsAstModalOpen] = useState(false);
  const [astSource, setAstSource] = useState(
    "// 在此粘贴混淆代码\nvar _0x5a2b = ['\\x68\\x65\\x6c\\x6c\\x6f', 'world'];\nconsole['log'](_0x5a2b[0] + ' ' + _0x5a2b[1]);"
  );
  const [astResult, setAstResult] = useState("");
  const [astLoading, setAstLoading] = useState(false);

  const isManuallyStopping = useRef(false);
  const isPickingCaptcha = useRef(false);
  const [aiLoading, setAiLoading] = useState(false);

  const isRunning =
    engineStatus.includes("Launch") ||
    engineStatus.includes("Running") ||
    engineStatus.includes("Launched");

  useEffect(() => {
    const savedScripts = localStorage.getItem("weblab_custom_scripts");
    if (savedScripts) {
      try {
        // 兼容旧数据，如果没有 timing 默认为 start
        const parsed = JSON.parse(savedScripts).map((s: any) => ({
          ...s,
          timing: s.timing || "start",
        }));
        setCustomScripts(parsed);
      } catch (e) { }
    }
  }, []);

  useEffect(() => {
    const unlisten = listen("weblab-event", (event: any) => {
      const { type, payload } = event.payload;

      if (type === "ast_result") {
        setAstResult(payload.code);
        setAstLoading(false);
        message.success(`还原完成，耗时 ${payload.cost}ms`);
        return;
      }

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
        setAstLoading(false);
        const time = new Date().toLocaleTimeString();
        setLogs((prev) => prev + `\n[${time}] [ERROR] ${payload}`);
        return;
      }
      if (type === "rpc_log") {
        const time = new Date().toLocaleTimeString();
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
            browserType: "chromium",
            headless: false,
            hooks: config.hooks,
            intercepts: interceptRules.filter((r) => r.enabled),
            // 🔥🔥🔥 升级：传递包含 timing 的完整对象，而不仅仅是 code 字符串 🔥🔥🔥
            customScripts: customScripts
              .filter((s) => s.enabled)
              .map((s) => ({
                code: s.code,
                timing: s.timing || "start",
              })),
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
    try {
      await invoke("stop_web_engine");
      setTimeout(() => {
        isManuallyStopping.current = false;
      }, 1000);
    } catch (e) {
      console.error(e);
    }
  };



  const runEval = async () => {
    if (!isRunning) {
      message.warning("请先启动浏览器");
      return;
    }
    await invoke("send_web_command", { action: "eval", data: code });
    setActiveTab("console");
  };

  const runAstDeobfuscate = async () => {
    if (!astSource.trim()) {
      message.warning("请先输入需要还原的代码");
      return;
    }
    setAstLoading(true);
    try {
      if (engineStatus === "Stopped") {
        await invoke("start_web_engine");
        await new Promise((r) => setTimeout(r, 500));
      }
      await invoke("send_web_command", {
        action: "ast_deobfuscate",
        data: { code: astSource },
      });
    } catch (e) {
      message.error("AST 引擎调用失败: " + e);
      setAstLoading(false);
    }
  };

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

  const addScript = () => {
    setCurrentScript({
      id: Date.now().toString(),
      name: `Script ${customScripts.length + 1}`,
      code: '// 在此输入代码...\nconsole.log("Custom script injected!");',
      enabled: true,
      timing: "start",
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

  const toolMenuItems: MenuProps["items"] = [
    {
      key: "inspector",
      label: "拾取网页元素",
      icon: <EyeOutlined />,
      disabled: !isRunning || aiLoading,
      onClick: startInspector,
    },
    {
      key: "captcha",
      label: aiLoading ? "AI 识别中..." : "AI 验证码识别",
      icon: aiLoading ? <Spin size="small" /> : <RobotOutlined />,
      disabled: !isRunning,
      onClick: startCaptchaInspector,
    },
    { type: "divider" },
    {
      key: "ast",
      label: "AST 混淆还原",
      icon: <ToolOutlined />,
      onClick: () => setIsAstModalOpen(true),
    },
  ];

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

      <Collapse defaultActiveKey={["scripts"]} ghost size="small">

        <Panel
          header={
            <span>
              <ChromeOutlined /> CDP 协议注入
            </span>
          }
          key="cdp"
        ></Panel>

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
                  {" "}
                  <div style={{ width: "100%", overflow: "hidden" }}>
                    <div style={{ fontWeight: 500, fontSize: 13 }}>
                      {item.urlPattern}
                    </div>
                    <div style={{ fontSize: 12, color: "#999" }}>
                      {" "}
                      {item.action === "AST_Transform" ? (
                        <Tag color="geekblue">AST 还原</Tag>
                      ) : (
                        item.action
                      )}{" "}
                      • {item.resourceType}{" "}
                    </div>
                  </div>{" "}
                </List.Item>
              )}
            />
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
        <Panel header={<span>我的脚本工坊</span>} key="scripts">
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
                  {" "}
                  <div style={{ width: "100%", overflow: "hidden" }}>
                    {" "}
                    <div style={{ fontWeight: 500, fontSize: 13 }}>
                      {item.name}
                    </div>
                    <div style={{ fontSize: 10, color: "#999" }}>
                      <Tag
                        color={item.timing === "load" ? "green" : "blue"}
                        style={{ marginRight: 5, transform: "scale(0.8)" }}
                      >
                        {item.timing === "load" ? "Load后" : "加载前"}
                      </Tag>
                      {item.code.length > 20
                        ? item.code.substring(0, 20) + "..."
                        : item.code}
                    </div>{" "}
                  </div>{" "}
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
        {/* 顶部工具栏保持不变 */}
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
          <Segmented
            options={[
              { label: "代码编辑", value: "code", icon: <CodeOutlined /> },
              {
                label: "超级控制台",
                value: "console",
                icon: <ConsoleSqlOutlined />,
              },
            ]}
            value={activeTab}
            onChange={setActiveTab}
          />
          <Space>
            <Dropdown
              menu={{ items: toolMenuItems }}
              placement="bottomRight"
              arrow
            >
              <Button icon={<ExperimentOutlined />}>
                调试工具 <DownOutlined style={{ fontSize: 10 }} />
              </Button>
            </Dropdown>
            {activeTab === "code" ? (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={runEval}
                disabled={!isRunning}
              >
                运行片段
              </Button>
            ) : (
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

      {/* Intercept Modal 保持不变 */}
      <Modal
        title="编辑拦截规则"
        open={isRuleModalOpen}
        onOk={saveRule}
        onCancel={() => setIsRuleModalOpen(false)}
        width={600}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div>
            <Text>URL 匹配模式</Text>
            <Input
              value={currentRule.urlPattern}
              onChange={(e) =>
                setCurrentRule({ ...currentRule, urlPattern: e.target.value })
              }
              placeholder="例如: **/main.js"
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
                  { value: "AST_Transform", label: "AST 自动还原 (新)" },
                  { value: "MockBody", label: "修改响应体" },
                  { value: "Abort", label: "阻断请求" },
                ]}
                style={{ width: "100%" }}
              />
            </div>
          </div>
          {currentRule.action === "MockBody" && (
            <div>
              <Text>内容</Text>
              <TextArea
                rows={6}
                value={currentRule.payload}
                onChange={(e) =>
                  setCurrentRule({ ...currentRule, payload: e.target.value })
                }
              />
            </div>
          )}
          {currentRule.action === "AST_Transform" && (
            <div
              style={{
                background: "#e6f7ff",
                padding: "10px",
                borderRadius: "4px",
                border: "1px solid #91d5ff",
              }}
            >
              <Text type="secondary">
                <ToolOutlined /> 启用此选项后，后端将自动获取原始 JS
                代码，使用内置的 AST 引擎进行反混淆，然后返回给浏览器。
              </Text>
            </div>
          )}
        </div>
      </Modal>

      {/* 🔥🔥🔥 脚本编辑 Modal (新增 Timing 选项) 🔥🔥🔥 */}
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
            gap: 12,
          }}
        >
          <Input
            addonBefore="脚本名称"
            value={currentScript.name}
            onChange={(e) =>
              setCurrentScript({ ...currentScript, name: e.target.value })
            }
          />

          {/* 🔥 新增注入时机选择 🔥 */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Text>注入时机:</Text>
            <Radio.Group
              value={currentScript.timing || "start"}
              onChange={(e) =>
                setCurrentScript({ ...currentScript, timing: e.target.value })
              }
            >
              <Radio.Button value="start">
                <RocketOutlined /> 加载前 (Pre-load)
              </Radio.Button>
              <Radio.Button value="load">
                <ClockCircleOutlined /> 加载后 (Post-load)
              </Radio.Button>
            </Radio.Group>
            <Text type="secondary" style={{ fontSize: 12, marginLeft: 10 }}>
              {currentScript.timing === "load"
                ? "页面完全加载后执行 (适合自动化操作)"
                : "页面初始化时执行 (适合环境Hook)"}
            </Text>
          </div>

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
        </div>
      </Modal>

      {/* AST Modal 保持不变 */}
      <Modal
        title="🛠️ AST 混淆还原工具"
        open={isAstModalOpen}
        footer={null}
        onCancel={() => setIsAstModalOpen(false)}
        width="90%"
        styles={{ body: { height: "80vh", padding: 0 } }}
        destroyOnClose
      >
        <div style={{ display: "flex", height: "100%" }}>
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              borderRight: "1px solid #ddd",
            }}
          >
            <div
              style={{
                padding: "8px",
                background: "#fafafa",
                borderBottom: "1px solid #eee",
                fontWeight: "bold",
              }}
            >
              混淆代码 (Input)
            </div>
            <Editor
              height="100%"
              defaultLanguage="javascript"
              value={astSource}
              onChange={(v) => setAstSource(v || "")}
              theme="vs-light"
              options={{ minimap: { enabled: false } }}
            />
          </div>
          <div
            style={{
              width: 60,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "#f5f5f5",
              flexDirection: "column",
              gap: 16,
            }}
          >
            <Button
              type="primary"
              shape="circle"
              size="large"
              icon={<ArrowRightOutlined />}
              onClick={runAstDeobfuscate}
              loading={astLoading}
            />
          </div>
          <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
            <div
              style={{
                padding: "8px",
                background: "#fafafa",
                borderBottom: "1px solid #eee",
                fontWeight: "bold",
              }}
            >
              还原结果 (Output)
            </div>
            <Editor
              height="100%"
              defaultLanguage="javascript"
              value={astResult}
              options={{ readOnly: true, minimap: { enabled: false } }}
              theme="vs-light"
            />
          </div>
        </div>
      </Modal>
    </Layout>
  );
};

export default WebLab;
