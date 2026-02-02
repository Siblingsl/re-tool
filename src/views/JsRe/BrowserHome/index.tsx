import React, { useEffect, useState } from "react";
import {
    Input,
    Button,
    Space,
    Empty,
    Tag,
    Card,
    Tooltip,
    Dropdown,
    theme,
    Spin,
    Tabs,
    Badge,
    Descriptions,
    Divider,
    Statistic,
    Row,
    Col,
    message,
    Select,
    Radio,
    Switch,
    Form,
    Modal,
    AutoComplete
} from "antd";
import {
    PlusOutlined,
    GlobalOutlined,
    StopOutlined,
    PlayCircleOutlined,
    ChromeOutlined,
    FireOutlined,
    CodeOutlined,
    MonitorOutlined,
    RocketOutlined,
    SafetyCertificateOutlined,
    SendOutlined,
    PlusCircleOutlined,
    DeleteOutlined,
    EditOutlined,
    CloseOutlined,
    CloudServerOutlined,
    BugOutlined,
    ScanOutlined,
    DisconnectOutlined,
    FullscreenOutlined,
    MoreOutlined,
    CopyOutlined,
    SettingOutlined,
    ArrowLeftOutlined,
    SaveOutlined
} from "@ant-design/icons";
import { BrowserInstance } from "@/components/Sidebar";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event"; // ✅ Add listen import

/*
// ...

const BrowserHome: React.FC<BrowserHomeProps> = (props) => {
    // ...
    const [loadingMap, setLoadingMap] = useState<Record<string, boolean>>({});
    const [maximizedInstanceId, setMaximizedInstanceId] = useState<string | null>(null);
    const maximizedInstance = instances.find(i => i.id === maximizedInstanceId);

    // ✅ Real logs state
    const [logs, setLogs] = useState<Array<{ time: string, type: string, msg: string }>>([]);

    // ✅ Listen to backend events
    useEffect(() => {
        const unlistenPromise = listen("weblab-event", (event: any) => {
            const payload = event.payload;
            const time = new Date().toLocaleTimeString();

            // 1. Handle Logs
            if (payload.type === "console" || payload.type === "info" || payload.type === "error") {
                setLogs(prev => [...prev, { time, type: payload.type, msg: payload.payload || payload.msg }]);
            }

            // 2. Handle Errors (Toast)
            if (payload.type === "error") {
                message.error(payload.payload || payload.msg);
                // If launch failed, verify status
            }

            // 3. Handle Status Changes
            // The backend sends "status" events like "Browser Launched", "Browser Force Closed"
            // We can use this to sync specific instance status if we could identify which instance it belongs to.
            // Currently the Node engine is a SINGLE process singleton for simplicity. 
            // So if it stops, the currently active running instance stops.

            if (payload.type === "status") {
                setLogs(prev => [...prev, { time, type: "success", msg: payload.payload }]);

                const msg = payload.payload as string;
                if (msg.includes("Launched")) {
                    // Confirmed running
                } else if (msg.includes("Closed") || msg.includes("Stopped")) {
                    // Check if any instance is marked as running and stop it
                    // Since we don't know EXACTLY which ID (unless we store activePid in backend),
                    // we assume the `maximizedInstance` or `activeInstance` is the one.
                    // A better way is to rely on `onUpdateInstance` to stop the running one.
                    // For now, let's just log it. The UI button relies on optimistic updates, 
                    // but we should set `loadingMap` to false.
                }
            }
        });

        return () => {
            unlistenPromise.then(unlisten => unlisten());
        };
    }, []);
*/
// ================= Interfaces =================
interface InterceptRule {
    id: string;
    urlPattern: string;
    resourceType: string;
    action: "Block" | "Mock" | "Pass";
    mockBody?: string;
    enabled: boolean;
}

interface CdpCommand {
    method: string;
    params: string; // JSON string
}

interface HookItem {
    id: string;
    name: string;
    desc: string;
}

// Mock Hooks (Real scenario: fetch from ScriptLab/DB)
const AVAILABLE_HOOKS: HookItem[] = [
    { id: "json_hook", name: "JSON Hook", desc: "Intercept JSON.parse/stringify" },
    { id: "rpc_inject", name: "RPC Bridge", desc: "Enable external RPC control" },
    { id: "anti_detect", name: "Anti-Detection", desc: "Hide webdriver/headless properties" },
    { id: "log_all", name: "Global Logger", desc: "Log all global function calls" },
];

const CDP_METHODS = [
    // Page
    { value: "Page.navigate", label: "Page.navigate (跳转)" },
    { value: "Page.reload", label: "Page.reload (刷新)" },
    { value: "Page.captureScreenshot", label: "Page.captureScreenshot (截图)" },
    { value: "Page.printToPDF", label: "Page.printToPDF (打印PDF)" },
    { value: "Page.getFrameTree", label: "Page.getFrameTree (获取框架树)" },
    { value: "Page.enable", label: "Page.enable (启用Page域)" },
    // Runtime
    { value: "Runtime.evaluate", label: "Runtime.evaluate (执行JS)" },
    { value: "Runtime.callFunctionOn", label: "Runtime.callFunctionOn (调用函数)" },
    { value: "Runtime.getProperties", label: "Runtime.getProperties (获取属性)" },
    { value: "Runtime.enable", label: "Runtime.enable (启用Runtime域)" },
    // Network
    { value: "Network.enable", label: "Network.enable (启用网络监控)" },
    { value: "Network.setUserAgentOverride", label: "Network.setUserAgentOverride (修改UA)" },
    { value: "Network.clearBrowserCache", label: "Network.clearBrowserCache (清除缓存)" },
    { value: "Network.getCookies", label: "Network.getCookies (获取Cookies)" },
    { value: "Network.setCookie", label: "Network.setCookie (设置Cookie)" },
    { value: "Network.deleteCookies", label: "Network.deleteCookies (删除Cookie)" },
    // DOM
    { value: "DOM.getDocument", label: "DOM.getDocument (获取DOM树)" },
    { value: "DOM.querySelector", label: "DOM.querySelector (选择元素)" },
    { value: "DOM.querySelectorAll", label: "DOM.querySelectorAll (选择所有元素)" },
    { value: "DOM.setAttributeValue", label: "DOM.setAttributeValue (设置属性)" },
    // Emulation
    { value: "Emulation.setDeviceMetricsOverride", label: "Emulation.setDeviceMetricsOverride (设备模拟)" },
    { value: "Emulation.setTouchEmulationEnabled", label: "Emulation.setTouchEmulationEnabled (触摸模拟)" },
    { value: "Emulation.setGeolocationOverride", label: "Emulation.setGeolocationOverride (定位模拟)" },
    // Input
    { value: "Input.dispatchKeyEvent", label: "Input.dispatchKeyEvent (模拟按键)" },
    { value: "Input.dispatchMouseEvent", label: "Input.dispatchMouseEvent (模拟鼠标)" },
    { value: "Input.dispatchTouchEvent", label: "Input.dispatchTouchEvent (模拟触摸)" },
    // Target
    { value: "Target.createTarget", label: "Target.createTarget (新建标签页)" },
    { value: "Target.closeTarget", label: "Target.closeTarget (关闭标签页)" },
    // Browser
    { value: "Browser.getVersion", label: "Browser.getVersion (版本信息)" },
    { value: "Browser.close", label: "Browser.close (关闭浏览器)" },
    // ApplicationCache
    { value: "ApplicationCache.getFramesWithManifests", label: "ApplicationCache.getFramesWithManifests" },
];

interface BrowserHomeProps {
    instances: BrowserInstance[];
    activeInstance?: BrowserInstance; // 当前选中的实例（侧边栏联动）
    onUpdateInstance: (id: string, updates: Partial<BrowserInstance>) => void;
    onActivateInstance: (id: string) => void;
    // ✅ 新增：接收外部动作请求
    actionRequest?: { instanceId: string, action: "cdp" | "network" | "hooks" } | null;
    onClearActionRequest?: () => void;
    onAddInstance?: () => void;
    onRemoveInstance?: (id: string) => void;
}

const BrowserHome: React.FC<BrowserHomeProps> = (props) => {
    // Destructure instances and methods from props for easier use
    const {
        instances,
        activeInstance,
        onUpdateInstance,
        onActivateInstance,
        onAddInstance,
        onRemoveInstance
    } = props;
    const { token } = theme.useToken();
    const [loadingMap, setLoadingMap] = useState<Record<string, boolean>>({});
    const [maximizedInstanceId, setMaximizedInstanceId] = useState<string | null>(null);
    const maximizedInstance = instances.find(i => i.id === maximizedInstanceId);

    // ✅ Real logs state
    const [logs, setLogs] = useState<Array<{ time: string, type: string, msg: string }>>([]);

    // ✅ Listen to backend events
    useEffect(() => {
        const unlistenPromise = listen("weblab-event", (event: any) => {
            const payload = event.payload;
            const time = new Date().toLocaleTimeString();

            // 1. Handle Logs
            if (payload.type === "console" || payload.type === "info" || payload.type === "error") {
                setLogs(prev => [...prev, { time, type: payload.type, msg: payload.payload || payload.msg }]);
            }

            // 2. Handle Errors (Toast)
            if (payload.type === "error") {
                message.error(payload.payload || payload.msg);
            }

            // 3. Status
            if (payload.type === "status") {
                setLogs(prev => [...prev, { time, type: "success", msg: payload.payload }]);
            }
        });

        return () => {
            unlistenPromise.then(unlisten => unlisten());
        };
    }, []);

    const [activeTab, setActiveTab] = useState("logs");

    // ✅ 响应外部动作请求
    useEffect(() => {
        if (props.actionRequest) {
            const { instanceId, action } = props.actionRequest;
            // 1. 设置当前最大化的实例
            setMaximizedInstanceId(instanceId);
            // 2. 切换到对应 Tab
            setActiveTab(action);
            // 3. 清除请求，防止重复触发
            props.onClearActionRequest?.();
        }
    }, [props.actionRequest]);

    const [form] = Form.useForm();

    // ================= State for New Features =================
    // 1. CDP Console State
    const [cdpCmd, setCdpCmd] = useState<CdpCommand>({ method: "", params: "{}" });
    const [cdpLogsMap, setCdpLogsMap] = useState<Record<string, string[]>>({});

    // 2. Network Interception State
    const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
    const [editingRule, setEditingRule] = useState<InterceptRule | null>(null);

    // Helpers for Props-based State
    const currentIntercepts = (maximizedInstance?.intercepts || []) as InterceptRule[];
    const currentHookIds = (maximizedInstance?.hooks || ["json_hook"]) as string[];

    const addCdpLog = (msg: string) => {
        if (!maximizedInstanceId) return;
        setCdpLogsMap(prev => ({
            ...prev,
            [maximizedInstanceId]: [...(prev[maximizedInstanceId] || []), msg]
        }));
    };

    // ================= Handlers =================

    // --- CDP Handlers ---
    const handleSendCdp = async () => {
        if (!maximizedInstanceId) return;
        if (!cdpCmd.method) {
            message.warning("请输入 Method (e.g. Page.navigate)");
            return;
        }
        try {
            const paramsObj = JSON.parse(cdpCmd.params || "{}");
            addCdpLog(`> ${cdpCmd.method} ${JSON.stringify(paramsObj)}`);

            await invoke("send_web_command", {
                action: "cdp",
                data: {
                    method: cdpCmd.method,
                    params: paramsObj
                }
            });
            // 模拟回显 (实际应通过事件监听获取结果)
            // addCdpLog(`< (Pending response...)`);
        } catch (e: any) {
            message.error("JSON 格式错误: " + e.message);
        }
    };

    // --- Network Interception Handlers ---
    const handleSaveRule = (values: any) => {
        const newRule: InterceptRule = {
            id: editingRule ? editingRule.id : Date.now().toString(),
            urlPattern: values.urlPattern,
            resourceType: values.resourceType,
            action: values.action,
            mockBody: values.mockBody,
            enabled: true,
        };

        let newRules = [];
        if (editingRule) {
            newRules = currentIntercepts.map(r => r.id === editingRule.id ? newRule : r);
        } else {
            newRules = [...currentIntercepts, newRule];
        }

        if (maximizedInstanceId) {
            onUpdateInstance(maximizedInstanceId, { intercepts: newRules });
            syncInterceptsToBackend(newRules); // Sync effectively
        }
        setIsRuleModalOpen(false);
        setEditingRule(null);
    };

    const toggleRule = (id: string, checked: boolean) => {
        if (!maximizedInstanceId) return;
        const newRules = currentIntercepts.map(r => r.id === id ? { ...r, enabled: checked } : r);
        onUpdateInstance(maximizedInstanceId, { intercepts: newRules });
        syncInterceptsToBackend(newRules);
    };

    const deleteRule = (id: string) => {
        if (!maximizedInstanceId) return;
        const newRules = currentIntercepts.filter(r => r.id !== id);
        onUpdateInstance(maximizedInstanceId, { intercepts: newRules });
        syncInterceptsToBackend(newRules);
    };

    const syncInterceptsToBackend = async (rules: InterceptRule[]) => {
        if (!maximizedInstanceId) return;
        // Convert to format backend expects
        const backendRules = rules.filter(r => r.enabled).map(r => ({
            url_pattern: r.urlPattern,
            resource_type: r.resourceType,
            action: r.action,
            mock_body: r.mockBody
        }));
        try {
            await invoke("send_web_command", {
                action: "update_intercepts",
                data: { rules: backendRules }
            });
            message.success("拦截规则已同步");
        } catch (e) { }
    };

    // --- Hooks Handlers ---
    const toggleHook = (id: string, checked: boolean) => {
        if (!maximizedInstanceId) return;
        const newHookIds = checked
            ? [...currentHookIds, id]
            : currentHookIds.filter(x => x !== id);
        onUpdateInstance(maximizedInstanceId, { hooks: newHookIds });
    };

    const handleToggleStatus = async (instance: BrowserInstance) => {
        const isRunning = instance.status === "running";
        setLoadingMap(prev => ({ ...prev, [instance.id]: true }));

        try {
            if (isRunning) {
                // ============ 停止逻辑 ============
                await invoke("stop_web_engine");
                message.success("浏览器引擎已停止");
                // 停止时，同时将 RPC 状态重置为 false，确保状态一致性
                onUpdateInstance(instance.id, {
                    status: "stopped",
                    rpc: instance.rpc ? { ...instance.rpc, enabled: false } : undefined
                });
            } else {
                // ============ 启动逻辑 ============
                await invoke("start_web_engine");

                // 等待一小会儿确保引擎准备就绪
                // 实际情况应该监听 "status" 事件，但为了简化逻辑，这里先发启动指令
                setTimeout(async () => {
                    await invoke("send_web_command", {
                        action: "launch",
                        data: {
                            url: instance.url,
                            browserType: instance.type,
                            headless: instance.env?.headless ?? false,
                            stealth: instance.env?.stealth ?? true,
                            hooks: instance.hooks || ["json_hook", "rpc_inject"], // ✅ Use instance config
                            intercepts: (instance.intercepts || []).filter((r: any) => r.enabled).map((r: any) => ({ // ✅ Use instance config
                                url_pattern: r.urlPattern,
                                resource_type: r.resourceType,
                                action: r.action,
                                mock_body: r.mockBody
                            })),
                            customScripts: [],
                            rpcConfig: instance.rpc, // ✅ 传递 RPC 配置
                            risk: instance.risk,     // ✅ 传递风控配置
                            proxy: instance.proxy    // ✅ 传递代理配置
                        },
                    });

                    // 如果启用了 RPC，发送开启指令 (或者后端根据 launch 里的 rpcConfig 自动开启)
                    // 这里我们假设后端 launch 时不自动开 RPC，需要单独开？
                    // 或者我们可以在 launch data 里带上 rpcConfig，让 backend 自动处理。
                    // 暂时我们也手动发一次以防万一
                    if (instance.rpc?.enabled) {
                        await invoke("send_web_command", {
                            action: "rpc_ctrl",
                            data: { action: "start", port: instance.rpc.port },
                        });
                    }

                    message.success("浏览器实例已启动");
                    onUpdateInstance(instance.id, { status: "running" });
                    setLoadingMap(prev => ({ ...prev, [instance.id]: false }));
                }, 1000); // 增加延时确保 Stability

                // 注意：上面的 setTimeout 里的逻辑是异步的，这里如果直接 return，loading状态可能一直转或者立刻消失
                // 我们把 setLoadingMap 放进 setTimeout 里
                return;
            }
        } catch (e) {
            message.error("操作失败: " + e);
        }

        setLoadingMap(prev => ({ ...prev, [instance.id]: false }));
    };



    // ... (Rest of UI rendering remains exactly the same) ...
    // Since write_to_file overwrites, I must include the full file content.
    // Copying full UI logic from previous step.

    return (
        <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "#f0f2f5" }}>
            {/* 头部区域 */}
            <div
                style={{
                    height: 60,
                    padding: "0 24px",
                    backgroundColor: "#fff",
                    borderBottom: "1px solid #e8e8e8",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.03)",
                    zIndex: 10,
                    flexShrink: 0,
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                    {maximizedInstance ? (
                        <Button
                            type="text"
                            icon={<CloseOutlined />}
                            onClick={() => setMaximizedInstanceId(null)}
                            style={{ fontWeight: 600, fontSize: 15 }}
                        />
                    ) : (
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <GlobalOutlined style={{ fontSize: 22, color: token.colorPrimary }} />
                            <span style={{ fontSize: 20, fontWeight: 600, color: "#1f1f1f" }}>
                                浏览器管理
                            </span>
                        </div>
                    )}

                    {maximizedInstance && (
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                            <Divider type="vertical" style={{ height: 20 }} />
                            <span style={{ fontSize: 18, fontWeight: 600, color: "#1f1f1f" }}>{maximizedInstance.name}</span>
                            <Tag color={maximizedInstance.status === "running" ? "success" : "default"} style={{ border: "none", padding: "0 10px" }}>
                                <Badge status={maximizedInstance.status === "running" ? "processing" : "default"} text={maximizedInstance.status === "running" ? "运行中" : "已停止"} />
                            </Tag>
                        </div>
                    )}
                </div>

                <Space size={16}>
                    {!maximizedInstance && (
                        <>
                            <Input
                                prefix={<GlobalOutlined style={{ color: "#bfbfbf" }} />}
                                placeholder="搜索实例名称或 ID..."
                                style={{ width: 280, borderRadius: 8 }}
                                size="large"
                            />
                            <Button type="primary" size="large" icon={<PlusOutlined />} style={{ borderRadius: 8 }} onClick={() => { }}>
                                新建实例
                            </Button>
                        </>
                    )}
                </Space>
            </div>

            {/* 内容区域 */}
            <div style={{ flex: 1, padding: maximizedInstance ? 0 : 24, overflowY: maximizedInstance ? "hidden" : "auto", overflowX: "hidden" }}>

                {maximizedInstance ? (
                    // ================== 全屏：外部控制器视图 (现代化 UI) ==================
                    <div style={{ width: "100%", height: "100%", display: "flex", backgroundColor: "#f5f7fa" }}>

                        {/* 左侧：核心控制区 */}
                        <div style={{ width: 420, borderRight: "1px solid #e8e8e8", display: "flex", flexDirection: "column", backgroundColor: "#fff" }}>

                            {/* 1. 仪表盘头部 */}
                            <div style={{ padding: 32, paddingBottom: 24 }}>
                                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 32 }}>
                                    <div style={{
                                        width: 96, height: 96, borderRadius: 24,
                                        backgroundColor: "#fff",
                                        boxShadow: "0 6px 16px rgba(0,0,0,0.08)",
                                        display: "flex", justifyContent: "center", alignItems: "center",
                                        marginBottom: 16
                                    }}>
                                        {maximizedInstance.type === "chrome" ? (
                                            <ChromeOutlined style={{ fontSize: 56, color: "#4285F4" }} />
                                        ) : (
                                            <FireOutlined style={{ fontSize: 56, color: "#FF7139" }} />
                                        )}
                                    </div>
                                    <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, color: "#1f1f1f" }}>{maximizedInstance.name}</h2>
                                    <div style={{ color: "#8c8c8c", fontSize: 13, marginTop: 4, fontFamily: "monospace" }}>ID: {maximizedInstance.id}</div>
                                </div>

                                <Button
                                    type={maximizedInstance.status === "running" ? "default" : "primary"}
                                    danger={maximizedInstance.status === "running"}
                                    block
                                    size="large"
                                    style={{ height: 48, fontSize: 16, borderRadius: 8, fontWeight: 500 }}
                                    icon={maximizedInstance.status === "running" ? <StopOutlined /> : <PlayCircleOutlined />}
                                    loading={loadingMap[maximizedInstance.id]}
                                    onClick={() => handleToggleStatus(maximizedInstance)}
                                >
                                    {maximizedInstance.status === "running" ? "停止进程" : "启动浏览器实例"}
                                </Button>
                            </div>

                            <Divider style={{ margin: 0 }} />

                            {/* 2. 状态指标 */}
                            <div style={{ padding: 24 }}>
                                <div style={{ fontWeight: 600, marginBottom: 16, color: "#262626", fontSize: 15 }}>实时状态</div>
                                <Row gutter={[16, 16]}>
                                    <Col span={12}>
                                        <Card size="small" bordered={false} style={{ backgroundColor: "#f9f9f9", borderRadius: 8 }}>
                                            <Statistic
                                                title={<span style={{ fontSize: 12 }}>CDP 端口</span>}
                                                value={maximizedInstance.status === "running" ? 9222 : "-"}
                                                valueStyle={{ fontSize: 18, fontWeight: 600 }}
                                                prefix={<MonitorOutlined style={{ opacity: 0.5 }} />}
                                            />
                                        </Card>
                                    </Col>
                                    <Col span={12}>
                                        <Card size="small" bordered={false} style={{ backgroundColor: "#f9f9f9", borderRadius: 8 }}>
                                            <Statistic
                                                title={<span style={{ fontSize: 12 }}>进程 PID</span>}
                                                value={maximizedInstance.status === "running" ? 12456 : "-"}
                                                valueStyle={{ fontSize: 18, fontWeight: 600 }}
                                                prefix={<CloudServerOutlined style={{ opacity: 0.5 }} />}
                                            />
                                        </Card>
                                    </Col>
                                </Row>

                                <div style={{ marginTop: 16 }}>
                                    <Card size="small" bordered={false} style={{ backgroundColor: "#f9f9f9", borderRadius: 8 }}>
                                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                                            <span style={{ color: "#8c8c8c", fontSize: 12 }}>隐私保护 (Fingerprint)</span>
                                            {maximizedInstance.status === "running" && <SafetyCertificateOutlined style={{ color: "#52c41a" }} />}
                                        </div>
                                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                                            <Tag color="green" style={{ margin: 0 }}>UserAgent</Tag>
                                            <Tag color="green" style={{ margin: 0 }}>WebGL</Tag>
                                            <Tag color="green" style={{ margin: 0 }}>Canvas</Tag>
                                            <Tag color="green" style={{ margin: 0 }}>Audio</Tag>
                                        </div>
                                    </Card>
                                </div>
                            </div>

                            <Divider style={{ margin: 0 }} />

                            {/* 3. 快捷工具 */}
                            {/* <div style={{ padding: 24, flex: 1 }}>
                                <div style={{ fontWeight: 600, marginBottom: 16, color: "#262626", fontSize: 15 }}>开发工具</div>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                                    <Button icon={<BugOutlined />} disabled={maximizedInstance.status !== "running"} style={{ height: 40, borderRadius: 6 }}>DevTools</Button>
                                    <Button icon={<RocketOutlined />} disabled={maximizedInstance.status !== "running"} style={{ height: 40, borderRadius: 6 }}>注入脚本</Button>
                                    <Button icon={<ScanOutlined />} disabled={maximizedInstance.status !== "running"} style={{ height: 40, borderRadius: 6 }}>检测指纹</Button>
                                    <Button icon={<DisconnectOutlined />} disabled={maximizedInstance.status !== "running"} style={{ height: 40, borderRadius: 6 }}>断开连接</Button>
                                </div>
                            </div> */}
                        </div>

                        {/* 右侧：日志终端 (重制版) */}
                        <div style={{ flex: 1, backgroundColor: "#fafafa", display: "flex", flexDirection: "column", padding: 24 }}>
                            <Card
                                title={
                                    <Tabs
                                        activeKey={activeTab}
                                        onChange={setActiveTab}
                                        items={[
                                            { key: "logs", label: <span><CodeOutlined /> 运行日志</span> },
                                            { key: "network", label: <span><GlobalOutlined /> 请求拦截</span> },
                                            { key: "cdp", label: <span><MonitorOutlined /> CDP 控制台</span> },
                                            { key: "hooks", label: <span><RocketOutlined /> 注入 Hooks</span> }
                                        ]}
                                        size="small"
                                        style={{ marginBottom: -16 }}
                                        tabBarStyle={{ borderBottom: "none" }}
                                    />
                                }
                                bordered={false}
                                style={{
                                    flex: 1,
                                    display: "flex",
                                    flexDirection: "column",
                                    boxShadow: "0 4px 12px rgba(0,0,0,0.03)",
                                    borderRadius: 12
                                }}
                                bodyStyle={{ flex: 1, padding: 0, display: "flex", flexDirection: "column", minHeight: 0 }}
                            >
                                {/* Tab Content Render */}
                                <div style={{ flex: 1, height: "100%", overflow: "hidden", minHeight: 0, position: "relative" }}>

                                    {/* 1. 日志面板 */}
                                    {activeTab === "logs" && (
                                        <div style={{
                                            position: "absolute",
                                            top: 0,
                                            left: 0,
                                            right: 0,
                                            bottom: 0,
                                            padding: 20,
                                            backgroundColor: "#1e1e1e",
                                            overflowY: "auto",
                                            fontFamily: "'JetBrains Mono', monospace",
                                            fontSize: 13,
                                            display: "flex",
                                            flexDirection: "column",
                                            gap: 6
                                        }}>
                                            {maximizedInstance.status === "running" ? (
                                                logs.map((log, idx) => (
                                                    <div key={idx} style={{ display: "flex", lineHeight: 1.5 }}>
                                                        <span style={{ color: "#5c6370", marginRight: 16, minWidth: 80 }}>{log.time}</span>
                                                        <div style={{ flex: 1, wordBreak: "break-all" }}>
                                                            <span style={{ fontWeight: 600, marginRight: 12, color: log.type === "info" ? "#61afef" : log.type === "success" ? "#98c379" : "#fff" }}>
                                                                [{log.type.toUpperCase()}]
                                                            </span>
                                                            <span style={{ color: "#abb2bf" }}>{log.msg}</span>
                                                        </div>
                                                    </div>
                                                ))
                                            ) : <div style={{ color: "#666", textAlign: "center", marginTop: 40 }}>等待启动...</div>}
                                        </div>
                                    )}

                                    {/* 2. 网络拦截面板 */}
                                    {activeTab === "network" && (
                                        <div style={{ position: "absolute", inset: 0, padding: 20, overflowY: "auto" }}>
                                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
                                                <span style={{ color: "#666" }}>拦截并替换网络请求 (Glob Pattern)</span>
                                                <Button type="primary" size="small" icon={<PlusCircleOutlined />} onClick={() => { setEditingRule(null); setIsRuleModalOpen(true); form.resetFields(); }}>添加规则</Button>
                                            </div>

                                            {currentIntercepts.length === 0 ? (
                                                <Empty description="暂无拦截规则" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                                            ) : (
                                                <Space direction="vertical" style={{ width: "100%" }}>
                                                    {currentIntercepts.map(rule => (
                                                        <Card key={rule.id} size="small" type="inner" bodyStyle={{ padding: "12px 16px" }}>
                                                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                                                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                                                                    <Switch size="small" checked={rule.enabled} onChange={c => toggleRule(rule.id, c)} />
                                                                    <Tag color={rule.action === "Block" ? "red" : "blue"}>{rule.action}</Tag>
                                                                    <span style={{ fontWeight: 500 }}>{rule.urlPattern}</span>
                                                                    <Tag bordered={false}>{rule.resourceType}</Tag>
                                                                </div>
                                                                <Space>
                                                                    <Button type="text" size="small" icon={<EditOutlined />} onClick={() => { setEditingRule(rule); setIsRuleModalOpen(true); form.setFieldsValue(rule); }} />
                                                                    <Button type="text" danger size="small" icon={<DeleteOutlined />} onClick={() => deleteRule(rule.id)} />
                                                                </Space>
                                                            </div>
                                                        </Card>
                                                    ))}
                                                </Space>
                                            )}
                                        </div>
                                    )}

                                    {/* 3. CDP 控制台 */}
                                    {activeTab === "cdp" && (
                                        <div style={{ flex: 1, display: "flex", flexDirection: "column", height: "100%" }}>
                                            <div style={{ flex: 1, backgroundColor: "#1e1e1e", color: "#d4d4d4", padding: 12, overflowY: "auto", fontFamily: "monospace", fontSize: 12 }}>
                                                {(cdpLogsMap[maximizedInstanceId!] || []).map((l, i) => <div key={i} style={{ marginBottom: 4 }}>{l}</div>)}
                                            </div>
                                            <div style={{ padding: 12, backgroundColor: "#fff", borderTop: "1px solid #e8e8e8" }}>
                                                <Space.Compact style={{ width: "100%" }}>
                                                    <AutoComplete
                                                        style={{ width: "30%" }}
                                                        placeholder="Method (e.g. Page.reload)"
                                                        value={cdpCmd.method}
                                                        onChange={val => setCdpCmd(prev => ({ ...prev, method: val }))}
                                                        options={CDP_METHODS}
                                                        filterOption={(inputValue, option) =>
                                                            ((option?.value || "") as string).toUpperCase().includes(inputValue.toUpperCase())
                                                        }
                                                    />
                                                    <Input style={{ width: "60%" }} placeholder='Params JSON (e.g. {"ignoreCache": true})' value={cdpCmd.params} onChange={e => setCdpCmd(prev => ({ ...prev, params: e.target.value }))} />
                                                    <Button type="primary" icon={<SendOutlined />} onClick={handleSendCdp}>发送</Button>
                                                </Space.Compact>
                                            </div>
                                        </div>
                                    )}

                                    {/* 4. Hooks 选择 */}
                                    {activeTab === "hooks" && (
                                        <div style={{ flex: 1, padding: 24, overflowY: "auto" }}>
                                            <div style={{ marginBottom: 16, color: "#666" }}>
                                                <SafetyCertificateOutlined style={{ color: "orange", marginRight: 8 }} />
                                                选中的脚本将在浏览器环境初始化时 (document_start) 自动注入。
                                            </div>
                                            <Row gutter={[16, 16]}>
                                                {AVAILABLE_HOOKS.map(hook => (
                                                    <Col span={12} key={hook.id}>
                                                        <Card
                                                            hoverable
                                                            size="small"
                                                            onClick={() => toggleHook(hook.id, !currentHookIds.includes(hook.id))}
                                                            style={{
                                                                borderColor: currentHookIds.includes(hook.id) ? token.colorPrimary : "#f0f0f0",
                                                                backgroundColor: currentHookIds.includes(hook.id) ? "#f6ffed" : "#fff"
                                                            }}
                                                        >
                                                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                                                                <div>
                                                                    <div style={{ fontWeight: 600, marginBottom: 4 }}>{hook.name}</div>
                                                                    <div style={{ fontSize: 12, color: "#999" }}>{hook.desc}</div>
                                                                </div>
                                                                <Switch size="small" checked={currentHookIds.includes(hook.id)} />
                                                            </div>
                                                        </Card>
                                                    </Col>
                                                ))}
                                            </Row>
                                        </div>
                                    )}
                                </div>
                            </Card>

                            {/* ================== Tab Views Components (Hidden/Visible logic) ================== */}
                            {/* NOTE: In a real app we'd use local state to switch content based on active tab. 
                                For simplicity, I'm just replacing the *content area* logic above or finding a way to inject... 
                                OR, improved: We can just render the content based on current active tab.
                             */}
                            {/* Wait, the Tabs above only control visual state but I didn't bind `onChange`. 
                                Let's fix that. I need a state for `activeTabKey`. 
                             */}
                            {/* Modal for Network Rules */}
                            <Modal
                                title={editingRule ? "编辑规则" : "添加拦截规则"}
                                open={isRuleModalOpen}
                                onOk={() => form.submit()}
                                onCancel={() => setIsRuleModalOpen(false)}
                            >
                                <Form form={form} onFinish={handleSaveRule} layout="vertical" initialValues={{ resourceType: "All", action: "Block" }}>
                                    <Form.Item name="urlPattern" label="URL Pattern (支持通配符 *)" rules={[{ required: true }]}>
                                        <Input placeholder="Example: *google-analytics.com*" />
                                    </Form.Item>
                                    <Form.Item name="resourceType" label="资源类型">
                                        <Select>
                                            <Select.Option value="All">All Types</Select.Option>
                                            <Select.Option value="Script">Script</Select.Option>
                                            <Select.Option value="XHR">XHR/Fetch</Select.Option>
                                            <Select.Option value="Image">Image</Select.Option>
                                        </Select>
                                    </Form.Item>
                                    <Form.Item name="action" label="动作">
                                        <Radio.Group buttonStyle="solid">
                                            <Radio.Button value="Block">Block</Radio.Button>
                                            <Radio.Button value="Mock">Mock Response</Radio.Button>
                                            <Radio.Button value="Pass">Pass (Allow)</Radio.Button>
                                        </Radio.Group>
                                    </Form.Item>
                                    <Form.Item noStyle shouldUpdate={(prev, curr) => prev.action !== curr.action}>
                                        {({ getFieldValue }) =>
                                            getFieldValue("action") === "Mock" && (
                                                <Form.Item name="mockBody" label="Mock Response Body">
                                                    <Input.TextArea rows={4} placeholder='{"status": "ok"}' />
                                                </Form.Item>
                                            )
                                        }
                                    </Form.Item>
                                </Form>
                            </Modal>
                        </div>
                    </div>
                ) : (
                    // ================== 网格视图 (保持不变) ==================
                    instances.length === 0 ? (
                        <div style={{ height: "100%", display: "flex", justifyContent: "center", alignItems: "center", flexDirection: "column" }}>
                            <Empty description="暂无浏览器实例"
                                image={Empty.PRESENTED_IMAGE_SIMPLE}
                                style={{ color: "#999" }}
                            />
                            <div style={{ color: "#999", marginTop: 12 }}>请在左侧侧边栏添加实例</div>
                        </div>
                    ) : (
                        <div
                            style={{
                                display: "grid",
                                gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
                                gap: 24,
                                alignContent: "start"
                            }}
                        >
                            {instances.map(inst => (
                                <Card
                                    key={inst.id}
                                    hoverable
                                    style={{
                                        borderRadius: 12,
                                        border: maximizedInstanceId === inst.id
                                            ? `2px solid ${token.colorPrimary}`
                                            : "1px solid #e8e8e8",
                                        overflow: "hidden",
                                        transition: "all 0.2s ease-in-out",
                                        boxShadow: "0 2px 8px rgba(0,0,0,0.04)"
                                    }}
                                    styles={{ body: { padding: 0 } }}
                                    onClick={() => onActivateInstance(inst.id)}
                                    onDoubleClick={() => setMaximizedInstanceId(inst.id)}
                                >
                                    {/* 卡片头部 */}
                                    <div style={{
                                        padding: "16px 20px",
                                        borderBottom: "1px solid #f0f0f0",
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                        backgroundColor: "#fff"
                                    }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                            {inst.type === "chrome" ? (
                                                <ChromeOutlined style={{ fontSize: 22, color: "#4285F4" }} />
                                            ) : (
                                                <FireOutlined style={{ fontSize: 22, color: "#FF7139" }} />
                                            )}
                                            <span style={{ fontWeight: 600, fontSize: 16, color: "#1f1f1f" }}>{inst.name}</span>
                                        </div>
                                        <Tag bordered={false} color={inst.status === "running" ? "success" : "default"} style={{ margin: 0 }}>
                                            {inst.status === "running" ? "运行中" : "已停止"}
                                        </Tag>
                                    </div>

                                    {/* 卡片主体 */}
                                    <div style={{
                                        padding: 24,
                                        height: 160,
                                        display: "flex",
                                        flexDirection: "column",
                                        justifyContent: "center",
                                        alignItems: "center",
                                        gap: 16,
                                        backgroundColor: "#fafafa"
                                    }}>
                                        {inst.status === "running" ? (
                                            <>
                                                <div style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, backgroundColor: "#fff", padding: "8px 12px", borderRadius: 8, border: "1px solid #f0f0f0", boxShadow: "0 2px 4px rgba(0,0,0,0.02)" }}>
                                                    <div style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#ff5f57" }}></div>
                                                    <div style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#ffbd2e" }}></div>
                                                    <div style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#28c940" }}></div>
                                                    <div style={{ flex: 1, fontSize: 12, color: "#8c8c8c", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", marginLeft: 8 }}>
                                                        {inst.url || "about:blank"}
                                                    </div>
                                                </div>
                                                <Button
                                                    type="text"
                                                    icon={<FullscreenOutlined />}
                                                    style={{ color: "#595959", fontSize: 13 }}
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        setMaximizedInstanceId(inst.id);
                                                    }}
                                                >
                                                    进入控制台
                                                </Button>
                                            </>
                                        ) : (
                                            <div style={{ color: "#bfbfbf", display: "flex", flexDirection: "column", alignItems: "center" }}>
                                                <StopOutlined style={{ fontSize: 40, marginBottom: 12, opacity: 0.5 }} />
                                                <span style={{ fontSize: 13 }}>等待启动</span>
                                            </div>
                                        )}
                                    </div>

                                    {/* 卡片底部 */}
                                    <div style={{
                                        padding: "12px 20px",
                                        borderTop: "1px solid #f0f0f0",
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                        backgroundColor: "#fff"
                                    }}>
                                        <Space size={8}>
                                            <Tooltip title={inst.status === "running" ? "停止" : "启动"}>
                                                <Button
                                                    size="small"
                                                    shape="circle"
                                                    loading={loadingMap[inst.id]}
                                                    icon={inst.status === "running" ? <StopOutlined style={{ color: "#ff4d4f" }} /> : <PlayCircleOutlined style={{ color: "#52c41a" }} />}
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleToggleStatus(inst);
                                                    }}
                                                />
                                            </Tooltip>
                                            <Tooltip title="指纹配置">
                                                <Button size="small" shape="circle" icon={<ScanOutlined />} />
                                            </Tooltip>
                                        </Space>

                                        <Dropdown menu={{
                                            items: [
                                                { key: 'details', label: '详细信息', icon: <MoreOutlined /> },
                                                { key: 'copy', label: '复制配置', icon: <CopyOutlined /> },
                                                { type: 'divider' },
                                                { key: 'delete', label: '删除实例', icon: <DeleteOutlined />, danger: true }
                                            ]
                                        }}>
                                            <Button size="small" type="text" icon={<SettingOutlined />} onClick={e => e.stopPropagation()} />
                                        </Dropdown>
                                    </div>
                                </Card>
                            ))}
                        </div>
                    )
                )}
            </div>
        </div>
    );
};

export default BrowserHome;
