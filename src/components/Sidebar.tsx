import React, { useState, useEffect } from "react";
import { useLiveQuery } from "dexie-react-hooks";
import {
  AppleFilled,
  AndroidFilled,
  CodeOutlined,
  FileZipOutlined,
  BugOutlined,
  ThunderboltFilled,
  CopyOutlined,
  ReloadOutlined,
  DisconnectOutlined,
  MoreOutlined,
  DesktopOutlined,
  AppstoreAddOutlined,
  PlusCircleOutlined,
  EditOutlined,
  WifiOutlined,
  ToolOutlined,
  AndroidOutlined,
  CloudDownloadOutlined,
  StopOutlined,
  PlayCircleOutlined,
  UnlockOutlined,
  ExperimentOutlined,
  FolderOpenOutlined,
  BuildOutlined,
  CoffeeOutlined,
  GatewayOutlined,
  CompassOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  AppstoreOutlined,
  RobotOutlined,
  PlusOutlined,
  MessageOutlined,
  DeleteOutlined,
  SettingOutlined,
  LaptopOutlined,
  ApiOutlined,
  InfoCircleOutlined,
  BgColorsOutlined,
  CheckCircleFilled,
  ExclamationCircleFilled,
  RocketOutlined, // 🔥 魔改版 Frida 图标
  DownOutlined,
  ChromeOutlined,
  FireOutlined,
  ScanOutlined,
  ThunderboltOutlined, // For AST
  FileTextOutlined, // For Scripts
  SafetyCertificateOutlined,
  EyeOutlined, // For Captcha
} from "@ant-design/icons";

import {
  Avatar,
  Button,
  Dropdown,
  Form,
  Input,
  List,
  MenuProps,
  message,
  Modal,
  Select,
  Tag,
  theme,
  Tooltip,
  Segmented,
  Divider,
  Switch,
  Radio,
  Table,
  Space,
  Popconfirm,
  Checkbox,
} from "antd";
import { Device, ViewMode } from "../types";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { db } from "@/db";

interface SidebarProps {
  currentView: ViewMode;
  onViewChange: (view: ViewMode) => void;
  devices: Device[];
  selectedDeviceId: string;
  onDeviceSelect: (id: string) => void;
  onRefresh?: () => void;
  deviceAliases: Record<string, string>;
  onRenameDevice: (id: string, name: string) => void;

  // ✅ 新增：浏览器实例状态提升
  browserInstances: BrowserInstance[];
  onAddBrowserInstance: () => void;
  onRemoveBrowserInstance: (id: string) => void;
  onUpdateBrowserInstance: (id: string, updates: Partial<BrowserInstance>) => void;
  // ✅ 新增：选中状态联动
  activeBrowserInstanceId?: string;
  onSelectBrowserInstance: (id: string) => void;
  // ✅ 新增：打开实例特定功能
  onOpenInstanceAction?: (id: string, action: "cdp" | "network" | "hooks") => void;
}

interface ToolItem {
  id: string;
  name: string;
  desc: string;
  icon: React.ReactNode;
  hasVersions?: boolean;
  hasArch?: boolean;
}

export interface BrowserFingerprint {
  userAgent?: string;
  canvasNoise: boolean;
  webglNoise: boolean;
  timezone: string;
  locale: string;
}

export interface EnvConfig {
  stealth: boolean;
  headless: boolean;
}

export interface RpcConfig {
  enabled: boolean;
  port: number;
}

export interface RiskConfig {
  bypassCF: boolean;
  bypassAkamai: boolean;
  bypassRuishu: boolean;
}

export interface ProxyConfig {
  mode: "direct" | "http" | "https" | "socks5";
  host?: string;
  port?: number;
  username?: string;
  password?: string;
}

export interface BrowserInstance {
  id: string;
  name: string;
  type: "chrome" | "firefox";
  status: "running" | "stopped";
  url: string;
  fingerprint: BrowserFingerprint;
  rpc?: RpcConfig;
  env?: EnvConfig;
  hooks?: string[];
  intercepts?: any[];
  risk?: RiskConfig;
  proxy?: ProxyConfig; // ✅ 新增代理配置
}

interface ChatSession {
  id: string;
  title: string;
  date: string;
  lastUpdated: number;
}

const toolsList: ToolItem[] = [
  {
    id: "frida",
    name: "Frida Server",
    desc: "动态插桩工具服务端 (需 Root)",
    icon: <BugOutlined style={{ color: "#ff5722" }} />,
    hasVersions: true,
    hasArch: true,
  },
  {
    id: "adb_keyboard",
    name: "ADB Keyboard",
    desc: "支持电脑输入中文",
    icon: <AndroidOutlined style={{ color: "#87d068" }} />,
    hasVersions: false,
    hasArch: false,
  },
  {
    id: "mt_manager",
    name: "MT 管理器",
    desc: "文件管理与 APK 修改神器",
    icon: <FileZipOutlined style={{ color: "#1890ff" }} />,
    hasVersions: false,
    hasArch: false,
  },
];

const DEFAULT_FRIDA_VERSIONS = ["16.2.1", "16.1.4", "15.2.2", "14.2.18"];

const ARCH_OPTIONS = [
  { label: "arm64-v8a (64位)", value: "arm64" },
  { label: "armeabi-v7a (32位)", value: "arm" },
  { label: "x86_64 (模拟器)", value: "x86_64" },
  { label: "x86 (模拟器)", value: "x86" },
];

const DEFAULT_PROVIDERS = [
  { value: "openai", label: "OpenAI (GPT-4o / GPT-3.5)" },
  { value: "deepseek", label: "DeepSeek (深度求索)" },
  { value: "anthropic", label: "Anthropic (Claude 3.5)" },
  { value: "custom", label: "自定义 / 本地模型 (Ollama)" },
];

const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onViewChange,
  devices,
  selectedDeviceId,
  onDeviceSelect,
  onRefresh,
  deviceAliases,
  onRenameDevice,
  // ✅ Props 解构
  browserInstances,
  onAddBrowserInstance,
  onRemoveBrowserInstance,
  onUpdateBrowserInstance,
  // ✅ 新增
  activeBrowserInstanceId,
  onSelectBrowserInstance,
  onOpenInstanceAction,
}) => {
  type SettingTab = "general" | "env" | "tools" | "about" | "ai";
  const { token } = theme.useToken();
  const [collapsed, setCollapsed] = useState(false);

  const [sidebarMode, setSidebarMode] = useState<"android" | "js" | "ai">("android");
  const [activeSettingTab, setActiveSettingTab] =
    useState<SettingTab>("general");
  const [isAddModelModalOpen, setIsAddModelModalOpen] = useState(false);

  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const [ipAddress, setIpAddress] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [isRenameModalOpen, setIsRenameModalOpen] = useState(false);
  const [currentRenameDevice, setCurrentRenameDevice] = useState<Device | null>(
    null
  );
  const [newDeviceName, setNewDeviceName] = useState("");
  const [isToolModalOpen, setIsToolModalOpen] = useState(false);
  const [currentToolDevice, setCurrentToolDevice] = useState<Device | null>(
    null
  );
  const [fridaVersions, setFridaVersions] = useState<string[]>(
    DEFAULT_FRIDA_VERSIONS
  );
  const [loadingVersions, setLoadingVersions] = useState(false);
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [installConfig, setInstallConfig] = useState({
    version: DEFAULT_FRIDA_VERSIONS[0],
    arch: "arm64",
  });
  const [fridaStatusMap, setFridaStatusMap] = useState<Record<string, boolean>>(
    {}
  );
  const [useStealthMode, setUseStealthMode] = useState(false); // 🔥 Stealth Mode State
  const [moddedFridaStatusMap, setModdedFridaStatusMap] = useState<Record<string, boolean>>(
    {}
  ); // 🔥 魔改版 Frida 状态追踪
  const [rootStatusMap, setRootStatusMap] = useState<Record<string, boolean>>(
    {}
  );


  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const [isAiRenameModalOpen, setIsAiRenameModalOpen] = useState(false);
  const [currentEditingSession, setCurrentEditingSession] =
    useState<ChatSession | null>(null);
  const [newTitle, setNewTitle] = useState("");

  // ✅ 新增：管理服务商列表的状态
  const [providers, setProviders] = useState(DEFAULT_PROVIDERS);

  // ✅ 新增：用于获取添加模型表单数据的 Form 实例
  const [addModelForm] = Form.useForm();

  const chatList =
    useLiveQuery(
      () => db.chatSessions.orderBy("lastUpdated").reverse().toArray(),
      []
    ) || [];

  const [isAiConfigModalOpen, setIsAiConfigModalOpen] = useState(false);
  const [editingConfig, setEditingConfig] = useState<any>(null); // 当前正在编辑的配置
  const [aiConfigForm] = Form.useForm(); // 表单实例
  const aiConfigs = useLiveQuery(() => db.aiConfigs.toArray(), []) || [];

  // ✅ 新增：工作区路径状态
  const [workspacePath, setWorkspacePath] = useState<string>("");

  // =========================================================
  // ⚠️ 状态提升：本地 browserInstances 及 CRUD 逻辑已移除
  // 改为使用 props: browserInstances, onAddBrowserInstance...
  // =========================================================

  // ✅ 指纹配置状态
  const [isFingerprintModalOpen, setIsFingerprintModalOpen] = useState(false);
  const [editingFingerprintId, setEditingFingerprintId] = useState<string | null>(null);
  const [fingerprintForm] = Form.useForm();

  const handleOpenFingerprint = (instance: BrowserInstance) => {
    setEditingFingerprintId(instance.id);
    fingerprintForm.setFieldsValue(instance.fingerprint);
    setIsFingerprintModalOpen(true);
  };

  const handleSaveFingerprint = async () => {
    try {
      const values = await fingerprintForm.validateFields();
      if (editingFingerprintId) {
        onUpdateBrowserInstance(editingFingerprintId, { fingerprint: values }); // ✅ 使用 Prop
        setIsFingerprintModalOpen(false);
        message.success("指纹配置已更新");
      }
    } catch (e) {
      // Form validation failed
    }
  };

  // ✅ 环境配置状态
  const [isEnvModalOpen, setIsEnvModalOpen] = useState(false);
  const [editingEnvInstanceId, setEditingEnvInstanceId] = useState<string | null>(null);

  // ✅ 代理配置状态
  const [isProxyModalOpen, setIsProxyModalOpen] = useState(false);
  const [editingProxyInstanceId, setEditingProxyInstanceId] = useState<string | null>(null);
  const [proxyForm] = Form.useForm();

  const handleOpenProxyModal = (instance: BrowserInstance) => {
    setEditingProxyInstanceId(instance.id);
    const proxy = instance.proxy || { mode: "direct" };
    proxyForm.setFieldsValue(proxy);
    setIsProxyModalOpen(true);
  };

  const handleSaveProxyConfig = async () => {
    try {
      const values = await proxyForm.validateFields();
      if (editingProxyInstanceId) {
        onUpdateBrowserInstance(editingProxyInstanceId, { proxy: values });
        setIsProxyModalOpen(false);
        message.success("代理配置已更新");
      }
    } catch (e) { }
  };

  // ✅ 风控配置状态
  const [isRiskModalOpen, setIsRiskModalOpen] = useState(false);
  const [editingRiskInstanceId, setEditingRiskInstanceId] = useState<string | null>(null);
  const [riskForm] = Form.useForm();

  const handleOpenRiskModal = (instance: BrowserInstance) => {
    setEditingRiskInstanceId(instance.id);
    const risk = instance.risk || { bypassCF: false, bypassAkamai: false, bypassRuishu: false };
    riskForm.setFieldsValue(risk);
    setIsRiskModalOpen(true);
  };

  const handleSaveRiskConfig = async () => {
    try {
      const values = await riskForm.validateFields();
      if (editingRiskInstanceId) {
        onUpdateBrowserInstance(editingRiskInstanceId, { risk: values });
        setIsRiskModalOpen(false);
        message.success("风控配置已更新");
      }
    } catch (e) { }
  };

  // ✅ 风控配置状态 (Already defined above)

  const handleOpenEnvModal = (instance: BrowserInstance) => {
    setEditingEnvInstanceId(instance.id);
    setIsEnvModalOpen(true);
  };

  const handleUpdateEnvConfig = (key: keyof EnvConfig, value: any) => {
    if (editingEnvInstanceId) {
      const instance = browserInstances.find(i => i.id === editingEnvInstanceId);
      if (instance) {
        // Initialize with defaults if env is undefined
        const currentEnv = instance.env || { stealth: true, headless: false };
        onUpdateBrowserInstance(editingEnvInstanceId, {
          env: { ...currentEnv, [key]: value }
        });
      }
    }
  };

  // ✅ 新增：初始化时从 localStorage 读取配置
  useEffect(() => {
    const savedPath = localStorage.getItem("retool_workspace_path");
    if (savedPath) setWorkspacePath(savedPath);
  }, []);

  // 🔥 新增：切换到工具配置标签时自动获取最新 Frida 版本
  useEffect(() => {
    if (activeSettingTab === "tools") {
      fetchFridaVersions();
    }
  }, [activeSettingTab]);


  // ✅ 新增：选择工作区文件夹
  const handleSelectWorkspace = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "选择反编译产物存放目录",
      });
      if (selected && typeof selected === "string") {
        setWorkspacePath(selected);
        localStorage.setItem("retool_workspace_path", selected);
        message.success("工作区路径已更新");
      }
    } catch (e) {
      console.error(e);
    }
  };

  // ✅ 处理：打开添加/编辑弹窗
  const handleOpenAiConfig = (config: any = null) => {
    setEditingConfig(config);
    if (config) {
      aiConfigForm.setFieldsValue(config); // 编辑模式：回填数据
    } else {
      aiConfigForm.resetFields(); // 添加模式：重置表单
      // 设置默认值
      aiConfigForm.setFieldsValue({
        provider: "openai",
        baseUrl: "https://api.openai.com/v1",
      });
    }
    setIsAiConfigModalOpen(true);
  };

  // ✅ 处理：保存配置
  const handleSaveAiConfig = async () => {
    try {
      const values = await aiConfigForm.validateFields();

      if (editingConfig) {
        // 更新现有
        await db.aiConfigs.update(editingConfig.id, values);
        message.success("配置已更新");
      } else {
        // 新增
        // 如果是第一个配置，默认设为激活
        const count = await db.aiConfigs.count();
        await db.aiConfigs.add({ ...values, isActive: count === 0 });
        message.success("添加成功");
      }
      setIsAiConfigModalOpen(false);
    } catch (error) {
      console.error("验证失败:", error);
    }
  };

  // ✅ 处理：删除配置
  const handleDeleteAiConfig = async (id: number) => {
    await db.aiConfigs.delete(id);
    message.success("已删除");
  };

  // ✅ 处理：设为激活 (互斥逻辑)
  const handleSetActive = async (id: number) => {
    await db.transaction("rw", db.aiConfigs, async () => {
      // 1.先把所有配置设为 false
      await db.aiConfigs.toCollection().modify({ isActive: false });
      // 2.把当前点击的设为 true
      await db.aiConfigs.update(id, { isActive: true });
    });
    message.success("已切换当前使用的模型");
  };

  const checkAllRootStatus = async () => {
    // ... existing logic ...
    const statusMap: Record<string, boolean> = {};
    await Promise.all(
      devices.map(async (dev) => {
        if (dev.type === "android" && dev.status === "online") {
          try {
            const isRooted = await invoke<boolean>("check_is_rooted", {
              deviceId: dev.id,
            });
            statusMap[dev.id] = isRooted;
          } catch (e) {
            statusMap[dev.id] = false;
          }
        }
      })
    );
    setRootStatusMap((prev) => ({ ...prev, ...statusMap }));
  };

  const checkAllFridaStatus = async () => {
    // ... existing logic ...
    const statusMap: Record<string, boolean> = {};
    await Promise.all(
      devices.map(async (dev) => {
        if (dev.type === "android" && dev.status === "online") {
          try {
            const isRunning = await invoke<boolean>("check_frida_running", {
              deviceId: dev.id,
            });
            statusMap[dev.id] = isRunning;
          } catch (e) {
            statusMap[dev.id] = false;
          }
        }
      })
    );
    setFridaStatusMap((prev) => ({ ...prev, ...statusMap }));
  };

  // 🔥 检查所有设备的魔改版 Frida 运行状态
  const checkAllModdedFridaStatus = async () => {
    const statusMap: Record<string, boolean> = {};
    await Promise.all(
      devices.map(async (dev) => {
        if (dev.type === "android" && dev.status === "online") {
          try {
            const isRunning = await invoke<boolean>("check_modded_frida_running", {
              deviceId: dev.id,
            });
            statusMap[dev.id] = isRunning;
          } catch (e) {
            statusMap[dev.id] = false;
          }
        }
      })
    );
    setModdedFridaStatusMap((prev) => ({ ...prev, ...statusMap }));
  };


  useEffect(() => {
    if (devices.length > 0) {
      checkAllFridaStatus();
      checkAllModdedFridaStatus();
      checkAllRootStatus();
    }
    const timer = setInterval(() => {
      checkAllFridaStatus();
      checkAllModdedFridaStatus();
      checkAllRootStatus();
    }, 5000);
    return () => clearInterval(timer);
  }, [devices]);


  // ... (keeping other helper functions like fetchFridaVersions, detectAbi, etc. exactly the same) ...
  const fetchFridaVersions = async () => {
    setLoadingVersions(true);
    try {
      const versions = await invoke<string[]>("get_frida_versions");
      setFridaVersions(versions);
      if (versions.length > 0) {
        setInstallConfig((prev) => ({ ...prev, version: versions[0] }));
      }
      message.success("已获取最新 Frida 版本列表");
    } catch (e) {
      console.error(e);
      message.error("获取版本失败，使用内置列表");
    } finally {
      setLoadingVersions(false);
    }
  };

  const detectAbi = async (device: Device) => {
    try {
      const abi = await invoke<string>("get_device_abi", {
        deviceId: device.id,
      });
      let detectedArch = "arm64";
      if (abi.includes("arm64")) detectedArch = "arm64";
      else if (abi.includes("arm")) detectedArch = "arm";
      else if (abi.includes("x86_64")) detectedArch = "x86_64";
      else if (abi.includes("x86")) detectedArch = "x86";
      setInstallConfig((prev) => ({ ...prev, arch: detectedArch }));
    } catch (e) {
      console.error("获取架构失败", e);
    }
  };

  const openToolModal = (device: Device) => {
    setCurrentToolDevice(device);
    setIsToolModalOpen(true);
    setSelectedToolId(null);
    detectAbi(device);
    fetchFridaVersions();
  };

  const handleConnectCloud = async () => {
    if (!ipAddress) {
      message.warning("请输入 IP 地址");
      return;
    }
    setConnecting(true);
    try {
      await invoke("adb_pair", { address: ipAddress });
      message.success(`成功连接到 ${ipAddress}`);
      setIsConnectModalOpen(false);
      setIpAddress("");
      if (onRefresh) onRefresh();
    } catch (error: any) {
      message.error(error);
    } finally {
      setConnecting(false);
    }
  };

  const handleInstallApp = async (device: Device) => {
    if (device.type === "ios") {
      message.warning("iOS 设备暂不支持直接安装应用");
      return;
    }
    try {
      const selectedPath = await open({
        multiple: false,
        filters: [{ name: "Android Package", extensions: ["apk"] }],
      });
      if (!selectedPath) return;

      const displayName = deviceAliases[device.id] || device.name;
      const hideLoading = message.loading(
        `正在为 ${displayName} 安装应用...`,
        0
      );

      try {
        await invoke("install_apk", {
          deviceId: device.id,
          apkPath: selectedPath,
        });
        hideLoading();
        message.success("安装成功！");
      } catch (err: any) {
        hideLoading();
        message.error("安装失败: " + err);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeployTool = async (tool: ToolItem) => {
    if (!currentToolDevice) return;
    const version = tool.hasVersions ? installConfig.version : "latest";
    const arch = tool.hasArch ? installConfig.arch : "all";

    const executeDeploy = async () => {
      const hideLoading = message.loading(
        `正在下载并部署 ${tool.name} (${version})...`,
        0
      );
      try {
        // 🔥 Determine which deploy command to use
        const deployCmd = (tool.id === "frida" && useStealthMode) ? "deploy_stealth_frida" : "deploy_tool";

        const result = await invoke<string>(deployCmd, {
          deviceId: currentToolDevice.id,
          // For stealth mode, we might not need toolId if it's a dedicated command but keeping it is fine
          toolId: tool.id,
          version: version,
          arch: arch,
        });
        hideLoading();
        message.success(result);
        if (tool.id === "frida") {
          Modal.confirm({
            title: "部署成功",
            content: "Frida Server 已就绪。是否立即启动服务？",
            okText: "启动",
            cancelText: "稍后",
            onOk: async () => {
              try {
                try {
                  await invoke("run_command", {
                    cmd: "adb",
                    args: [
                      "-s",
                      currentToolDevice.id,
                      "shell",
                      "shell",
                      "su -c 'pkill -f frida-server; pkill -f sys_svc_mgr'", // Kill both potential processes
                    ],
                  });
                } catch (e) { }

                // 🔥 Construct Start Command based on mode
                const serverName = useStealthMode ? "sys_svc_mgr" : "frida-server";
                const startCmd = `su -c 'setenforce 0; chmod 755 /data/local/tmp/${serverName}; nohup /data/local/tmp/${serverName} > /dev/null 2>&1 &'`;

                await invoke("run_command", {
                  cmd: "adb",
                  args: [
                    "-s",
                    currentToolDevice.id,
                    "shell",
                    startCmd,
                  ],
                });
                message.success(
                  "Frida Server 已在后台启动 (SELinux: Permissive)"
                );
              } catch (e: any) {
                console.error("启动详情报错:", e);
                message.error(`启动失败: ${e}`);
              }
            },
          });
        }
      } catch (e: any) {
        hideLoading();
        message.error(`部署失败: ${e}`);
      }
    };

    if (tool.id === "frida") {
      try {
        const isInstalled = await invoke<boolean>("check_frida_installed", {
          deviceId: currentToolDevice.id,
        });
        if (isInstalled) {
          Modal.confirm({
            title: "发现旧版本",
            icon: <BugOutlined style={{ color: "orange" }} />,
            content: (
              <div>
                <p>检测到设备上已经存在 Frida Server 文件。</p>
                <p>
                  是否<strong>覆盖安装</strong>为版本 <b>{version}</b>？
                </p>
                <p style={{ fontSize: 12, color: "#999" }}>
                  (将会自动替换 /data/local/tmp/frida-server)
                </p>
              </div>
            ),
            okText: "覆盖安装",
            okType: "danger",
            cancelText: "取消",
            onOk: executeDeploy,
          });
          return;
        }
      } catch (e) {
        console.warn("检测 Frida 状态失败，直接尝试安装", e);
      }
    }
    executeDeploy();
  };

  const handleAiRenameSubmit = () => {
    if (currentRenameDevice && newDeviceName.trim()) {
      onRenameDevice(currentRenameDevice.id, newDeviceName.trim());
      message.success("重命名成功");
      setIsRenameModalOpen(false);
    }
  };

  const handleSwitchToWireless = async (device: Device) => {
    if (device.type === "ios") {
      message.warning("iOS 不支持此操作");
      return;
    }
    const hideLoading = message.loading("正在配置无线连接...", 0);
    try {
      const ip = await invoke<string>("get_device_ip", { deviceId: device.id });
      await invoke("enable_wireless_mode", { deviceId: device.id });
      setTimeout(async () => {
        try {
          await invoke("adb_pair", { address: `${ip}:5555` });
          hideLoading();
          message.success(`无线连接成功！IP: ${ip}`);
          if (onRefresh) onRefresh();
          Modal.success({
            title: "无线连接已就绪",
            content: `已成功连接到 ${ip}:5555。现在您可以拔掉 USB 数据线了。`,
          });
        } catch (e: any) {
          hideLoading();
          message.error("连接失败: " + e);
        }
      }, 1000);
    } catch (e: any) {
      hideLoading();
      message.error("配置失败: " + e);
    }
  };

  const handleMenuClick = (key: string, device: Device) => {
    switch (key) {
      case "copy-id":
        navigator.clipboard.writeText(device.id);
        message.success(`已复制 ID`);
        break;
      case "copy-name":
        navigator.clipboard.writeText(deviceAliases[device.id] || device.name);
        message.success("已复制名称");
        break;
      case "refresh":
        if (onRefresh) onRefresh();
        break;
      case "rename":
        setCurrentRenameDevice(device);
        setNewDeviceName(deviceAliases[device.id] || device.name);
        setIsRenameModalOpen(true);
        break;
      default:
        break;
    }
  };

  const handleSidebarModeChange = () => {
    if (sidebarMode === "android") {
      setSidebarMode("ai");
      onViewChange("ai-chat" as any);
    } else {
      setSidebarMode("android");
      onViewChange("device");
    }
  };

  const handleNewChat = async () => {
    const newId = Date.now().toString();
    const newSession: ChatSession = {
      id: newId,
      title: "新对话",
      date: "刚刚",
      lastUpdated: Date.now(),
    };
    await db.chatSessions.add(newSession);
    message.success("已创建新对话");
    onViewChange(`ai-chat-${newId}` as any);
  };

  const handleStartFrida = async (device: Device) => {
    // ... (logic same as before)
    const hideCheckLoading = message.loading("正在检测环境...", 0);
    try {
      const isInstalled = await invoke<boolean>("check_frida_installed", {
        deviceId: device.id,
      });
      hideCheckLoading();
      if (!isInstalled) {
        Modal.confirm({
          title: "未安装 Frida Server",
          content: (
            <div>
              <p>
                检测到设备 <b>{deviceAliases[device.id] || device.name}</b>{" "}
                尚未安装 Frida Server。
              </p>
              <p>是否立即打开安装向导？</p>
            </div>
          ),
          okText: "去安装",
          cancelText: "取消",
          onOk: () => {
            openToolModal(device);
            setSelectedToolId("frida");
          },
        });
        return;
      }
      const hideStartLoading = message.loading("正在启动 Frida Server...", 0);
      await invoke("run_command", {
        cmd: "adb",
        args: [
          "-s",
          device.id,
          "shell",
          "su -c 'setenforce 0; chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'",
        ],
      });
      setTimeout(async () => {
        try {
          const isRunning = await invoke<boolean>("check_frida_running", {
            deviceId: device.id,
          });
          hideStartLoading();
          if (isRunning) {
            message.success("Frida Server 启动成功！");
            checkAllFridaStatus();
          } else {
            Modal.error({
              title: "启动失败",
              content: (
                <div>
                  <p>发送启动指令成功，但进程立即退出了。</p>
                  <p>可能有以下原因：</p>
                  <ul>
                    <li>安装的 Frida 架构（arm/arm64）与手机不匹配</li>
                    <li>Frida 版本与系统不兼容</li>
                    <li>手机 Root 权限管理拒绝了后台执行</li>
                  </ul>
                  <p>建议：尝试在“部署调试工具”中更换架构或版本重新安装。</p>
                </div>
              ),
            });
          }
        } catch (e) {
          hideStartLoading();
        }
      }, 2000);
    } catch (e) {
      hideCheckLoading();
      message.error("检测失败，请检查 ADB 连接");
    }
  };

  const handleStopFrida = async (device: Device) => {
    // ... (logic same as before)
    const hideLoading = message.loading("正在停止 Frida Server...", 0);
    try {
      await invoke("run_command", {
        cmd: "adb",
        args: ["-s", device.id, "shell", "su -c 'pkill -f frida-server'"],
      });
      setTimeout(() => {
        hideLoading();
        message.success("Frida Server 已停止");
        checkAllFridaStatus();
      }, 1000);
    } catch (e) {
      hideLoading();
      message.error("停止失败");
    }
  };

  // 🔥 启动魔改版 Frida Server
  const handleStartModdedFrida = async (device: Device) => {
    const hideCheckLoading = message.loading("正在检测魔改版 Frida 环境...", 0);
    try {
      // 检查 modded-frida-server 是否已安装
      const checkResult = await invoke<string>("run_command", {
        cmd: "adb",
        args: ["-s", device.id, "shell", "ls /data/local/tmp/modded-frida-server"],
      });
      hideCheckLoading();

      if (checkResult.includes("No such file")) {
        Modal.warning({
          title: "未安装魔改版 Frida Server",
          content: (
            <div>
              <p>设备上未检测到 modded-frida-server 文件。</p>
              <p>请先编译魔改版 Frida 并推送到 <b>/data/local/tmp/modded-frida-server</b>。</p>
            </div>
          ),
        });
        return;
      }

      const hideStartLoading = message.loading("正在启动魔改版 Frida Server...", 0);
      await invoke("run_command", {
        cmd: "adb",
        args: [
          "-s",
          device.id,
          "shell",
          "su -c 'setenforce 0; chmod 755 /data/local/tmp/modded-frida-server; nohup /data/local/tmp/modded-frida-server > /dev/null 2>&1 &'",
        ],
      });
      setTimeout(async () => {
        hideStartLoading();
        checkAllModdedFridaStatus();
        message.success("魔改版 Frida Server 已启动！");
      }, 2000);
    } catch (e) {
      hideCheckLoading();
      message.error("启动魔改版 Frida 失败");
    }
  };

  // 🔥 停止魔改版 Frida Server
  const handleStopModdedFrida = async (device: Device) => {
    const hideLoading = message.loading("正在停止魔改版 Frida Server...", 0);
    try {
      await invoke("run_command", {
        cmd: "adb",
        args: ["-s", device.id, "shell", "su -c 'pkill -f modded-frida-server'"],
      });
      setTimeout(() => {
        hideLoading();
        message.success("魔改版 Frida Server 已停止");
        checkAllModdedFridaStatus();
      }, 1000);
    } catch (e) {
      hideLoading();
      message.error("停止失败");
    }
  };


  const getDeviceMenuItems = (device: Device): MenuProps["items"] => [
    {
      key: "show",
      label: "显示画面",
      icon: <DesktopOutlined />,
      onClick: () => {
        onViewChange("show");
        onDeviceSelect(device.id);
      },
    },
    {
      key: "install",
      label: "安装应用",
      icon: <AppstoreAddOutlined />,
      onClick: () => handleInstallApp(device),
    },
    {
      key: "files",
      label: "文件管理器",
      icon: <FolderOpenOutlined />,
      onClick: () => {
        onViewChange("file-manager");
        onDeviceSelect(device.id);
      },
    },
    { type: "divider" },
    device.type === "android"
      ? {
        key: "frida_control",
        label: fridaStatusMap[device.id]
          ? "停止 Frida Server"
          : "启动 Frida Server",
        icon: fridaStatusMap[device.id] ? (
          <StopOutlined style={{ color: "#ff4d4f" }} />
        ) : (
          <PlayCircleOutlined style={{ color: "#52c41a" }} />
        ),
        danger: fridaStatusMap[device.id],
        onClick: () => {
          if (fridaStatusMap[device.id]) {
            handleStopFrida(device);
          } else {
            handleStartFrida(device);
          }
        },
      }
      : null,
    // 🔥 魔改版 Frida Server 控制
    device.type === "android"
      ? {
        key: "modded_frida_control",
        label: moddedFridaStatusMap[device.id]
          ? "停止魔改版 Frida"
          : "启动魔改版 Frida",
        icon: <RocketOutlined style={{ color: moddedFridaStatusMap[device.id] ? "#ff4d4f" : "#722ed1" }} />,
        danger: moddedFridaStatusMap[device.id],
        onClick: () => {
          if (moddedFridaStatusMap[device.id]) {
            handleStopModdedFrida(device);
          } else {
            handleStartModdedFrida(device);
          }
        },

      }
      : null,

    { type: "divider" },

    { key: "copy-id", label: "复制 ID", icon: <CopyOutlined /> },
    { key: "copy-name", label: "复制名称", icon: <CopyOutlined /> },
    { type: "divider" },
    {
      key: "wireless",
      label: "转为无线连接",
      icon: <WifiOutlined />,
      disabled: device.id.includes(".") || device.type === "ios",
      onClick: () => handleSwitchToWireless(device),
    },
    {
      key: "rename",
      label: "重命名设备",
      icon: <EditOutlined />,
      onClick: () => {
        setCurrentRenameDevice(device);
        setNewDeviceName(deviceAliases[device.id] || device.name);
        setIsRenameModalOpen(true);
      },
    },
    { type: "divider" },
    {
      key: "disconnect",
      label: "断开连接",
      icon: <DisconnectOutlined />,
      danger: true,
      onClick: async () => {
        await invoke("run_command", {
          cmd: "adb",
          args: ["disconnect", device.id],
        });
        if (onRefresh) onRefresh();
      },
    },
    { key: "refresh", label: "刷新", icon: <ReloadOutlined /> },
  ];

  const renderNavItem = (
    id: ViewMode,
    icon: React.ReactNode,
    label: string
  ) => (
    <Tooltip title={collapsed ? label : ""} placement="right">
      <div
        className={`nav-item ${currentView === id ? "active" : ""}`}
        onClick={() => onViewChange(id)}
        style={{
          justifyContent: collapsed ? "center" : "flex-start",
          padding: collapsed ? "0 0" : "0 16px",
          minHeight: 46,
        }}
      >
        <span style={{ fontSize: 16, display: "flex" }}>{icon}</span>
        {!collapsed && (
          <span
            style={{ marginLeft: 10, whiteSpace: "nowrap", overflow: "hidden" }}
          >
            {label}
          </span>
        )}
      </div>
    </Tooltip>
  );

  // ✅ 2. Use handleDeleteSession in proper context
  const handleDeleteSession = (e: any, session: ChatSession) => {
    // Using 'any' for event here to simplify call from dropdown
    Modal.confirm({
      title: "删除对话",
      icon: <ExclamationCircleFilled />,
      content: `确定要删除 "${session.title}" 吗？此操作无法恢复。`,
      okText: "删除",
      okType: "danger",
      cancelText: "取消",
      onOk: async () => {
        try {
          await db.transaction(
            "rw",
            db.chatSessions,
            db.chatMessages,
            async () => {
              await db.chatMessages.where({ sessionId: session.id }).delete();
              await db.chatSessions.delete(session.id);
            }
          );
          message.success("对话已删除");
          if (currentView === (`ai-chat-${session.id}` as any)) {
            // Optional: redirect logic
          }
        } catch (error) {
          console.error("删除失败:", error);
          message.error("删除失败");
        }
      },
    });
  };

  // ✅ 3. Use openRenameModal in proper context
  const openRenameModal = (e: any, session: ChatSession) => {
    // e?.stopPropagation(); // Optional if called from menu item
    setCurrentEditingSession(session);
    setNewTitle(session.title);
    setIsAiRenameModalOpen(true);
  };

  // ✅ 4. Submit rename
  const handleRenameSubmit = async () => {
    if (currentEditingSession && newTitle.trim()) {
      await db.chatSessions.update(currentEditingSession.id, {
        title: newTitle.trim(),
      });
      message.success("重命名成功");
      setIsAiRenameModalOpen(false);
      setCurrentEditingSession(null);
    }
  };

  const renderChatHistoryItem = (session: ChatSession) => {
    const viewId = `ai-chat-${session.id}`;
    const isActive = currentView === (viewId as any);

    // Dropdown menu configuration using the newly defined functions
    const menuItems: MenuProps["items"] = [
      {
        key: "rename",
        label: "重命名",
        icon: <EditOutlined />,
        onClick: ({ domEvent }) => {
          domEvent.stopPropagation();
          openRenameModal(domEvent, session); // ✅ Connected here
        },
      },
      {
        type: "divider",
      },
      {
        key: "delete",
        label: "删除",
        icon: <DeleteOutlined />,
        danger: true,
        onClick: ({ domEvent }) => {
          domEvent.stopPropagation();
          handleDeleteSession(domEvent, session); // ✅ Connected here
        },
      },
    ];

    return (
      <div
        key={session.id}
        className={`nav-item chat-item-group ${isActive ? "active" : ""}`}
        onClick={() => onViewChange(viewId as any)}
        style={{
          justifyContent: collapsed ? "center" : "flex-start",
          padding: collapsed ? "0 0" : "8px 16px",
          minHeight: 20,
          maxHeight: 30,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          position: "relative",
        }}
      >
        <MessageOutlined
          style={{
            fontSize: 16,
            color: isActive ? token.colorPrimary : "#666",
            flexShrink: 0,
          }}
        />
        {!collapsed && (
          <>
            <div
              style={{
                marginLeft: 10,
                flex: 1,
                overflow: "hidden",
                paddingRight: 20,
              }}
            >
              <div
                style={{
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  fontSize: 13,
                  color: "var(--text-color)",
                }}
              >
                {session.title}
              </div>
              <div style={{ fontSize: 11, color: "#999" }}>{session.date}</div>
            </div>

            <div
              className="chat-action-btn"
              onClick={(e) => e.stopPropagation()}
              style={{
                position: "absolute",
                right: 8,
                top: "50%",
                transform: "translateY(-50%)",
              }}
            >
              <Dropdown menu={{ items: menuItems }} trigger={["click"]}>
                <div
                  style={{
                    padding: 4,
                    borderRadius: 4,
                    color: "#666",
                    display: "flex",
                    alignItems: "center",
                  }}
                  className="hover-bg"
                >
                  <MoreOutlined style={{ fontSize: 16 }} />
                </div>
              </Dropdown>
            </div>
          </>
        )}
      </div>
    );
  };

  // ... (Return block and Modals - identical to your previous version, just ensuring Modal uses correct props) ...
  // ================= RPC Modal Logic =================
  const [isRpcModalOpen, setIsRpcModalOpen] = useState(false);
  // Store ID instead of full object to avoid stale state
  const [editingRpcInstanceId, setEditingRpcInstanceId] = useState<string | null>(null);
  const [rpcPortInput, setRpcPortInput] = useState(9999);

  // Derive the current instance from the latest props
  const targetRpcInstance = browserInstances.find(i => i.id === editingRpcInstanceId);

  const handleOpenRpcModal = (inst: BrowserInstance) => {
    setEditingRpcInstanceId(inst.id); // Only store ID
    setRpcPortInput(inst.rpc?.port || 9999);
    setIsRpcModalOpen(true);
  };

  const handleToggleRpc = async (enabled: boolean) => {
    if (!targetRpcInstance) return;

    // 1. 始终更新配置状态 (持久化)
    // This prop update will flow back down to us, updating `targetRpcInstance`
    onUpdateBrowserInstance(targetRpcInstance.id, {
      rpc: {
        enabled: enabled,
        port: rpcPortInput
      }
    });

    // 2. 只有当引擎运行时，才发送实时指令
    if (targetRpcInstance.status === "running") {
      try {
        const action = enabled ? "start" : "stop";
        await invoke("send_web_command", {
          action: "rpc_ctrl",
          data: { action, port: rpcPortInput },
        });
        message.success(`RPC 服务已${enabled ? "开启" : "停止"}`);
      } catch (e) {
        console.error("RPC 操作警告:", e);
        message.warning("配置已保存，但实时应用失败 (引擎可能未就绪)");
      }
    }
  };

  return (
    <>
      <div
        className="sidebar"
        style={{
          width: collapsed ? 80 : 250,
          transition: "width 0.2s cubic-bezier(0.2, 0, 0, 1) 0s",
          display: "flex",
          flexDirection: "column",
          height: "100%",
          overflow: "hidden",
          position: "relative",
        }}
      >
        <style>
          {`
          .no-scrollbar::-webkit-scrollbar { display: none; }
          .ant-segmented-item-label { display: flex; align-items: center; justify-content: center; gap: 6px; }
          
          .chat-action-btn { opacity: 0; transition: opacity 0.2s; }
          .chat-item-group:hover .chat-action-btn { opacity: 1; }
          
          .hover-bg:hover { background-color: rgba(0,0,0,0.06); }
        `}
        </style>

        {/* ... Headers, Device List ... */}
        {/* 1. 顶部 Header (固定) */}
        <div
          className="sidebar-header"
          style={{
            justifyContent: collapsed ? "center" : "flex-start",
            // padding: collapsed ? "20px 0" : "20px",
            flexShrink: 0, // 禁止被压缩
          }}
        >
          <ThunderboltFilled
            style={{
              color: "var(--accent-color)",
              fontSize: collapsed ? 24 : 18,
            }}
          />
          {!collapsed && (
            <span style={{ marginLeft: 8, whiteSpace: "nowrap" }}>
              逆向工作台
            </span>
          )}
        </div>

        {/* 2. 设备列表标题栏 (固定) - 仅在 Android 模式显示 */}
        {sidebarMode === "android" && (
          <div
            className="sidebar-section-title"
            style={{
              display: "flex",
              justifyContent: collapsed ? "center" : "space-between",
              alignItems: "center",
              marginBottom: 10,
              flexShrink: 0, // 禁止被压缩
            }}
          >
            {!collapsed && <span style={{ whiteSpace: "nowrap" }}>已连接设备</span>}
            <Tooltip title="连接新设备" placement="right">
              <PlusCircleOutlined
                style={{
                  cursor: "pointer",
                  fontSize: collapsed ? 18 : 14,
                  color: "var(--accent-color)",
                  marginBottom: collapsed ? 4 : 0,
                }}
                onClick={() => setIsConnectModalOpen(true)}
              />
            </Tooltip>
          </div>
        )}

        {/* 3. 设备列表区域 (独立滚动) - 仅在 Android 模式显示 */}
        {sidebarMode === "android" && (
          <div
            className="no-scrollbar"
            style={{
              // 关键逻辑：
              // flex: "0 1 auto" 表示初始高度根据内容自适应，但允许缩小
              // maxHeight: "35%" 稍微调小一点，留更多空间给下方的双模式区域
              flex: "0 1 auto",
              maxHeight: "35%",
              overflowY: "auto", // 开启垂直滚动
              overflowX: "hidden",
              scrollbarWidth: "none", // Firefox 隐藏滚动条
              msOverflowStyle: "none", // IE 隐藏滚动条
              marginBottom: 8,
              borderBottom: "1px solid rgba(0,0,0,0.03)",
              paddingBottom: 8,
            }}
          >
            {devices.length === 0 && !collapsed && (
              <div
                style={{
                  textAlign: "center",
                  color: "#ccc",
                  padding: "10px 0",
                  fontSize: 12,
                }}
              >
                暂无设备
              </div>
            )}
            {devices.map((dev) => (
              <Tooltip
                key={dev.id}
                title={collapsed ? deviceAliases[dev.id] || dev.name : ""}
                placement="right"
              >
                <div
                  className={`nav-item-split ${currentView === "device" && selectedDeviceId === dev.id
                    ? "active"
                    : ""
                    }`}
                  style={{
                    padding: collapsed ? "4px" : undefined,
                    justifyContent: collapsed ? "center" : "space-between",
                  }}
                >
                  <div
                    className="nav-item-main"
                    onClick={() => {
                      onViewChange("device");
                      onDeviceSelect(dev.id);
                    }}
                    style={{
                      justifyContent: collapsed ? "center" : "flex-start",
                      padding: collapsed ? "8px 0" : undefined,
                      width: collapsed ? "100%" : "auto",
                    }}
                  >
                    {dev.type === "android" ? (
                      <AndroidFilled style={{ fontSize: 16 }} />
                    ) : (
                      <AppleFilled style={{ fontSize: 16 }} />
                    )}
                    {!collapsed && (
                      <>
                        <div
                          style={{
                            flex: 1,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            fontSize: 13,
                            fontWeight: 500,
                            marginLeft: 8,
                          }}
                        >
                          {deviceAliases[dev.id] || dev.name}
                        </div>
                        <div style={{ display: "flex", gap: 4 }}>
                          {fridaStatusMap[dev.id] && (
                            <Tooltip title="Frida Server 运行中">
                              <BugOutlined
                                style={{
                                  color: "#ff4d4f",
                                  fontSize: 13,
                                  padding: "0 3px",
                                }}
                              />
                            </Tooltip>
                          )}
                          {rootStatusMap[dev.id] && (
                            <Tooltip title="设备已 Root">
                              <UnlockOutlined
                                style={{
                                  color: "#faad14",
                                  fontSize: 13,
                                  padding: "0 3px",
                                }}
                              />
                            </Tooltip>
                          )}
                        </div>
                        <span
                          style={{
                            background:
                              dev.status === "online" ? "#10b981" : "#ccc",
                            margin: 0,
                            marginRight: 5,
                            marginLeft: 8,
                            flexShrink: 0,
                            backgroundColor:
                              dev.status === "online" ? "#10b981" : "#ccc",
                          }}
                          className="status-indicator"
                        />
                      </>
                    )}
                  </div>
                  {!collapsed && (
                    <Dropdown
                      menu={{
                        items: getDeviceMenuItems(dev),
                        onClick: ({ key, domEvent }) => {
                          domEvent.stopPropagation();
                          handleMenuClick(key, dev);
                        },
                      }}
                      trigger={["click"]}
                      placement="bottomRight"
                    >
                      <div
                        className="nav-item-action"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <MoreOutlined style={{ fontSize: 16 }} />
                      </div>
                    </Dropdown>
                  )}
                </div>
              </Tooltip>
            ))}
          </div>
        )}

        {/* 2b. JS 引擎控制面板 (仅在 JS 模式显示) */}
        {sidebarMode === "js" && (
          <div
            className="sidebar-section-title"
            style={{
              display: "flex",
              justifyContent: collapsed ? "center" : "space-between",
              alignItems: "center",
              marginBottom: 10,
              flexShrink: 0, // 禁止被压缩
            }}
          >
            <span style={{ whiteSpace: "nowrap" }}>JS 引擎控制</span>
            <Tooltip title="新增浏览器实例" placement="right">
              <PlusCircleOutlined
                style={{
                  cursor: "pointer",
                  fontSize: collapsed ? 18 : 14,
                  color: "var(--accent-color)",
                  marginBottom: collapsed ? 4 : 0,
                }}
                onClick={onAddBrowserInstance}
              />
            </Tooltip>
          </div>
        )}
        {sidebarMode === "js" && (
          <div
            className="no-scrollbar"
            style={{
              // 关键逻辑：
              // flex: "0 1 auto" 表示初始高度根据内容自适应，但允许缩小
              // maxHeight: "35%" 稍微调小一点，留更多空间给下方的双模式区域
              flex: "0 1 auto",
              maxHeight: "35%",
              overflowY: "auto", // 开启垂直滚动
              overflowX: "hidden",
              scrollbarWidth: "none", // Firefox 隐藏滚动条
              msOverflowStyle: "none", // IE 隐藏滚动条
              marginBottom: 8,
              borderBottom: "1px solid rgba(0,0,0,0.03)",
              paddingBottom: 8,
            }}
          >
            {browserInstances.map((inst) => (
              <Tooltip
                key={inst.id}
                title={collapsed ? (inst.status === "running" ? "JS 引擎运行中" : "JS 引擎未运行") : ""}
                placement="right"
              >
                <div
                  className={`nav-item-split ${activeBrowserInstanceId === inst.id ? "active" : ""}`}
                  style={{
                    padding: collapsed ? "4px" : undefined,
                    justifyContent: collapsed ? "center" : "space-between",
                  }}
                  onClick={() => {
                    onSelectBrowserInstance(inst.id);
                    onViewChange("browser" as any); // 确保切换到 JS 视图
                  }}
                >
                  <div
                    className="nav-item-main"
                    style={{
                      justifyContent: collapsed ? "center" : "flex-start",
                      padding: collapsed ? "8px 0" : undefined,
                      width: collapsed ? "100%" : "auto",
                      cursor: "default", // 输入框可点，整体默认光标
                    }}
                  >
                    <Dropdown
                      menu={{
                        items: [
                          {
                            key: "chrome",
                            label: "谷歌 (Chrome)",
                            icon: <ChromeOutlined style={{ color: "#4285F4" }} />, // Chrome Blue
                          },
                          {
                            key: "firefox",
                            label: "火狐 (Firefox)",
                            icon: <FireOutlined style={{ color: "#FF7139" }} />, // Firefox Orange
                          },
                        ],
                        onClick: ({ key }) => onUpdateBrowserInstance(inst.id, { type: key as any }),
                      }}
                      trigger={["click"]}
                    >
                      <div style={{ cursor: "pointer", display: "flex", alignItems: "center", marginTop: 2 }}>
                        {inst.type === "chrome" ? (
                          <ChromeOutlined style={{ fontSize: 16, color: "#4285F4" }} />
                        ) : (
                          <FireOutlined style={{ fontSize: 16, color: "#FF7139" }} />
                        )}
                      </div>
                    </Dropdown>
                    {!collapsed && (
                      <>
                        <div
                          style={{
                            flex: 1,
                            overflow: "hidden",
                            marginLeft: 8,
                            marginRight: 8,
                          }}
                        >
                          <Input
                            placeholder="目标 URL"
                            value={inst.url}
                            onChange={(e) => onUpdateBrowserInstance(inst.id, { url: e.target.value })}
                            variant="borderless"
                            size="small"
                            style={{
                              padding: 0,
                              fontSize: 13,
                              fontWeight: 500,
                            }}
                          />
                        </div>

                        {/* 状态指示点 */}
                        <span
                          style={{
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: inst.status === "running" ? "#10b981" : "#ccc",
                            flexShrink: 0,
                            marginRight: 4,
                          }}
                          className="status-indicator"
                        />
                      </>
                    )}
                  </div>

                  {!collapsed && (
                    <>
                      <div
                        className="nav-item-action"
                        onClick={(e) => {
                          e.stopPropagation();
                        }}
                        style={{
                          cursor: "pointer",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <Dropdown
                          menu={{
                            items: [
                              {
                                key: "toggle",
                                label: inst.status === "running" ? "停止浏览器" : "启动浏览器",
                                icon: inst.status === "running" ? <StopOutlined style={{ color: "#ff4d4f" }} /> : <PlayCircleOutlined style={{ color: "#52c41a" }} />,
                                onClick: () => onUpdateBrowserInstance(inst.id, { status: inst.status === "running" ? "stopped" : "running" }),
                              },
                              {
                                key: "env_config", // ✅ 新增 环境配置 菜单项
                                label: "环境伪造配置",
                                icon: <SettingOutlined />,
                                onClick: () => handleOpenEnvModal(inst),
                              },
                              {
                                key: "rpc_bridge", // ✅ 新增 RPC 菜单项
                                label: "RPC 桥接服务",
                                icon: <ThunderboltFilled style={{ color: "#faad14" }} />,
                                onClick: () => handleOpenRpcModal(inst),
                              },
                              {
                                key: "risk_config",
                                label: "风控配置",
                                icon: <SafetyCertificateOutlined />,
                                onClick: () => handleOpenRiskModal(inst),
                              },
                              {
                                key: "proxy_config",
                                label: "网络代理",
                                icon: <ApiOutlined />,
                                onClick: () => handleOpenProxyModal(inst),
                              },
                              { type: "divider" },
                              {
                                key: "action_network",
                                label: "请求拦截 & 替换",
                                icon: <GatewayOutlined />,
                                onClick: () => onOpenInstanceAction?.(inst.id, "network"),
                              },
                              {
                                key: "action_cdp",
                                label: "CDP 协议注入",
                                icon: <CodeOutlined />,
                                onClick: () => onOpenInstanceAction?.(inst.id, "cdp"),
                              },
                              {
                                key: "action_hooks",
                                label: "注入 Hooks",
                                icon: <RocketOutlined />,
                                onClick: () => onOpenInstanceAction?.(inst.id, "hooks"),
                              },
                              { type: "divider" },
                              {
                                key: "fingerprint",
                                label: "指纹配置",
                                icon: <ScanOutlined />,
                                onClick: () => handleOpenFingerprint(inst),
                              },
                              { type: "divider" },
                              {
                                key: "rename",
                                label: "重命名",
                                icon: <EditOutlined />,
                                onClick: () => message.info("重命名功能暂未实现"),
                              },
                              {
                                key: "delete",
                                label: "删除",
                                icon: <DeleteOutlined />,
                                danger: true,
                                onClick: () => onRemoveBrowserInstance(inst.id),
                              },
                            ],
                          }}
                          trigger={["click"]}
                          placement="bottomRight"
                        >
                          <div style={{ padding: 4 }}>
                            <MoreOutlined style={{ fontSize: 16, color: token.colorPrimary }} />
                          </div>
                        </Dropdown>
                      </div>
                    </>
                  )}
                </div>
              </Tooltip>
            ))}


          </div>
        )}



        {/* 4. 模式切换标题栏 (替代原工具箱标题) */}
        <div
          className="sidebar-section-title"
          style={{
            display: collapsed ? "none" : "flex", // 折叠时隐藏，由下方图标控制
            justifyContent: "space-between", // 关键：两端对齐
            alignItems: "center", // 垂直居中
            paddingRight: 8, // 右侧稍微留点空隙给按钮
            marginBottom: 10,
            flexShrink: 0,
            height: 32, // 固定高度保持对齐
          }}
        >
          {/* 左侧：动态标题 */}
          <span style={{ fontWeight: 600, fontSize: 14 }}>
            {sidebarMode === "android"
              ? "安卓工具箱"
              : sidebarMode === "js"
                ? "JS 工具箱"
                : "智能协作"}
          </span>

          {/* 右侧：下拉切换菜单 */}
          <Dropdown
            menu={{
              items: [
                {
                  key: "android",
                  label: "安卓工具箱",
                  icon: <AndroidOutlined style={{ color: "#3DDC84" }} />,
                },
                {
                  key: "js",
                  label: "JS 工具箱",
                  icon: <CodeOutlined style={{ color: "#F7DF1E" }} />,
                },
                {
                  key: "ai",
                  label: "AI 助手",
                  icon: <RobotOutlined style={{ color: "var(--accent-color)" }} />,
                },
              ],
              onClick: ({ key }) => {
                const newMode = key as "android" | "js" | "ai";
                setSidebarMode(newMode);
                if (newMode === "ai") {
                  onViewChange("ai-chat" as any);
                } else if (newMode === "js") {
                  onViewChange("browser" as any); // ✅ 切换到内嵌浏览器模式
                } else {
                  onViewChange("device");
                }
              },
            }}
            trigger={["click"]}
            placement="bottomRight"
          >
            <Button
              type="text"
              size="small"
              style={{
                color: "var(--text-color)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 12,
              }}
            >
              <DownOutlined style={{ fontSize: 10, marginLeft: 2 }} />
            </Button>
          </Dropdown>
        </div>

        {/* 分割线 (仅在展开时显示，增加层次感) */}
        {collapsed && (
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              marginBottom: 10,
              flexShrink: 0,
            }}
          >
            <Dropdown
              menu={{
                items: [
                  {
                    key: "android",
                    label: "安卓工具箱",
                    icon: <AndroidOutlined style={{ color: "#3DDC84" }} />,
                  },
                  {
                    key: "js",
                    label: "JS 工具箱",
                    icon: <CodeOutlined style={{ color: "#F7DF1E" }} />,
                  },
                  {
                    key: "ai",
                    label: "AI 助手",
                    icon: <RobotOutlined style={{ color: "var(--accent-color)" }} />,
                  },
                ],
                onClick: ({ key }) => {
                  const newMode = key as "android" | "js" | "ai";
                  setSidebarMode(newMode);
                  if (newMode === "ai") {
                    onViewChange("ai-chat" as any);
                  } else if (newMode === "js") {
                    onViewChange("browser" as any); // ✅ 切换到内嵌浏览器模式
                  } else {
                    onViewChange("device");
                  }
                },
              }}
              placement="topRight"
            >
              <Button
                type="text"
                shape="circle"
                icon={
                  sidebarMode === "android" ? (
                    <AndroidOutlined />
                  ) : sidebarMode === "js" ? (
                    <CodeOutlined />
                  ) : (
                    <RobotOutlined />
                  )
                }
              />
            </Dropdown>
          </div>
        )}

        {/* 5. 双模态内容区域 (独立滚动，占据剩余空间) */}
        <div
          className="no-scrollbar"
          style={{
            flex: 1, // 占据剩余的所有垂直空间
            overflowY: "auto", // 开启垂直滚动
            overflowX: "hidden",
            scrollbarWidth: "none",
            msOverflowStyle: "none",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* === 模式 A: 工具列表 === */}
          {sidebarMode === "android" && (
            <>
              {renderNavItem(
                "network-sniffer",
                <GatewayOutlined />,
                "一键抓包 (Mitmproxy)"
              )}
              {renderNavItem("script-lab", <ExperimentOutlined />, "脚本工坊")}
              {renderNavItem("apk-builder", <BuildOutlined />, "APK 改包工坊")}
              {renderNavItem(
                "java-analyzer",
                <CoffeeOutlined />,
                "Java 源码分析"
              )}
              {renderNavItem("algo-converter", <CodeOutlined />, "伪代码转译")}

              {renderNavItem("asm-lab", <BugOutlined />, "ARM 汇编实验室")}
            </>
          )}

          {/* === 模式 C: JS 工具箱 === */}
          {sidebarMode === "js" && (
            <>
              {renderNavItem("web-lab", <CompassOutlined />, "Web 逆向实验室")}
              {renderNavItem("js-script-workshop", <FileTextOutlined />, "我的脚本工坊")}
              {renderNavItem("ast-lab", <ThunderboltOutlined style={{ color: '#faad14' }} />, "AST 混淆还原")}
              {renderNavItem("ai-captcha", <EyeOutlined style={{ color: '#1890ff' }} />, "AI 验证码识别")}
            </>
          )}

          {/* === 模式 B: AI 智能体对话 === */}
          {sidebarMode === "ai" && (
            <div style={{ padding: collapsed ? "0 4px" : "0" }}>
              {!collapsed && (
                <div style={{ padding: "0 12px 12px 12px" }}>
                  <Button
                    type="dashed"
                    block
                    icon={<PlusOutlined />}
                    onClick={() => {
                      handleNewChat();
                    }}
                  >
                    新建对话
                  </Button>
                </div>
              )}
              {collapsed && (
                <Tooltip title="新建对话" placement="right">
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "center",
                      marginBottom: 8,
                    }}
                  >
                    <Button
                      type="dashed"
                      shape="circle"
                      icon={<PlusOutlined />}
                      onClick={() => message.info("新建对话")}
                    />
                  </div>
                </Tooltip>
              )}

              {/* 历史记录列表 */}
              {!collapsed && (
                <div
                  style={{
                    padding: "0 16px 4px 16px",
                    fontSize: 12,
                    color: "#999",
                  }}
                >
                  最近对话
                </div>
              )}
              {chatList.map((session) => renderChatHistoryItem(session))}

              {/* 更多示例内容填充 */}
              <div style={{ height: 20 }}></div>
            </div>
          )}

          {/* 底部留白，避免内容贴到底部按钮上 */}
          <div style={{ height: 30, flexShrink: 0 }}></div>
        </div>

        {/* ==================== 6. 统一底部功能栏 (设置 + 折叠) ==================== */}
        <div
          style={{
            flexShrink: 0, // 禁止压缩
            borderTop: "1px solid rgba(0,0,0,0.06)", // 只有这一条顶部分割线
            padding: collapsed ? "16px 0" : "12px 16px", // 调整内边距
            display: "flex",
            // 关键布局：折叠时竖排，展开时横排（两端对齐）
            flexDirection: collapsed ? "column" : "row",
            alignItems: "center",
            justifyContent: collapsed ? "center" : "space-between",
            gap: collapsed ? 24 : 0, // 折叠时让两个图标稍微拉开距离
            backgroundColor: "var(--bg-color, #fff)",
            transition: "all 0.2s",
          }}
        >
          {/* 左侧 (或上方): 设置按钮 */}
          <Tooltip title="全局设置" placement="right">
            <div
              onClick={() => setIsSettingsOpen(true)}
              style={{
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                color: "var(--text-color)",
                transition: "color 0.2s",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.color = token.colorPrimary)
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.color = "var(--text-color)")
              }
            >
              <SettingOutlined style={{ fontSize: 18 }} />
              {/* {!collapsed && (
              <span style={{ marginLeft: 10, fontSize: 14 }}>全局设置</span>
            )} */}
            </div>
          </Tooltip>

          {/* 右侧 (或下方): 折叠按钮 */}
          <Tooltip title={collapsed ? "展开" : "折叠"} placement="right">
            <div
              onClick={() => setCollapsed(!collapsed)}
              style={{
                cursor: "pointer",
                color: "#999",
                display: "flex",
                alignItems: "center",
                transition: "color 0.2s",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.color = token.colorPrimary)
              }
              onMouseLeave={(e) => (e.currentTarget.style.color = "#999")}
            >
              {collapsed ? (
                <MenuUnfoldOutlined style={{ fontSize: 18 }} />
              ) : (
                <MenuFoldOutlined style={{ fontSize: 18 }} />
              )}
            </div>
          </Tooltip>
        </div>

        {/* Modals */}
        <Modal
          title="连接云手机"
          open={isConnectModalOpen}
          onOk={handleConnectCloud}
          onCancel={() => setIsConnectModalOpen(false)}
          confirmLoading={connecting}
          okText="连接"
          cancelText="取消"
        >
          <Input
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
            onPressEnter={handleConnectCloud}
          />
        </Modal>
        <Modal
          title="重命名设备"
          open={isRenameModalOpen}
          onOk={handleAiRenameSubmit}
          onCancel={() => setIsRenameModalOpen(false)}
          okText="保存"
          cancelText="取消"
        >
          <Input
            value={newDeviceName}
            onChange={(e) => setNewDeviceName(e.target.value)}
            placeholder="输入新标题"
            onPressEnter={handleAiRenameSubmit}
            autoFocus
          />
        </Modal>

        {/* ✅ 新增：风控配置弹窗 */}
        <Modal
          title={
            <Space>
              <SafetyCertificateOutlined style={{ color: token.colorWarning }} />
              <span>风控配置 (Anti-bot)</span>
            </Space>
          }
          open={isRiskModalOpen}
          onOk={handleSaveRiskConfig}
          onCancel={() => setIsRiskModalOpen(false)}
          okText="保存配置"
          cancelText="取消"
          destroyOnClose
        >
          <Form form={riskForm} layout="vertical" style={{ marginTop: 20 }}>
            <div style={{ background: '#fffbe6', padding: 12, borderRadius: 6, border: '1px solid #ffe58f', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 4 }}>
                <ExclamationCircleFilled style={{ color: '#faad14', marginRight: 8 }} />
                <span style={{ fontWeight: 600, color: '#d48806' }}>自动化过盾说明</span>
              </div>
              <span style={{ fontSize: 12, color: '#d48806' }}>
                开启后，浏览器会自动注入反检测脚本并尝试点击验证码。
                此操作会增加资源消耗，且可能被部分站点检测（建议配合高质量 ISP 代理）。
              </span>
            </div>

            <Form.Item label="Cloudflare 5s 盾 (CF Bypass)" style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>自动检测并尝试穿透 Cloudflare Challenge</span>
                <Form.Item name="bypassCF" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
              </div>
            </Form.Item>
            <Divider style={{ margin: '12px 0' }} />

            <Form.Item label="Akamai Bot Manager" style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#999' }}>企业级反爬防护 (Coming Soon)</span>
                <Form.Item name="bypassAkamai" valuePropName="checked" noStyle>
                  <Switch disabled />
                </Form.Item>
              </div>
            </Form.Item>
            <Divider style={{ margin: '12px 0' }} />

            <Form.Item label="瑞数 6 (River Security)" style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#999' }}>动态混淆与环境检测 (Coming Soon)</span>
                <Form.Item name="bypassRuishu" valuePropName="checked" noStyle>
                  <Switch disabled />
                </Form.Item>
              </div>
            </Form.Item>
          </Form>
        </Modal>

        {/* ✅ 新增：代理配置弹窗 */}
        <Modal
          title="网络代理配置 (Proxy)"
          open={isProxyModalOpen}
          onOk={handleSaveProxyConfig}
          onCancel={() => setIsProxyModalOpen(false)}
          okText="保存配置"
          cancelText="取消"
          destroyOnClose
        >
          <Form form={proxyForm} layout="vertical" style={{ marginTop: 20 }}>
            <Form.Item name="mode" label="代理模式" initialValue="direct">
              <Select>
                <Select.Option value="direct">直连 (Direct - No Proxy)</Select.Option>
                <Select.Option value="http">HTTP</Select.Option>
                <Select.Option value="https">HTTPS</Select.Option>
                <Select.Option value="socks5">Socks5</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item
              noStyle
              shouldUpdate={(prev, current) => prev.mode !== current.mode}
            >
              {({ getFieldValue }) =>
                getFieldValue("mode") !== "direct" ? (
                  <>
                    <div style={{ display: "flex", gap: 16 }}>
                      <Form.Item
                        name="host"
                        label="主机 (Host)"
                        style={{ flex: 2 }}
                        rules={[{ required: true, message: "请输入主机地址" }]}
                      >
                        <Input placeholder="127.0.0.1" />
                      </Form.Item>
                      <Form.Item
                        name="port"
                        label="端口 (Port)"
                        style={{ flex: 1 }}
                        rules={[{ required: true, message: "请输入端口" }]}
                      >
                        <Input type="number" placeholder="7890" />
                      </Form.Item>
                    </div>
                    <div style={{ display: "flex", gap: 16 }}>
                      <Form.Item name="username" label="用户名 (可选)" style={{ flex: 1 }}>
                        <Input placeholder="Username" />
                      </Form.Item>
                      <Form.Item name="password" label="密码 (可选)" style={{ flex: 1 }}>
                        <Input.Password placeholder="Password" />
                      </Form.Item>
                    </div>
                  </>
                ) : null
              }
            </Form.Item>

            <Form.Item shouldUpdate={(prev, cur) => prev.mode !== cur.mode}>
              {({ getFieldValue }) =>
                getFieldValue("mode") !== "direct" && (
                  <Button
                    type="dashed"
                    block
                    onClick={async () => {
                      try {
                        const values = await proxyForm.validateFields();
                        // 🔴 Fix: Port needs to be a number for Rust u16
                        const payload = {
                          ...values,
                          port: Number(values.port)
                        };
                        const hide = message.loading("正在测试代理连通性...", 0);
                        try {
                          const res = await invoke<string>("test_proxy_connection", { proxyConfig: payload });
                          hide();
                          message.success({ content: res, duration: 5 });
                        } catch (e: any) {
                          hide();
                          message.error("连接失败: " + e.toString());
                        }
                      } catch (e) { }
                    }}
                  >
                    <ApiOutlined /> 测试连接 (Test Connection)
                  </Button>
                )
              }
            </Form.Item>
          </Form>
        </Modal>

        {/* ✅ 新增：指纹配置弹窗 */}
        <Modal
          title="配置浏览器指纹"
          open={isFingerprintModalOpen}
          onOk={handleSaveFingerprint}
          onCancel={() => setIsFingerprintModalOpen(false)}
          okText="保存配置"
          cancelText="取消"
          destroyOnClose
        >
          <Form form={fingerprintForm} layout="vertical" style={{ marginTop: 20 }}>
            <Form.Item
              label="User Agent"
              name="userAgent"
              tooltip="浏览器的用户代理字符串"
              rules={[{ required: true, message: "User Agent 不能为空" }]}
            >
              <Input.TextArea rows={3} placeholder="Mozilla/5.0..." />
            </Form.Item>

            <div style={{ display: "flex", gap: 16 }}>
              <Form.Item
                label="Canvas 噪音"
                name="canvasNoise"
                valuePropName="checked"
                tooltip="对 Canvas 绘图加入微量噪音以抵抗指纹追踪"
                style={{ flex: 1 }}
              >
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
              <Form.Item
                label="WebGL 噪音"
                name="webglNoise"
                valuePropName="checked"
                tooltip="对 WebGL 渲染加入参数扰动"
                style={{ flex: 1 }}
              >
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
            </div>

            <div style={{ display: "flex", gap: 16 }}>
              <Form.Item
                label="时区 (Timezone)"
                name="timezone"
                style={{ flex: 1 }}
                rules={[{ required: true }]}
              >
                <Select
                  showSearch
                  options={[
                    { value: "Asia/Shanghai", label: "上海 (Asia/Shanghai)" },
                    { value: "America/New_York", label: "纽约 (America/New_York)" },
                    { value: "Europe/London", label: "伦敦 (Europe/London)" },
                    { value: "Asia/Tokyo", label: "东京 (Asia/Tokyo)" },
                    { value: "UTC", label: "UTC" },
                  ]}
                />
              </Form.Item>
              <Form.Item
                label="语言 (Locale)"
                name="locale"
                style={{ flex: 1 }}
                rules={[{ required: true }]}
              >
                <Input placeholder="zh-CN, en-US" />
              </Form.Item>
            </div>
          </Form>
        </Modal>

        <Modal
          title={
            <span>
              <ToolOutlined /> 部署调试环境 - {currentToolDevice?.name}
            </span>
          }
          open={isToolModalOpen}
          onCancel={() => setIsToolModalOpen(false)}
          footer={null}
          width={480}
        >
          {/* ... (Tools List Content) ... */}
          <List
            itemLayout="horizontal"
            dataSource={toolsList}
            renderItem={(item) => {
              const isSelected = selectedToolId === item.id;
              return (
                <div
                  style={{
                    border: isSelected
                      ? `1px solid ${token.colorPrimary}`
                      : "1px solid #f0f0f0",
                    borderRadius: 8,
                    marginBottom: 8,
                    padding: "8px 16px",
                    transition: "all 0.2s",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 12 }}
                    >
                      <Avatar
                        icon={item.icon}
                        style={{
                          backgroundColor: token.colorBgLayout,
                          color: "inherit",
                        }}
                      />
                      <div>
                        <div style={{ fontWeight: 600 }}>{item.name}</div>
                        <div style={{ fontSize: 12, color: "#999" }}>
                          {item.desc}
                        </div>
                      </div>
                    </div>
                    {(item.hasVersions || item.hasArch) && !isSelected ? (
                      <Button
                        type="default"
                        size="small"
                        onClick={() => setSelectedToolId(item.id)}
                      >
                        配置
                      </Button>
                    ) : (
                      <Button
                        type="primary"
                        size="small"
                        icon={<CloudDownloadOutlined />}
                        onClick={() => handleDeployTool(item)}
                      >
                        安装
                      </Button>
                    )}
                  </div>
                  {isSelected && (item.hasVersions || item.hasArch) && (
                    <div
                      style={{
                        marginTop: 12,
                        paddingTop: 12,
                        borderTop: "1px dashed #eee",
                      }}
                    >
                      <div
                        style={{
                          marginBottom: 12,
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          background: "#f5f7fa",
                          padding: "8px 12px",
                          borderRadius: 6,
                        }}
                      >
                        <span style={{ fontSize: 12, color: "#666" }}>
                          当前设备架构:
                        </span>
                        <Tag color="blue" style={{ margin: 0, fontWeight: 600 }}>
                          {installConfig.arch === "arm64"
                            ? "arm64-v8a (64位)"
                            : installConfig.arch === "arm"
                              ? "armeabi-v7a (32位)"
                              : installConfig.arch}
                        </Tag>
                      </div>
                      <Form layout="inline" size="small">
                        {item.hasVersions && (
                          <Form.Item label="版本">
                            <Select
                              value={installConfig.version}
                              onChange={(v) =>
                                setInstallConfig((prev) => ({
                                  ...prev,
                                  version: v,
                                }))
                              }
                              style={{ width: 120 }}
                              loading={loadingVersions}
                              options={fridaVersions.map((v) => ({
                                label: v,
                                value: v,
                              }))}
                            />
                          </Form.Item>
                        )}
                        {item.id === "frida" && (
                          <Form.Item label="隐身模式" tooltip="重命名进程以绕过检测">
                            <Switch
                              checked={useStealthMode}
                              onChange={setUseStealthMode}
                              checkedChildren="开启"
                              unCheckedChildren="关闭"
                            />
                          </Form.Item>
                        )}
                        {item.hasArch && (
                          <Form.Item label="架构">
                            <Select
                              value={installConfig.arch}
                              onChange={(v) =>
                                setInstallConfig((prev) => ({ ...prev, arch: v }))
                              }
                              style={{ width: 160 }}
                              options={ARCH_OPTIONS}
                            />
                          </Form.Item>
                        )}
                      </Form>
                      <div
                        style={{
                          marginTop: 8,
                          fontSize: 12,
                          color: token.colorPrimary,
                        }}
                      >
                        * 已根据设备自动推荐架构，通常无需修改
                      </div>
                    </div>
                  )}
                </div>
              );
            }}
          />
        </Modal>
        <Modal
          title="添加模型服务商"
          open={isAddModelModalOpen}
          onCancel={() => setIsAddModelModalOpen(false)}
          onOk={() => {
            // ✅ 修改：提交表单并获取数据
            addModelForm
              .validateFields()
              .then((values) => {
                // values 包含表单字段：{ name, baseUrl, modelId }

                // 1. 构造新的选项对象
                const newProvider = {
                  value: values.name, // 或者生成一个唯一ID
                  label: values.name,
                };

                // 2. 更新状态：将新选项追加到列表末尾
                setProviders([...providers, newProvider]);

                // 3. 重置表单并关闭弹窗
                addModelForm.resetFields();
                setIsAddModelModalOpen(false);
                message.success(`成功添加服务商: ${values.name}`);
              })
              .catch((info) => {
                console.log("Validate Failed:", info);
              });
          }}
          okText="保存"
          cancelText="取消"
          width={480}
        >
          <Form form={addModelForm} layout="vertical" style={{ marginTop: 20 }}>
            <Form.Item
              label="服务商名称"
              name="name"
              rules={[{ required: true, message: "请输入服务商名称" }]}
              tooltip="显示在下拉列表中的名称"
            >
              <Input placeholder="例如: Moonshot (Kimi), 通义千问" autoFocus />
            </Form.Item>

            <Form.Item
              label="API Base URL"
              name="baseUrl"
              rules={[{ required: true, message: "请输入 API 地址" }]}
              tooltip="OpenAI 格式的接口地址"
            >
              <Input placeholder="https://api.moonshot.cn/v1" />
            </Form.Item>

            <Form.Item
              label="默认模型 ID"
              name="modelId"
              tooltip="该服务商的主力模型名称"
            >
              <Input placeholder="例如: moonshot-v1-8k" />
            </Form.Item>

            <div
              style={{
                fontSize: 12,
                color: "#999",
                backgroundColor: "#f5f5f5",
                padding: 10,
                borderRadius: 6,
              }}
            >
              <InfoCircleOutlined style={{ marginRight: 6 }} />
              目前仅支持兼容 <strong>OpenAI 接口格式</strong> 的服务商。
            </div>
          </Form>
        </Modal>
        <Modal
          open={isSettingsOpen}
          onCancel={() => setIsSettingsOpen(false)}
          footer={null}
          width={840} // 加宽一点，适合左右布局
          centered
          styles={{ body: { padding: 0 } }} // 移除默认 padding，自己控制布局
          closeIcon={null} // 隐藏默认关闭按钮，我们自己画或者不需要
        >
          <div
            style={{
              display: "flex",
              height: "500px",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {/* === 左侧：导航栏 === */}
            <div
              style={{
                width: 150,
                backgroundColor: "#f5f5f5",
                borderRight: "1px solid #e8e8e8",
                padding: "20px 0",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  padding: "0 20px 20px",
                  fontWeight: 600,
                  fontSize: 18,
                  color: "#333",
                }}
              >
                设置
              </div>

              {[
                { key: "general", icon: <LaptopOutlined />, label: "通用设置" },
                { key: "env", icon: <ApiOutlined />, label: "逆向环境" },
                { key: "tools", icon: <ToolOutlined />, label: "工具配置" },
                { key: "ai", icon: <RobotOutlined />, label: "AI配置" },
                { key: "about", icon: <InfoCircleOutlined />, label: "关于" },
              ].map((item) => (
                <div
                  key={item.key}
                  onClick={() => setActiveSettingTab(item.key as SettingTab)}
                  style={{
                    padding: "10px 24px",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    fontSize: 14,
                    backgroundColor:
                      activeSettingTab === item.key ? "#fff" : "transparent",
                    color:
                      activeSettingTab === item.key ? token.colorPrimary : "#666",
                    borderLeft:
                      activeSettingTab === item.key
                        ? `3px solid ${token.colorPrimary}`
                        : "3px solid transparent",
                    transition: "all 0.2s",
                  }}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </div>
              ))}
            </div>

            {/* === 右侧：内容区域 === */}
            <div
              style={{
                flex: 1,
                padding: "24px 32px",
                overflowY: "auto",
                backgroundColor: "#fff",
              }}
            >
              {/* 1. 通用设置 */}
              {activeSettingTab === "general" && (
                <div>
                  <h3 style={{ marginBottom: 24 }}>通用设置</h3>

                  <div style={{ marginBottom: 24 }}>
                    <div style={{ fontWeight: 500, marginBottom: 8 }}>
                      主题偏好
                    </div>
                    <div style={{ display: "flex", gap: 16 }}>
                      {/* 模拟的主题选择卡片 */}
                      {["Light", "Dark", "Auto"].map((themeName) => (
                        <div
                          key={themeName}
                          style={{
                            border:
                              themeName === "Light"
                                ? `2px solid ${token.colorPrimary}`
                                : "1px solid #d9d9d9",
                            borderRadius: 8,
                            padding: "12px 24px",
                            cursor: "pointer",
                            textAlign: "center",
                            minWidth: 80,
                            backgroundColor:
                              themeName === "Light" ? "#e6f7ff" : "#fff",
                          }}
                        >
                          <BgColorsOutlined
                            style={{
                              fontSize: 20,
                              marginBottom: 8,
                              display: "block",
                            }}
                          />
                          <span style={{ fontSize: 13 }}>
                            {themeName === "Light"
                              ? "明亮"
                              : themeName === "Dark"
                                ? "暗黑"
                                : "跟随系统"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <Divider />

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 20,
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 500 }}>自动连接设备</div>
                      <div style={{ fontSize: 12, color: "#999" }}>
                        启动时自动尝试连接上次使用的设备
                      </div>
                    </div>
                    <Switch defaultChecked />
                  </div>

                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 500 }}>硬件加速</div>
                      <div style={{ fontSize: 12, color: "#999" }}>
                        使用 GPU 渲染界面 (可能增加内存占用)
                      </div>
                    </div>
                    <Switch defaultChecked />
                  </div>
                </div>
              )}

              {/* 2. 环境配置 */}
              {activeSettingTab === "env" && (
                <div>
                  <h3 style={{ marginBottom: 24 }}>环境配置</h3>

                  <Form layout="vertical">
                    <Form.Item
                      label={
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            width: "100%",
                          }}
                        >
                          <div>
                            <span>ADB 路径</span>
                            <span
                              style={{
                                color: "#52c41a",
                                fontSize: 12,
                                marginLeft: 10,
                              }}
                            >
                              <CheckCircleFilled /> 检测正常
                            </span>
                          </div>
                        </div>
                      }
                    >
                      <Input
                        defaultValue="/Users/dev/platform-tools/adb"
                        addonAfter={
                          <FolderOpenOutlined style={{ cursor: "pointer" }} />
                        }
                      />
                      <div style={{ fontSize: 12, color: "#999", marginTop: 4 }}>
                        用于连接安卓设备，留空则使用内置 ADB
                      </div>
                    </Form.Item>

                    <Form.Item label="Java 路径 (JDK)">
                      <Input
                        placeholder="未配置"
                        addonAfter={
                          <FolderOpenOutlined style={{ cursor: "pointer" }} />
                        }
                        status="warning"
                      />
                      <div
                        style={{
                          fontSize: 12,
                          color: "#faad14",
                          marginTop: 4,
                          display: "flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        未检测到有效 JDK，Java 源码分析功能将受限
                      </div>
                    </Form.Item>

                    <Form.Item label="Python 解释器">
                      <Select defaultValue="system">
                        <Select.Option value="system">
                          系统默认 (/usr/bin/python3)
                        </Select.Option>
                        <Select.Option value="conda">
                          Conda Environment (base)
                        </Select.Option>
                        <Select.Option value="custom">自定义...</Select.Option>
                      </Select>
                    </Form.Item>

                    <Divider />

                    <div style={{ fontWeight: 500, marginBottom: 8 }}>
                      JADX工作区 (Workspace)
                    </div>
                    <Form.Item label="">
                      <div style={{ marginBottom: 24 }}>
                        <div style={{ display: "flex", gap: 10 }}>
                          <Input
                            value={workspacePath}
                            placeholder="默认存放在下载目录/ReTool_Workspace"
                            readOnly
                            prefix={
                              <FolderOpenOutlined style={{ color: "#999" }} />
                            }
                          />
                          <Button onClick={handleSelectWorkspace}>
                            更改目录
                          </Button>
                        </div>
                        <div
                          style={{ fontSize: 12, color: "#999", marginTop: 4 }}
                        >
                          反编译后的源码将存放在此目录下，避免污染项目根目录。
                        </div>
                      </div>
                    </Form.Item>
                  </Form>
                </div>
              )}

              {/* 3. 工具配置 */}
              {activeSettingTab === "tools" && (
                <div>
                  <h3 style={{ marginBottom: 24 }}>工具配置</h3>
                  <Form layout="vertical">
                    <Form.Item label="Frida Server 默认版本">
                      <Select
                        value={installConfig.version}
                        onChange={(v) => setInstallConfig(prev => ({ ...prev, version: v }))}
                      >
                        {fridaVersions.map(v => (
                          <Select.Option key={v} value={v}>{v}</Select.Option>
                        ))}
                      </Select>
                      <div style={{ fontSize: 12, color: "#999", marginTop: 4 }}>
                        向设备部署 Frida 时默认选中的版本
                      </div>
                    </Form.Item>

                    <Form.Item label="反编译引擎">
                      <Radio.Group defaultValue="jadx">
                        <Radio value="jadx">JADX (速度快)</Radio>
                        <Radio value="fernflower">Fernflower (IDEA 内置)</Radio>
                      </Radio.Group>
                    </Form.Item>

                    <Divider />

                    {/* 🔥 新增：部署调试工具区域 */}
                    <h4 style={{ marginBottom: 16 }}>部署调试工具</h4>

                    <Form.Item label="选择目标设备">
                      <Select
                        placeholder="请选择设备"
                        value={currentToolDevice?.id}
                        onChange={(deviceId) => {
                          const dev = devices.find(d => d.id === deviceId);
                          if (dev) {
                            setCurrentToolDevice(dev);
                            detectAbi(dev);
                          }
                        }}
                      >
                        {devices.filter(d => d.type === "android").map(dev => (
                          <Select.Option key={dev.id} value={dev.id}>
                            {deviceAliases[dev.id] || dev.name}
                          </Select.Option>
                        ))}
                      </Select>
                    </Form.Item>

                    <Form.Item label="设备架构">
                      <Select
                        value={installConfig.arch}
                        onChange={(v) => setInstallConfig(prev => ({ ...prev, arch: v }))}
                      >
                        <Select.Option value="arm64">arm64 (推荐)</Select.Option>
                        <Select.Option value="arm">arm</Select.Option>
                        <Select.Option value="x86_64">x86_64</Select.Option>
                        <Select.Option value="x86">x86</Select.Option>
                      </Select>
                    </Form.Item>

                    <div style={{ display: "flex", gap: 12, marginTop: 16 }}>
                      <Button
                        type="primary"
                        icon={<BugOutlined />}
                        disabled={!currentToolDevice}
                        onClick={() => {
                          const fridaTool = toolsList.find(t => t.id === "frida");
                          if (fridaTool) handleDeployTool(fridaTool);
                        }}
                      >
                        部署 Frida Server
                      </Button>
                      <Button
                        icon={<RocketOutlined />}
                        onClick={() => {
                          Modal.info({
                            title: "编译 Frida Server 魔改版",
                            width: 500,
                            content: (
                              <div>
                                <p>魔改版 Frida 需要从源码编译以绕过检测。</p>
                                <p style={{ marginTop: 12 }}>推荐方案：</p>
                                <ul style={{ paddingLeft: 20 }}>
                                  <li>修改 Frida 特征字符串 (frida → fr1da)</li>
                                  <li>修改端口号 (27042 → 随机)</li>
                                  <li>修改二进制名称 (frida-server → myserver)</li>
                                </ul>
                                <p style={{ marginTop: 12, color: "#999" }}>
                                  详细教程请参考：
                                  <a href="https://github.com/AbiaoProject/frida-builder" target="_blank" rel="noreferrer">
                                    Frida Builder
                                  </a>
                                </p>
                              </div>
                            ),
                          });
                        }}
                      >
                        编译 Frida Server 魔改版
                      </Button>
                    </div>

                    <div style={{ fontSize: 12, color: "#999", marginTop: 8 }}>
                      魔改版 Frida 通过修改特征字符串和端口号来绕过部分检测。
                    </div>

                  </Form>
                </div>
              )}


              {/* ai配置 */}
              {activeSettingTab === "ai" && (
                <div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 24,
                    }}
                  >
                    <h3 style={{ margin: 0 }}>AI 模型管理</h3>
                    <Button
                      type="primary"
                      icon={<PlusOutlined />}
                      onClick={() => handleOpenAiConfig(null)}
                    >
                      添加模型
                    </Button>
                  </div>

                  {/* 核心表格 */}
                  <Table
                    dataSource={aiConfigs}
                    rowKey="id"
                    pagination={false}
                    size="small"
                    columns={[
                      {
                        title: "状态",
                        key: "isActive",
                        width: 80,
                        render: (_, record) => (
                          <div
                            style={{ cursor: "pointer", textAlign: "center" }}
                            onClick={() => handleSetActive(record.id!)}
                          >
                            {record.isActive ? (
                              <Tag color="success" icon={<CheckCircleFilled />}>
                                使用中
                              </Tag>
                            ) : (
                              <Tag color="default">备用</Tag>
                            )}
                          </div>
                        ),
                      },
                      {
                        title: "名称",
                        dataIndex: "name",
                        key: "name",
                        render: (text) => <strong>{text}</strong>,
                      },
                      {
                        title: "服务商",
                        dataIndex: "provider",
                        key: "provider",
                        render: (text) => {
                          const colors: Record<string, string> = {
                            openai: "green",
                            deepseek: "blue",
                            anthropic: "purple",
                            custom: "orange",
                          };
                          return (
                            <Tag color={colors[text] || "default"}>
                              {text.toUpperCase()}
                            </Tag>
                          );
                        },
                      },
                      {
                        title: "模型ID",
                        dataIndex: "modelId",
                        key: "modelId",
                        render: (text) => (
                          <span style={{ color: "#999", fontSize: 12 }}>
                            {text}
                          </span>
                        ),
                      },
                      {
                        title: "操作",
                        key: "action",
                        render: (_, record) => (
                          <Space size="small">
                            <Button
                              type="text"
                              size="small"
                              icon={<EditOutlined />}
                              onClick={() => handleOpenAiConfig(record)}
                            />
                            <Popconfirm
                              title="确定删除吗？"
                              onConfirm={() => handleDeleteAiConfig(record.id!)}
                              okText="是"
                              cancelText="否"
                            >
                              <Button
                                type="text"
                                danger
                                size="small"
                                icon={<DeleteOutlined />}
                                disabled={record.isActive} // 正在使用的不能删
                              />
                            </Popconfirm>
                          </Space>
                        ),
                      },
                    ]}
                  />

                  <div
                    style={{
                      marginTop: 24,
                      padding: 16,
                      backgroundColor: "#f9f9f9",
                      borderRadius: 8,
                    }}
                  >
                    <div
                      style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}
                    >
                      全局提示词 (System Prompt)
                    </div>
                    <Input.TextArea
                      rows={3}
                      placeholder="设置全局的系统提示词，对所有模型生效..."
                      defaultValue="你是一个精通 Android 逆向工程的安全专家。"
                      style={{ resize: "none", backgroundColor: "#fff" }}
                    />
                  </div>
                </div>
              )}

              {/* 4. 关于 */}
              {activeSettingTab === "about" && (
                <div style={{ textAlign: "center", padding: "40px 0" }}>
                  <Avatar
                    size={64}
                    icon={<ThunderboltFilled />}
                    style={{
                      backgroundColor: token.colorPrimary,
                      marginBottom: 16,
                    }}
                  />
                  <h2 style={{ marginBottom: 8 }}>逆向工作台</h2>
                  <p style={{ color: "#999", marginBottom: 24 }}>
                    Version 1.0.0 (Beta)
                  </p>
                  <div
                    style={{ display: "flex", gap: 12, justifyContent: "center" }}
                  >
                    <Button>检查更新</Button>
                    <Button
                      type="primary"
                      href="https://github.com"
                      target="_blank"
                    >
                      GitHub
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </Modal>
        {/* ==================== ✅ 新增：AI 配置 添加/编辑 弹窗 ==================== */}
        <Modal
          title={editingConfig ? "编辑模型配置" : "添加新模型"}
          open={isAiConfigModalOpen}
          onOk={handleSaveAiConfig}
          onCancel={() => setIsAiConfigModalOpen(false)}
          width={500}
          okText="保存"
          cancelText="取消"
          destroyOnClose
        >
          <Form form={aiConfigForm} layout="vertical" style={{ marginTop: 20 }}>
            <Form.Item
              label="配置名称 (Alias)"
              name="name"
              rules={[{ required: true, message: "起个名字吧，比如: 公司GPT" }]}
            >
              <Input placeholder="例如: 我的 DeepSeek, 公司 GPT-4" />
            </Form.Item>

            <div style={{ display: "flex", gap: 16 }}>
              <Form.Item label="服务商" name="provider" style={{ flex: 1 }}>
                <Select>
                  <Select.Option value="openai">OpenAI</Select.Option>
                  <Select.Option value="deepseek">DeepSeek</Select.Option>
                  <Select.Option value="anthropic">Anthropic</Select.Option>
                  <Select.Option value="custom">Custom / Local</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item
                label="模型 ID"
                name="modelId"
                style={{ flex: 1 }}
                rules={[{ required: true, message: "请输入模型ID" }]}
              >
                <Input placeholder="例如: gpt-4o, deepseek-chat" />
              </Form.Item>
            </div>

            <Form.Item
              label="API Key"
              name="apiKey"
              rules={[{ required: true, message: "请输入 API Key" }]}
            >
              <Input.Password placeholder="sk-..." />
            </Form.Item>

            <Form.Item
              label="API 代理地址 (Base URL)"
              name="baseUrl"
              rules={[{ required: true, message: "请输入 Base URL" }]}
            >
              <Input placeholder="https://api.openai.com/v1" />
            </Form.Item>
          </Form>
        </Modal>
        <Modal
          title="重命名对话"
          open={isAiRenameModalOpen}
          onOk={handleRenameSubmit}
          onCancel={() => setIsAiRenameModalOpen(false)}
          okText="保存"
          cancelText="取消"
          width={400}
          // 建议加上 destroyOnClose，确保每次打开都重新渲染 Input，触发 autoFocus
          destroyOnClose
        >
          <Input
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            onPressEnter={handleRenameSubmit}
            // 1. 自动获取焦点
            autoFocus
            // 2. 核心修改：当获得焦点时，执行全选操作
            onFocus={(e) => e.target.select()}
          />
        </Modal>
      </div>

      {/* Environment Configuration Modal */}
      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SettingOutlined />
            <span>环境伪造配置</span>
          </div>
        }
        open={isEnvModalOpen && !!editingEnvInstanceId}
        onCancel={() => setIsEnvModalOpen(false)}
        footer={null}
        width={400}
      >
        {(() => {
          const instance = browserInstances.find(i => i.id === editingEnvInstanceId);
          if (!instance) return null;
          const env = instance.env || { stealth: true, headless: false };
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16, paddingTop: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span>隐身模式 (Stealth)</span>
                  <span style={{ fontSize: 12, color: '#999' }}>自动抹除 CDP/WebDriver 指纹</span>
                </div>
                <Switch
                  checked={env.stealth}
                  onChange={(checked) => handleUpdateEnvConfig('stealth', checked)}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span>无头模式 (Headless)</span>
                  <span style={{ fontSize: 12, color: '#999' }}>后台静默运行，不显示界面</span>
                </div>
                <Switch
                  checked={env.headless}
                  onChange={(checked) => handleUpdateEnvConfig('headless', checked)}
                />
              </div>
            </div>
          );
        })()}
      </Modal>

      {/* RPC Configuration Modal */}
      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ThunderboltFilled style={{ color: '#faad14' }} />
            <span>RPC 桥接服务配置</span>
          </div>
        }
        open={isRpcModalOpen && !!targetRpcInstance}
        onCancel={() => setIsRpcModalOpen(false)}
        footer={null}
        width={400}
      >
        {targetRpcInstance && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, paddingTop: 8 }}>
            <div style={{ backgroundColor: '#fffbe6', border: '1px solid #ffe58f', padding: 12, borderRadius: 6, fontSize: 13, color: '#d48806' }}>
              <InfoCircleOutlined style={{ marginRight: 6 }} />
              开启 RPC 服务后，您可以通过 WebSocket 连接到该端口进行远程指令控制。
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>服务端口 (WS)</span>
              <Input
                type="number"
                value={rpcPortInput}
                onChange={e => setRpcPortInput(Number(e.target.value))}
                style={{ width: 120 }}
                disabled={targetRpcInstance.rpc?.enabled}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 }}>
              <span style={{ fontWeight: 600 }}>服务状态</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {targetRpcInstance.status !== "running" && (
                  <span style={{ fontSize: 12, color: '#ff4d4f' }}>需启动浏览器</span>
                )}
                <Switch
                  checkedChildren="已开启"
                  unCheckedChildren="已关闭"
                  disabled={targetRpcInstance.status !== "running"}
                  checked={targetRpcInstance.status === "running" && !!targetRpcInstance.rpc?.enabled}
                  onChange={(checked) => handleToggleRpc(checked)}
                />
              </div>
            </div>

            {targetRpcInstance.rpc?.enabled && targetRpcInstance.rpc && targetRpcInstance.status === "running" && (
              <div style={{ marginTop: 8, padding: 12, backgroundColor: '#f6ffed', border: '1px solid #b7eb8f', borderRadius: 6, textAlign: 'center' }}>
                <CheckCircleFilled style={{ color: '#52c41a', marginRight: 6 }} />
                <span style={{ color: '#237804', fontWeight: 500 }}>ws://127.0.0.1:{targetRpcInstance.rpc.port}</span>
              </div>
            )}
          </div>
        )}
      </Modal>
    </>
  );
};

export default Sidebar;
