import React, { useState, useEffect } from "react";
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
} from "antd";
import { Device, ViewMode } from "../types";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

interface SidebarProps {
  currentView: ViewMode;
  onViewChange: (view: ViewMode) => void;
  devices: Device[];
  selectedDeviceId: string;
  onDeviceSelect: (id: string) => void;
  onRefresh?: () => void;
  deviceAliases: Record<string, string>;
  onRenameDevice: (id: string, name: string) => void;
}

interface ToolItem {
  id: string;
  name: string;
  desc: string;
  icon: React.ReactNode;
  hasVersions?: boolean;
  hasArch?: boolean;
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

// 🔥 修改：改名为默认列表
const DEFAULT_FRIDA_VERSIONS = ["16.2.1", "16.1.4", "15.2.2", "14.2.18"];

const ARCH_OPTIONS = [
  { label: "arm64-v8a (64位)", value: "arm64" },
  { label: "armeabi-v7a (32位)", value: "arm" },
  { label: "x86_64 (模拟器)", value: "x86_64" },
  { label: "x86 (模拟器)", value: "x86" },
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
}) => {
  const { token } = theme.useToken();

  // --- 状态管理 ---
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const [ipAddress, setIpAddress] = useState("");
  const [connecting, setConnecting] = useState(false);

  const [isRenameModalOpen, setIsRenameModalOpen] = useState(false);
  const [currentRenameDevice, setCurrentRenameDevice] = useState<Device | null>(
    null
  );
  const [newDeviceName, setNewDeviceName] = useState("");

  // 部署工具状态
  const [isToolModalOpen, setIsToolModalOpen] = useState(false);
  const [currentToolDevice, setCurrentToolDevice] = useState<Device | null>(
    null
  );

  // 🔥 修改：初始化使用默认列表
  const [fridaVersions, setFridaVersions] = useState<string[]>(
    DEFAULT_FRIDA_VERSIONS
  );
  const [loadingVersions, setLoadingVersions] = useState(false);

  // 选中的配置
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [installConfig, setInstallConfig] = useState({
    version: DEFAULT_FRIDA_VERSIONS[0], // 🔥 使用默认列表第一项
    arch: "arm64",
  });

  // 🔥 新增状态：记录每个设备的 Frida 状态 { "device_id": true/false }
  const [fridaStatusMap, setFridaStatusMap] = useState<Record<string, boolean>>(
    {}
  );

  // 🔥 新增：Root 状态
  const [rootStatusMap, setRootStatusMap] = useState<Record<string, boolean>>(
    {}
  );

  // 🔥 新增：批量检查 Root 状态
  const checkAllRootStatus = async () => {
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

  // 🔥 新增：批量检查所有设备的 Frida 状态
  const checkAllFridaStatus = async () => {
    const statusMap: Record<string, boolean> = {};

    // 并行检查所有安卓设备
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

  // 修改 useEffect，同时检查 Frida 和 Root
  useEffect(() => {
    if (devices.length > 0) {
      checkAllFridaStatus();
      checkAllRootStatus(); // 🔥 调用检查
    }
    const timer = setInterval(() => {
      checkAllFridaStatus();
      // Root 状态通常不会变，可以不频繁轮询，或者设置较长间隔
      // 这里为了简单，一起轮询也没问题
      checkAllRootStatus();
    }, 5000);
    return () => clearInterval(timer);
  }, [devices]);

  // --- 获取 Frida 版本 ---
  const fetchFridaVersions = async () => {
    setLoadingVersions(true);
    try {
      const versions = await invoke<string[]>("get_frida_versions");
      // 更新状态为真实列表
      setFridaVersions(versions);

      // 如果获取到了版本，自动选中最新的
      if (versions.length > 0) {
        setInstallConfig((prev) => ({ ...prev, version: versions[0] }));
      }
      message.success("已获取最新 Frida 版本列表");
    } catch (e) {
      console.error(e);
      // 失败时不覆盖，保持使用默认列表
      message.error("获取版本失败，使用内置列表");
    } finally {
      setLoadingVersions(false);
    }
  };

  // --- 自动检测架构 ---
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

  // 打开弹窗逻辑
  const openToolModal = (device: Device) => {
    setCurrentToolDevice(device);
    setIsToolModalOpen(true);
    setSelectedToolId(null);
    detectAbi(device);

    // 🔥 每次打开都尝试获取最新版本（或者加个 flag 控制只获取一次）
    fetchFridaVersions();
  };

  // --- 1. 核心功能：连接 IP 设备 (云手机/局域网) ---
  const handleConnectCloud = async () => {
    if (!ipAddress) {
      message.warning("请输入 IP 地址");
      return;
    }
    setConnecting(true);
    try {
      // 调用后端 adb connect
      await invoke("adb_pair", { address: ipAddress });
      message.success(`成功连接到 ${ipAddress}`);

      // 连接成功后的清理工作
      setIsConnectModalOpen(false);
      setIpAddress(""); // 清空输入框以便下次使用

      // 自动刷新列表，让用户立即看到新设备
      if (onRefresh) onRefresh();
    } catch (error: any) {
      message.error(error); // 显示后端的错误信息
    } finally {
      setConnecting(false);
    }
  };

  // --- 2. 安装应用 ---
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

    // 1. 准备参数
    const version = tool.hasVersions ? installConfig.version : "latest";
    const arch = tool.hasArch ? installConfig.arch : "all";

    // --- 定义核心安装过程 ---
    const executeDeploy = async () => {
      const hideLoading = message.loading(
        `正在下载并部署 ${tool.name} (${version})...`,
        0
      );

      try {
        const result = await invoke<string>("deploy_tool", {
          deviceId: currentToolDevice.id,
          toolId: tool.id,
          version: version,
          arch: arch,
        });

        hideLoading();
        message.success(result);

        // Frida 安装后的引导
        if (tool.id === "frida") {
          Modal.confirm({
            title: "部署成功",
            content: "Frida Server 已就绪。是否立即启动服务？",
            okText: "启动",
            cancelText: "稍后",
            onOk: async () => {
              try {
                // 1. 先尝试清理旧进程 (忽略错误)
                try {
                  await invoke("run_command", {
                    cmd: "adb",
                    args: [
                      "-s",
                      currentToolDevice.id,
                      "shell",
                      "su -c 'pkill -f frida-server'",
                    ],
                  });
                } catch (e) {}

                // 2. 执行“究极启动命令”
                // setenforce 0: 关闭 SELinux 限制 (关键！)
                // chmod 755: 确保有执行权限
                // nohup ... &: 后台静默运行
                await invoke("run_command", {
                  cmd: "adb",
                  args: [
                    "-s",
                    currentToolDevice.id,
                    "shell",
                    // 注意：这里用分号 ; 连接命令，即使 setenforce 失败也会继续执行后面
                    "su -c 'setenforce 0; chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'",
                  ],
                });

                message.success(
                  "Frida Server 已在后台启动 (SELinux: Permissive)"
                );
              } catch (e: any) {
                console.error("启动详情报错:", e); // 🔥 在控制台打印真实错误
                // 把 e 显示出来，而不是只显示固定文案，方便排查
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

    // --- 🔥 冲突检测逻辑 ---
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
            okType: "danger", // 红色按钮示警
            cancelText: "取消",
            onOk: executeDeploy, // 用户确认后才执行
          });
          return; // 阻断直接安装
        }
      } catch (e) {
        console.warn("检测 Frida 状态失败，直接尝试安装", e);
      }
    }

    // 如果不是 Frida 或者没检测到旧版，直接安装
    executeDeploy();
  };

  // --- 3. 重命名逻辑 ---
  const handleRenameSubmit = () => {
    if (currentRenameDevice && newDeviceName.trim()) {
      onRenameDevice(currentRenameDevice.id, newDeviceName.trim());
      message.success("重命名成功");
      setIsRenameModalOpen(false);
    }
  };

  // --- 4. 转为无线连接 (USB -> WiFi) ---
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

  // 菜单点击分发
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

  // src/components/Sidebar.tsx

  // --- 启动 Frida (严谨版：检测安装 -> 启动 -> 验证运行) ---
  const handleStartFrida = async (device: Device) => {
    const hideCheckLoading = message.loading("正在检测环境...", 0);

    try {
      // 1. 核心检测：文件是否存在？
      const isInstalled = await invoke<boolean>("check_frida_installed", {
        deviceId: device.id,
      });

      hideCheckLoading();

      // --- 分支 A：未安装 ---
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
            // 打开部署弹窗并自动选中 Frida
            openToolModal(device);
            setSelectedToolId("frida");
          },
        });
        return; // ⛔ 终止后续逻辑
      }

      // --- 分支 B：已安装，开始启动 ---
      const hideStartLoading = message.loading("正在启动 Frida Server...", 0);

      // 执行启动命令 (带 SELinux 绕过)
      await invoke("run_command", {
        cmd: "adb",
        args: [
          "-s",
          device.id,
          "shell",
          "su -c 'setenforce 0; chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'",
        ],
      });

      // 🔥 关键步骤：等待 2 秒后，验证进程是否真的活着
      // 很多时候命令发送成功了，但进程瞬间 crash 掉了（比如架构选错了）
      setTimeout(async () => {
        try {
          const isRunning = await invoke<boolean>("check_frida_running", {
            deviceId: device.id,
          });

          hideStartLoading();

          if (isRunning) {
            message.success("Frida Server 启动成功！");
            checkAllFridaStatus(); // 刷新图标
          } else {
            // 命令没报错，但进程没了 -> 启动失败
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
      }, 2000); // 给它 2 秒钟启动时间
    } catch (e) {
      hideCheckLoading();
      message.error("检测失败，请检查 ADB 连接");
    }
  };

  // --- 停止 Frida ---
  const handleStopFrida = async (device: Device) => {
    const hideLoading = message.loading("正在停止 Frida Server...", 0);
    try {
      // 杀进程命令
      await invoke("run_command", {
        cmd: "adb",
        args: [
          "-s",
          device.id,
          "shell",
          "su -c 'pkill -f frida-server'", // 使用 pkill 杀掉所有相关进程
        ],
      });
      setTimeout(() => {
        hideLoading();
        message.success("Frida Server 已停止");
        checkAllFridaStatus(); // 刷新状态图标
      }, 1000);
    } catch (e) {
      hideLoading();
      message.error("停止失败");
    }
  };

  const getDeviceMenuItems = (device: Device): MenuProps["items"] => [
    // ... 菜单项保持不变
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
    { type: "divider" },
    // 🔥 动态 Frida 控制菜单
    // 只有 Android 设备才显示此选项
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
          danger: fridaStatusMap[device.id], // 停止操作标红
          onClick: () => {
            if (fridaStatusMap[device.id]) {
              handleStopFrida(device);
            } else {
              handleStartFrida(device);
            }
          },
        }
      : null,
    {
      key: "deploy",
      label: "部署调试工具",
      icon: <ToolOutlined />,
      onClick: () => openToolModal(device),
    },
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

  return (
    <div className="sidebar">
      {/* ... 头部、设备列表保持不变 ... */}
      <div className="sidebar-header">
        <ThunderboltFilled style={{ color: "var(--accent-color)" }} />{" "}
        逆向工作台
      </div>
      <div
        className="sidebar-section-title"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingRight: 18,
        }}
      >
        <span>已连接设备</span>
        <PlusCircleOutlined
          style={{
            cursor: "pointer",
            fontSize: 14,
            color: "var(--accent-color)",
          }}
          onClick={() => setIsConnectModalOpen(true)}
        />
      </div>

      {devices.map((dev) => (
        // ... 设备项渲染保持不变 ...
        <div
          key={dev.id}
          className={`nav-item-split ${
            currentView === "device" && selectedDeviceId === dev.id
              ? "active"
              : ""
          }`}
        >
          <div
            className="nav-item-main"
            onClick={() => {
              onViewChange("device");
              onDeviceSelect(dev.id);
            }}
          >
            {dev.type === "android" ? <AndroidFilled /> : <AppleFilled />}
            <div
              style={{
                flex: 1,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                fontSize: 13,
                fontWeight: 500,
              }}
            >
              {deviceAliases[dev.id] || dev.name}
            </div>
            {/* 图标区域：使用 Flex 布局排列多个图标 */}
            <div style={{ display: "flex", gap: 4 }}>
              {/* 原有的 Frida 指示器 (红色小虫子) */}
              {fridaStatusMap[dev.id] && (
                <Tooltip title="Frida Server 运行中">
                  <BugOutlined
                    style={{ color: "#ff4d4f", fontSize: 13, padding: "0 3px" }}
                  />
                </Tooltip>
              )}

              {/* 🔥 新增：Root 指示器 (金色开锁图标) */}
              {rootStatusMap[dev.id] && (
                <Tooltip title="设备已 Root">
                  <UnlockOutlined
                    style={{ color: "#faad14", fontSize: 13, padding: "0 3px" }}
                  />
                </Tooltip>
              )}
            </div>
            <span
              className="status-indicator"
              style={{
                background: dev.status === "online" ? "#10b981" : "#ccc",
                margin: 0,
                marginRight: 5,
                flexShrink: 0,
              }}
            />
          </div>
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
        </div>
      ))}

      {/* ... 工具箱 ... */}
      <div className="sidebar-section-title">工具箱</div>
      <div
        className={`nav-item ${currentView === "script-lab" ? "active" : ""}`}
        onClick={() => onViewChange("script-lab")}
      >
        <ExperimentOutlined /> <span>脚本工坊</span>
      </div>
      <div
        className={`nav-item ${
          currentView === "algo-converter" ? "active" : ""
        }`}
        onClick={() => onViewChange("algo-converter")}
      >
        <CodeOutlined /> <span>伪代码转译</span>
      </div>
      <div
        className={`nav-item ${currentView === "so-analyzer" ? "active" : ""}`}
        onClick={() => onViewChange("so-analyzer")}
      >
        <FileZipOutlined /> <span>SO 文件分析</span>
      </div>
      <div
        className={`nav-item ${currentView === "asm-lab" ? "active" : ""}`}
        onClick={() => onViewChange("asm-lab")}
      >
        <BugOutlined /> <span>ARM 汇编实验室</span>
      </div>

      {/* ... 连接和重命名 Modal ... */}
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
        onOk={handleRenameSubmit}
        onCancel={() => setIsRenameModalOpen(false)}
        okText="确定"
        cancelText="取消"
      >
        <Input
          value={newDeviceName}
          onChange={(e) => setNewDeviceName(e.target.value)}
          onPressEnter={handleRenameSubmit}
          autoFocus
        />
      </Modal>

      {/* 🔥 部署工具选择弹窗 */}
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
                            loading={loadingVersions} // 🔥 显示 Loading
                            // 🔥 使用 state 里的 fridaVersions
                            options={fridaVersions.map((v) => ({
                              label: v,
                              value: v,
                            }))}
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
    </div>
  );
};

export default Sidebar;
