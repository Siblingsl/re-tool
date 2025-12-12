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
  FolderOpenOutlined,
  BuildOutlined,
  CoffeeOutlined,
  GatewayOutlined,
  CompassOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
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
  const [collapsed, setCollapsed] = useState(false);

  // --- 状态管理 ---
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
  const [rootStatusMap, setRootStatusMap] = useState<Record<string, boolean>>(
    {}
  );

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

  const checkAllFridaStatus = async () => {
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

  useEffect(() => {
    if (devices.length > 0) {
      checkAllFridaStatus();
      checkAllRootStatus();
    }
    const timer = setInterval(() => {
      checkAllFridaStatus();
      checkAllRootStatus();
    }, 5000);
    return () => clearInterval(timer);
  }, [devices]);

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
        const result = await invoke<string>("deploy_tool", {
          deviceId: currentToolDevice.id,
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
                      "su -c 'pkill -f frida-server'",
                    ],
                  });
                } catch (e) {}
                await invoke("run_command", {
                  cmd: "adb",
                  args: [
                    "-s",
                    currentToolDevice.id,
                    "shell",
                    "su -c 'setenforce 0; chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'",
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

  const handleRenameSubmit = () => {
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

  const handleStartFrida = async (device: Device) => {
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

  return (
    <div
      className="sidebar"
      style={{
        width: collapsed ? 80 : 250,
        transition: "width 0.2s cubic-bezier(0.2, 0, 0, 1) 0s",
        display: "flex",
        flexDirection: "column",
        height: "100%", // 关键：撑满父容器高度
        overflow: "hidden", // 关键：防止侧边栏整体滚动
        position: "relative",
      }}
    >
      {/* 隐藏滚动条的 CSS Hack */}
      <style>
        {`
          .no-scrollbar::-webkit-scrollbar {
            display: none;
          }
        `}
      </style>

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

      {/* 2. 设备列表标题栏 (固定) */}
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
            }}
            onClick={() => setIsConnectModalOpen(true)}
          />
        </Tooltip>
      </div>

      {/* 3. 设备列表区域 (独立滚动) */}
      <div
        className="no-scrollbar"
        style={{
          // 关键逻辑：
          // flex: "0 1 auto" 表示初始高度根据内容自适应，但允许缩小
          // maxHeight: "40%" 限制设备列表最多占据 40% 的高度，防止挤占工具箱
          flex: "0 1 auto",
          maxHeight: "40%",
          overflowY: "auto", // 开启垂直滚动
          overflowX: "hidden",
          scrollbarWidth: "none", // Firefox 隐藏滚动条
          msOverflowStyle: "none", // IE 隐藏滚动条
          marginBottom: 8,
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
              className={`nav-item-split ${
                currentView === "device" && selectedDeviceId === dev.id
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

      {/* 4. 工具箱标题栏 (固定) */}
      <div
        className="sidebar-section-title"
        style={{
          display: collapsed ? "none" : "block",
          marginBottom: 10,
          whiteSpace: "nowrap",
          flexShrink: 0, // 禁止被压缩
        }}
      >
        工具箱
      </div>
      {collapsed && (
        <div
          style={{
            height: 1,
            background: "#f0f0f0",
            margin: "8px 12px",
            flexShrink: 0,
          }}
        />
      )}

      {/* 5. 工具箱区域 (独立滚动，占据剩余空间) */}
      <div
        className="no-scrollbar"
        style={{
          flex: 1, // 占据剩余的所有垂直空间
          overflowY: "auto", // 开启垂直滚动
          overflowX: "hidden",
          scrollbarWidth: "none",
          msOverflowStyle: "none",
        }}
      >
        {renderNavItem(
          "network-sniffer",
          <GatewayOutlined />,
          "一键抓包 (Mitmproxy)"
        )}
        {renderNavItem("script-lab", <ExperimentOutlined />, "脚本工坊")}
        {renderNavItem("apk-builder", <BuildOutlined />, "APK 改包工坊")}
        {renderNavItem("java-analyzer", <CoffeeOutlined />, "Java 源码分析")}
        {renderNavItem("packer-lab", <ToolOutlined />, "壳工坊")}
        {renderNavItem("algo-converter", <CodeOutlined />, "伪代码转译")}
        {renderNavItem("web-lab", <CompassOutlined />, "Web 逆向实验室")}
        {renderNavItem("asm-lab", <BugOutlined />, "ARM 汇编实验室")}

        {/* 底部留白，避免内容贴到底部按钮上 */}
        <div style={{ height: 30 }}></div>
      </div>

      {/* 6. 底部折叠按钮 (固定) */}
      <div
        style={{
          flexShrink: 0, // 禁止被压缩
          padding: "16px 0",
          borderTop: "1px solid rgba(0,0,0,0.06)",
          display: "flex",
          justifyContent: "center",
          cursor: "pointer",
          backgroundColor: "var(--bg-color, #fff)",
        }}
        onClick={() => setCollapsed(!collapsed)}
      >
        {collapsed ? (
          <MenuUnfoldOutlined style={{ fontSize: 18, color: "#666" }} />
        ) : (
          <MenuFoldOutlined style={{ fontSize: 18, color: "#666" }} />
        )}
      </div>

      {/* Modals 保持不变 */}
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
                            loading={loadingVersions}
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
