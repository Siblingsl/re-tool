import React, { useState, useEffect, useRef } from "react";
import {
  Drawer,
  Avatar,
  Tag,
  Descriptions,
  Button,
  message,
  Spin,
  Divider,
  Select,
  Tooltip,
  Tabs,
  Card,
  Empty,
  Modal,
} from "antd";
import {
  AppstoreOutlined,
  BugOutlined,
  CodeOutlined,
  FileZipOutlined,
  DeleteOutlined,
  ReloadOutlined,
  PlayCircleOutlined,
  FieldTimeOutlined,
  EditOutlined,
  ThunderboltOutlined,
  DashboardOutlined,
  FolderOpenOutlined,
  FileTextOutlined,
  DownloadOutlined,
} from "@ant-design/icons";
import { AppInfo, ViewMode, AppDetail, Device } from "../../types"; // 引入 Device 和 AppDetail
import { invoke } from "@tauri-apps/api/core";
import FridaConsole from "./FridaConsole";

interface AppDrawerProps {
  visible: boolean;
  app: AppInfo | null;
  // 🔥 新增：需要 device 信息来执行 adb 命令
  device: Device | null;
  scripts: { id: string; name: string; code: string }[];
  onClose: () => void;
  onNavigate: (view: ViewMode, contextData?: string) => void;
}

const AppDrawer: React.FC<AppDrawerProps> = ({
  visible,
  app,
  device,
  scripts,
  onClose,
  onNavigate,
}) => {
  // 详情数据状态
  const [detail, setDetail] = useState<AppDetail | null>(null);
  const [loading, setLoading] = useState(false);
  // 🔥 新增状态：控制控制台显示
  const [consoleVisible, setConsoleVisible] = useState(false);
  // 🔥 新增：用于挂载控制台的容器引用
  const drawerContainerRef = useRef<HTMLDivElement>(null);

  // 🔥 新增：当前选中的脚本 ID
  const [selectedScriptId, setSelectedScriptId] = useState<string>(
    scripts[0]?.id || ""
  );
  // 获取当前脚本内容
  const currentScript = scripts.find((s) => s.id === selectedScriptId);

  // --- 通用执行逻辑 ---
  const runFrida = async (mode: "spawn" | "attach") => {
    if (!app || !device || !currentScript) return;

    const hide = message.loading(
      `正在 ${mode === "spawn" ? "冷启动" : "附加"} 并注入脚本...`,
      0
    );

    try {
      // 1. 如果是 Spawn，先重启应用
      if (mode === "spawn") {
        // 先杀
        try {
          await invoke("run_command", {
            cmd: "adb",
            args: ["-s", device.id, "shell", "am", "force-stop", app.pkg],
          });
        } catch {}
        // 再起 (使用 monkey 或 am start)
        await invoke("run_command", {
          cmd: "adb",
          args: [
            "-s",
            device.id,
            "shell",
            "monkey",
            "-p",
            app.pkg,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
          ],
        });
        // 等待应用启动
        await new Promise((r) => setTimeout(r, 1000));
      }

      // 2. 调用后端注入脚本 (假设你实现了 run_frida_script)
      // 注意：这里我们把脚本内容直接传过去，或者传路径
      const result = await invoke("run_frida_script", {
        deviceId: device.id,
        packageName: app.pkg,
        scriptContent: currentScript.code,
      });

      hide();
      message.success(`${currentScript.name} 注入成功！`);
      console.log("Frida Output:", result);
      // 🔥 成功后，打开控制台抽屉
      setConsoleVisible(true);
    } catch (e: any) {
      hide();
      message.error(`注入失败: ${e}`);
    }
  };

  // 当 app 或 visible 变化时，加载详情
  useEffect(() => {
    if (visible && app && device) {
      fetchDetail();
    } else {
      setDetail(null); // 关闭时清空
    }
  }, [visible, app, device]);

  const fetchDetail = async () => {
    if (!app || !device) return;
    setLoading(true);
    try {
      const res = await invoke<AppDetail>("get_app_detail", {
        deviceId: device.id,
        pkg: app.pkg,
      });
      setDetail(res);
    } catch (e) {
      console.error(e);
      message.error("获取详情失败");
    } finally {
      setLoading(false);
    }
  };

  const handleUninstall = async () => {
    if (!app || !device) return;
    try {
      await invoke("run_command", {
        cmd: "adb",
        args: ["-s", device.id, "uninstall", app.pkg],
      });
      message.success("卸载成功");
      onClose();
      // 最好能触发父组件刷新列表，这里暂略
    } catch (e) {
      message.error("卸载失败");
    }
  };

  // --- 处理提取 APK ---
  const handleExtractApk = async () => {
    if (!app || !device) return;
    const hide = message.loading(`正在提取 ${app.name} 的 APK...`, 0);

    try {
      // 1. 调用后端
      const savePath = await invoke<string>("extract_apk", {
        deviceId: device.id,
        pkg: app.pkg,
      });

      hide();

      // 2. 成功弹窗
      Modal.success({
        title: "提取成功",
        content: (
          <div>
            <p>APK 已保存至下载目录：</p>
            <div
              style={{
                background: "#f5f5f5",
                padding: 8,
                borderRadius: 4,
                fontFamily: "monospace",
                wordBreak: "break-all",
              }}
            >
              {savePath}
            </div>
          </div>
        ),
        okText: "打开所在文件夹",
        cancelText: "关闭",
        closable: true,
        onOk: () => {
          // 调用后端打开文件夹
          invoke("open_file_explorer", { path: savePath });
        },
      });
    } catch (e: any) {
      hide();
      message.error(e); // 显示具体的错误信息
    }
  };
  if (!app) return null;

  // --- 处理 Spawn (冷启动) ---
  const handleSpawn = async () => {
    if (!app || !device) return;
    const hide = message.loading("正在重启应用 (Spawn)...", 0);
    try {
      // 1. 先停止
      await invoke("stop_app", { deviceId: device.id, pkg: app.pkg });
      // 2. 再启动
      await invoke("launch_app", { deviceId: device.id, pkg: app.pkg });

      hide();
      message.success("应用已 Spawn (冷启动)");

      // 这里后续可以衔接你的 Python 脚本或者 frida 命令
      // 比如: invoke('run_frida_script', { mode: 'spawn' })
    } catch (e) {
      hide();
      message.error("Spawn 失败");
    }
  };

  // --- 处理 Attach (热启动) ---
  const handleAttach = async () => {
    if (!app || !device) return;
    const hide = message.loading("正在附加进程 (Attach)...", 0);
    try {
      // Attach 不需要重启，直接确认应用在运行即可
      // 这里只是简单的 UI 反馈，实际逆向时这里会运行 frida -U -n ...
      await new Promise((r) => setTimeout(r, 500)); // 模拟连接耗时

      hide();
      message.success("已附加到当前进程 (Attach)");

      // 后续衔接: invoke('run_frida_script', { mode: 'attach' })
    } catch (e) {
      hide();
      message.error("Attach 失败");
    }
  };

  const tabItems = [
    {
      key: "overview",
      label: <span>概览</span>,
      icon: <DashboardOutlined />,
      children: (
        <div style={{ padding: 16 }}>
          {/* 详细信息展示区 */}
          <Spin spinning={loading}>
            <Descriptions column={1} bordered size="small" title="详细信息">
              <Descriptions.Item label="版本名称">
                {detail?.versionName || app.ver || "加载中..."}
              </Descriptions.Item>
              <Descriptions.Item label="内部版本号">
                {detail?.versionCode || "-"}
              </Descriptions.Item>
              <Descriptions.Item label="最低 SDK">
                {detail?.minSdk || "-"}
              </Descriptions.Item>
              <Descriptions.Item label="目标 SDK">
                {detail?.targetSdk || "-"}
              </Descriptions.Item>
              <Descriptions.Item label="用户 ID (UID)">
                {detail?.uid || "-"}
              </Descriptions.Item>
              <Descriptions.Item label="数据目录">
                <span style={{ wordBreak: "break-all", fontSize: 12 }}>
                  {detail?.dataDir}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="APK 路径">
                <span style={{ wordBreak: "break-all", fontSize: 12 }}>
                  {detail?.sourceDir}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="安装时间">
                {detail?.firstInstallTime}
              </Descriptions.Item>
            </Descriptions>
          </Spin>

          {/* 操作按钮 */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 12,
              marginTop: 24,
            }}
          >
            <Divider style={{ margin: "0" }}>Frida 调试台</Divider>

            {/* 🔥 核心区域：脚本选择与执行 */}
            <div
              style={{
                background: "#f5f7fa",
                padding: 16,
                borderRadius: 8,
                border: "1px solid #e8e8e8",
              }}
            >
              <div style={{ marginBottom: 12, display: "flex", gap: 8 }}>
                <Select
                  style={{ flex: 1 }}
                  placeholder="选择要注入的脚本"
                  value={selectedScriptId}
                  onChange={setSelectedScriptId}
                  options={scripts.map((s) => ({
                    label: s.name,
                    value: s.id,
                  }))}
                />
                <Tooltip title="去脚本工坊编辑">
                  <Button
                    icon={<EditOutlined />}
                    onClick={() => {
                      onClose();
                      onNavigate("script-lab"); // 跳转去编辑
                    }}
                  />
                </Tooltip>
              </div>

              <div style={{ display: "flex", gap: 12 }}>
                <Button
                  type="primary"
                  block
                  icon={<ReloadOutlined />}
                  onClick={() => runFrida("spawn")}
                  style={{ background: "#722ed1", borderColor: "#722ed1" }}
                >
                  Spawn (重启注入)
                </Button>

                <Button
                  type="primary"
                  block
                  icon={<ThunderboltOutlined />}
                  onClick={() => runFrida("attach")}
                  style={{ background: "#fa8c16", borderColor: "#fa8c16" }}
                >
                  Attach (热注入)
                </Button>
              </div>

              <div
                style={{
                  marginTop: 8,
                  fontSize: 12,
                  color: "#999",
                  textAlign: "center",
                }}
              >
                当前选中: {currentScript?.name || "无"} (
                {currentScript?.code.length || 0} chars)
              </div>
            </div>

            <div style={{ display: "flex", gap: 12 }}>
              <Button
                block
                icon={<CodeOutlined />}
                onClick={() => {
                  onClose();
                  onNavigate(
                    "algo-converter",
                    `// 正在分析应用: ${app.name}\n// 包名: ${app.pkg}\n// APK路径: ${detail?.sourceDir}\n`
                  );
                  message.info("已跳转至代码转译工具");
                }}
              >
                算法分析
              </Button>
              <Button
                style={{ flex: 1 }}
                icon={<DownloadOutlined />}
                onClick={handleExtractApk}
              >
                提取 APK
              </Button>
              <Button
                block
                icon={<FileZipOutlined />}
                onClick={() => {
                  onClose();
                  onNavigate("so-analyzer");
                  message.info("请从 APK 路径提取 SO 文件");
                }}
              >
                查看 SO 库
              </Button>
            </div>

            <Button
              block
              danger
              icon={<DeleteOutlined />}
              onClick={handleUninstall}
            >
              卸载应用
            </Button>
          </div>
        </div>
      ),
    },
    {
      key: "files",
      label: <span>文件</span>,
      icon: <FolderOpenOutlined />,
      children: (
        <div
          style={{
            padding: 24,
            height: "100%",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            color: "#999",
          }}
        >
          <Empty description="Root 文件管理器 (开发中)" />
          <div style={{ marginTop: 16 }}>支持查看 /data/data/{app.pkg}</div>
        </div>
      ),
    },
    {
      key: "logs",
      label: <span>日志</span>,
      icon: <FileTextOutlined />,
      children: (
        <div
          style={{
            padding: 24,
            height: "100%",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            color: "#999",
          }}
        >
          <Empty description="系统 Logcat + Frida Log (开发中)" />
          <div style={{ marginTop: 16 }}>实时过滤 {app.pkg} 的日志</div>
        </div>
      ),
    },
  ];

  return (
    <Drawer
      title={app.name}
      open={visible}
      onClose={onClose}
      width={consoleVisible ? 900 : 480}
      extra={
        <Button
          type="text"
          icon={<ReloadOutlined />}
          onClick={fetchDetail}
          loading={loading}
        />
      }
      // 去掉默认 padding，由内部 flex 布局控制
      bodyStyle={{ padding: 0, overflow: "hidden" }}
    >
      <div
        style={{
          display: "flex", // 让左右两块并排
          height: "100%",
          width: "100%",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: 450, // 固定宽度
            flexShrink: 0, // 防止被压缩
            padding: 24, // 内容 padding
            overflowY: "auto", // 只有这一块滚动
            borderRight: consoleVisible ? "1px solid #f0f0f0" : "none",
          }}
        >
          {/* 头部信息 */}
          <div style={{ textAlign: "center" }}>
            <Avatar
              shape="square"
              size={80}
              style={{ backgroundColor: app.icon }}
              icon={<AppstoreOutlined />}
            />
            <h3 style={{ margin: "12px 0 4px" }}>{app.name}</h3>
            <Tag style={{ fontFamily: "monospace" }}>{app.pkg}</Tag>
          </div>
          {/* 🔥 这里的 Tabs 撑满左侧 */}
          <Tabs
            defaultActiveKey="overview"
            centered
            items={tabItems}
            style={{ height: "100%" }}
            tabBarStyle={{ padding: "0 24px", marginBottom: 0, marginTop: 12 }}
          />
        </div>

        {/* 🔥 核心修改 3：右侧控制台 (条件渲染) */}
        {consoleVisible && (
          <div style={{ flex: 1, minWidth: 0, height: "100%" }}>
            {/* 这里直接渲染 FridaConsole，因为它已经是个普通 div 了 */}
            <FridaConsole
              onClose={() => setConsoleVisible(false)} // 点击关闭，隐藏右侧，抽屉变窄
              appName={app.name}
              sessionId={app.pkg}
            />
          </div>
        )}
      </div>
    </Drawer>
  );
};

export default AppDrawer;
