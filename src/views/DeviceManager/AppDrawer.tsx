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
  ToolOutlined,
} from "@ant-design/icons";
import { AppInfo, ViewMode, AppDetail, Device } from "../../types";
import { invoke } from "@tauri-apps/api/core";
import FridaConsole from "./FridaConsole";
import FileExplorer from "../FileExplorer";
import SoViewer from "./SoViewer"; // 🔥 引入新组件
import PackerViewer from "./PackerViewer";

interface AppDrawerProps {
  visible: boolean;
  app: AppInfo | null;
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

  // 🔥 核心修改 1：状态升级
  // null = 关闭右侧, 'console' = Frida控制台, 'so' = SO查看器
  const [rightPanel, setRightPanel] = useState<
    null | "console" | "so" | "packer"
  >(null);

  // 当前选中的脚本 ID
  const [selectedScriptId, setSelectedScriptId] = useState<string>(
    scripts[0]?.id || ""
  );
  const currentScript = scripts.find((s) => s.id === selectedScriptId);

  // --- Frida 执行逻辑 ---
  const runFrida = async (mode: "spawn" | "attach") => {
    if (!app || !device || !currentScript) return;

    const hide = message.loading(
      `正在 ${mode === "spawn" ? "冷启动" : "附加"} 并注入脚本...`,
      0
    );

    try {
      // 1. Spawn 模式重启应用
      if (mode === "spawn") {
        try {
          await invoke("run_command", {
            cmd: "adb",
            args: ["-s", device.id, "shell", "am", "force-stop", app.pkg],
          });
        } catch {}
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
        await new Promise((r) => setTimeout(r, 1000));
      }

      // 2. 注入脚本
      const result = await invoke("run_frida_script", {
        deviceId: device.id,
        packageName: app.pkg,
        scriptContent: currentScript.code,
      });

      hide();
      message.success(`${currentScript.name} 注入成功！`);
      console.log("Frida Output:", result);

      // 🔥 成功后，打开控制台面板
      setRightPanel("console");
    } catch (e: any) {
      hide();
      message.error(`注入失败: ${e}`);
    }
  };

  // 加载详情
  useEffect(() => {
    if (visible && app && device) {
      fetchDetail();
    } else {
      setDetail(null);
      setRightPanel(null); // 关闭抽屉时重置右侧
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
    } catch (e) {
      message.error("卸载失败");
    }
  };

  const handleExtractApk = async () => {
    if (!app || !device) return;
    const hide = message.loading(`正在提取 ${app.name} 的 APK...`, 0);
    try {
      const savePath = await invoke<string>("extract_apk", {
        deviceId: device.id,
        pkg: app.pkg,
      });
      hide();
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
        onOk: () => invoke("open_file_explorer", { path: savePath }),
      });
    } catch (e: any) {
      hide();
      message.error(e);
    }
  };

  if (!app) return null;

  const tabItems = [
    {
      key: "overview",
      label: <span>概览</span>,
      icon: <DashboardOutlined />,
      children: (
        <div style={{ padding: "16px 0" }}>
          {/* 详细信息展示区 */}
          <Spin spinning={loading}>
            <Descriptions column={1} bordered size="small">
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
              <Descriptions.Item label="用户 ID">
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

          {/* 操作按钮区 */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 12,
              marginTop: 24,
            }}
          >
            <Divider style={{ margin: "0" }}>Frida 调试台</Divider>

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
                  options={scripts.map((s) => ({ label: s.name, value: s.id }))}
                />
                <Tooltip title="去脚本工坊编辑">
                  <Button
                    icon={<EditOutlined />}
                    onClick={() => {
                      onClose();
                      onNavigate("script-lab");
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
                  onNavigate("algo-converter", `// 正在分析: ${app.name}\n`);
                  message.info("已跳转");
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
              {/* 🔥 修改：点击按钮切换右侧面板状态 */}
              <Button
                block
                icon={<FileZipOutlined />}
                type={rightPanel === "so" ? "primary" : "default"} // 高亮状态
                onClick={() => {
                  // 如果已经是 SO 界面，则关闭；否则打开 SO 界面
                  setRightPanel(rightPanel === "so" ? null : "so");
                }}
              >
                查看 SO 库
              </Button>
            </div>

            <div style={{ display: "flex", gap: 12 }}>
              <Button
                block
                icon={<ToolOutlined />}
                type={rightPanel === "packer" ? "primary" : "default"} // 高亮状态
                onClick={() => {
                  // 查壳/脱壳功能预留接口
                  setRightPanel(rightPanel === "packer" ? null : "packer");
                }}
              >
                查壳/脱壳
              </Button>
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
        </div>
      ),
    },
    {
      key: "files",
      label: <span>文件</span>,
      icon: <FolderOpenOutlined />,
      children: (
        <div style={{ padding: "16px 0", height: "100%" }}>
          <FileExplorer
            deviceId={device?.id || ""}
            initialPath={`/data/data/${app.pkg}`}
            mode="compact"
          />
        </div>
      ),
    },
    {
      key: "logs",
      label: <span>日志</span>,
      icon: <FileTextOutlined />,
      children: (
        <Empty description="系统 Logcat (开发中)" style={{ marginTop: 50 }} />
      ),
    },
  ];

  return (
    <Drawer
      title={app.name}
      open={visible}
      onClose={onClose}
      // 🔥 核心修改 2：根据是否有右侧面板动态调整宽度
      width={rightPanel ? 900 : 480}
      extra={
        <Button
          type="text"
          icon={<ReloadOutlined />}
          onClick={fetchDetail}
          loading={loading}
        />
      }
      bodyStyle={{ padding: 0, overflow: "hidden" }}
    >
      <div
        style={{
          display: "flex",
          height: "100%",
          width: "100%",
          overflow: "hidden",
        }}
      >
        {/* 左侧固定区域 (450px) */}
        <div
          style={{
            width: 450,
            flexShrink: 0,
            padding: 24,
            overflowY: "auto",
            // 右侧有内容时显示分割线
            borderRight: rightPanel ? "1px solid #f0f0f0" : "none",
          }}
        >
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
          <Tabs
            defaultActiveKey="overview"
            centered
            items={tabItems}
            style={{ height: "100%" }}
            tabBarStyle={{ padding: "0 24px", marginBottom: 0, marginTop: 12 }}
          />
        </div>

        {/* 🔥 核心修改 3：右侧动态区域 (Flex 1) */}
        {rightPanel && (
          <div style={{ flex: 1, minWidth: 0, height: "100%" }}>
            {/* 情况 A: 显示 Frida 控制台 */}
            {rightPanel === "console" && (
              <FridaConsole
                onClose={() => setRightPanel(null)} // 关闭右侧
                appName={app.name}
                sessionId={app.pkg}
              />
            )}

            {/* 情况 B: 显示 SO 库查看器 */}
            {rightPanel === "so" && device && (
              <SoViewer
                deviceId={device.id}
                pkg={app.pkg}
                apkPath={detail?.sourceDir}
                onClose={() => setRightPanel(null)} // 关闭右侧
                onAnalyze={(path) => {
                  // 预留接口
                  console.log("Analyze SO:", path);
                }}
              />
            )}

            {/* 情况 C: 显示查壳/脱壳界面 */}
            {rightPanel === "packer" && (
              <PackerViewer
                onClose={() => setRightPanel(null)} // 关闭右侧
                pkg={app.pkg}
                onAnalyze={(res) => {
                  // 预留接口
                  console.log("packerViewer:", res);
                }}
              />
            )}
          </div>
        )}
      </div>
    </Drawer>
  );
};

export default AppDrawer;
