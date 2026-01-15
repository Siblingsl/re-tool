import React, { useState, useEffect, useRef } from "react";
import Editor from "@monaco-editor/react";
import { Layout, List, Button, message, Space, Modal, Radio } from "antd";

import {
  PlayCircleOutlined,
  SnippetsOutlined,
  SaveOutlined,
  ThunderboltFilled,
  ClearOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event"; // 🔥 引入事件监听
import { ScriptItem } from "../../App";
import AiGeneratorModal from "./AiGeneratorModal";

const { Sider, Content } = Layout;

interface ScriptLabProps {
  scripts: ScriptItem[];
  onSave: (newScript: ScriptItem) => void;
  currentDeviceId?: string;
}

const ScriptLab: React.FC<ScriptLabProps> = ({
  scripts,
  onSave,
  currentDeviceId,
}) => {
  const [code, setCode] = useState(
    "// 请选择左侧模板，或让 AI 生成代码\n\nconsole.log('Hello Frida');"
  );
  const [isRunning, setIsRunning] = useState(false);
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);

  // 🔥 新增：日志状态
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // 🔥 新增：日志自动滚动
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // 🔥 新增：监听后端日志事件
  useEffect(() => {
    // 这里的 unlisten 是个 Promise
    const unlistenPromise = listen<string>("frida-log", (event) => {
      setLogs((prev) => [...prev, event.payload]);
    });

    return () => {
      unlistenPromise.then((f) => f());
    };
  }, []);

  // 🔥 新增：进程选择相关状态
  const [processes, setProcesses] = useState<{ pid: number, name: string, is_main: boolean }[]>([]);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [showProcessModal, setShowProcessModal] = useState(false);
  const [pendingRun, setPendingRun] = useState<{ deviceId: string, pkg: string } | null>(null);

  const handleRun = async () => {
    setIsRunning(true);
    setLogs([]); // 每次运行前清空日志

    // 添加一条系统日志
    setLogs((prev) => [...prev, "[System] Starting injection..."]);

    try {
      let targetDevice = currentDeviceId;
      // ... (之前的自动获取设备逻辑保持不变) ...
      if (!targetDevice) {
        const devices = await invoke<any[]>("get_all_devices");
        const online = devices.find((d) => d.status === "online");
        if (online) {
          targetDevice = online.id;
          setLogs((prev) => [
            ...prev,
            `[System] Auto-selected device: ${online.name}`,
          ]);
        } else {
          throw new Error("未连接任何设备");
        }
      }

      const currentPkg = await invoke<string>("get_foreground_app", {
        deviceId: targetDevice,
      });
      setLogs((prev) => [...prev, `[System] Target App: ${currentPkg}`]);

      // 🔥 枚举目标 App 的所有进程
      const procs = await invoke<{ pid: number, name: string, is_main: boolean }[]>("list_app_processes", {
        deviceId: targetDevice,
        packageName: currentPkg,
      });

      // 如果有多个进程，弹出选择框
      if (procs.length > 1) {
        setProcesses(procs);
        setPendingRun({ deviceId: targetDevice!, pkg: currentPkg });
        setShowProcessModal(true);
        setIsRunning(false);
        return;
      }

      // 单进程直接注入
      await executeInjection(targetDevice!, currentPkg, procs.length > 0 ? procs[0].pid : null);


    } catch (e: any) {
      message.error("执行失败");
      setLogs((prev) => [...prev, `[Error] ${e}`]);
    } finally {
      setIsRunning(false);
    }
  };

  // 🔥 实际执行注入
  const executeInjection = async (deviceId: string, pkg: string, pid: number | null) => {
    try {
      if (pid) {
        setLogs((prev) => [...prev, `[System] Injecting into PID: ${pid}`]);
      }

      await invoke("run_frida_script", {
        deviceId: deviceId,
        packageName: pkg,
        scriptContent: code,
        targetPid: pid, // 🔥 传入目标 PID
      });

      message.success("注入成功！");
    } catch (e: any) {
      message.error("注入失败");
      setLogs((prev) => [...prev, `[Error] ${e}`]);
    }
  };

  // 🔥 处理进程选择确认
  const handleProcessSelect = async () => {
    if (!pendingRun || selectedPid === null) return;
    setShowProcessModal(false);
    setIsRunning(true);
    await executeInjection(pendingRun.deviceId, pendingRun.pkg, selectedPid);
    setIsRunning(false);
    setPendingRun(null);
    setSelectedPid(null);
  };


  return (
    <Layout style={{ height: "100%", background: "#fff" }}>
      <Sider
        width={250}
        theme="light"
        style={{ borderRight: "1px solid #f0f0f0" }}
      >
        {/* ... 侧边栏保持不变 ... */}
        <div className="content-header">常用脚本库</div>
        <List
          itemLayout="horizontal"
          dataSource={scripts}
          renderItem={(item: any) => (
            <List.Item
              style={{ padding: "12px 16px", cursor: "pointer" }}
              onClick={() => setCode(item.code.trim())}
            >
              <List.Item.Meta title={item.name} description={item.desc} />
            </List.Item>
          )}
        />
      </Sider>

      <Content style={{ display: "flex", flexDirection: "column" }}>
        <div className="content-header">
          <span>脚本编辑器 (JavaScript)</span>
          <Space>
            <Button
              icon={<ThunderboltFilled />}
              style={{ color: "#faad14", borderColor: "#faad14" }}
              onClick={() => setIsAiModalOpen(true)}
            >
              AI 生成 Hook
            </Button>
            <Button icon={<SaveOutlined />}>保存</Button>
            <Button
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={handleRun}
              loading={isRunning}
            >
              运行 / 注入
            </Button>
          </Space>
        </div>

        {/* 编辑器区域 (flex: 1，占据剩余空间的一半) */}
        <div style={{ flex: 1, minHeight: 200 }}>
          <Editor
            height="100%"
            defaultLanguage="javascript"
            value={code}
            onChange={(value) => setCode(value || "")}
            theme="vs-dark"
            options={{ minimap: { enabled: false }, fontSize: 14 }}
          />
        </div>

        {/* 🔥 新增：底部日志控制台 (固定高度或 flex 占比) */}
        <div
          style={{
            height: "30%", // 占据底部 30% 高度
            background: "#1e1e1e",
            color: "#d4d4d4",
            borderTop: "1px solid #333",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* 控制台标题栏 */}
          <div
            style={{
              padding: "4px 10px",
              background: "#252526",
              fontSize: 12,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>Console Output</span>
            <Button
              type="text"
              size="small"
              icon={<ClearOutlined />}
              onClick={() => setLogs([])}
              style={{ color: "#ccc" }}
            >
              Clear
            </Button>
          </div>

          {/* 日志滚动区 */}
          <div
            style={{
              flex: 1,
              overflowY: "auto",
              padding: 10,
              fontFamily: "monospace",
              fontSize: 12,
              lineHeight: 1.5,
            }}
          >
            {logs.map((log, idx) => (
              <div
                key={idx}
                style={{
                  wordBreak: "break-all",
                  color: log.includes("[Error]")
                    ? "#ff4d4f"
                    : log.includes("[System]")
                      ? "#52c41a"
                      : "inherit",
                }}
              >
                {log}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        <AiGeneratorModal
          visible={isAiModalOpen}
          onClose={() => setIsAiModalOpen(false)}
          onGenerate={(generatedCode) =>
            setCode(
              (prev) => prev + "\n\n// --- AI Generated ---\n" + generatedCode
            )
          }
        />

        {/* 🔥 多进程选择 Modal */}
        <Modal
          title="选择目标进程"
          open={showProcessModal}
          onOk={handleProcessSelect}
          onCancel={() => {
            setShowProcessModal(false);
            setPendingRun(null);
            setSelectedPid(null);
          }}
          okButtonProps={{ disabled: selectedPid === null }}
        >
          <p style={{ marginBottom: 16 }}>检测到该应用有多个进程，请选择要注入的进程：</p>
          <Radio.Group
            value={selectedPid}
            onChange={(e) => setSelectedPid(e.target.value)}
            style={{ width: "100%" }}
          >
            {processes.map((proc) => (
              <Radio
                key={proc.pid}
                value={proc.pid}
                style={{ display: "block", marginBottom: 8 }}
              >
                <span style={{ fontWeight: proc.is_main ? 600 : 400 }}>
                  {proc.name}
                </span>
                <span style={{ color: "#999", marginLeft: 8 }}>
                  (PID: {proc.pid})
                  {proc.is_main && <span style={{ color: "#52c41a", marginLeft: 8 }}>主进程</span>}
                </span>
              </Radio>
            ))}
          </Radio.Group>
        </Modal>

      </Content>
    </Layout>
  );
};

export default ScriptLab;
