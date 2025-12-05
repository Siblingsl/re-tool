import React, { useState, useEffect, useRef } from "react";
import Editor from "@monaco-editor/react";
import { Layout, List, Button, message, Space } from "antd";
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

      await invoke("run_frida_script", {
        deviceId: targetDevice,
        packageName: currentPkg,
        scriptContent: code,
      });

      // 注意：run_frida_script 返回就代表启动成功了，后续日志是异步来的
      message.success("注入成功！");
    } catch (e: any) {
      message.error("执行失败");
      setLogs((prev) => [...prev, `[Error] ${e}`]);
    } finally {
      setIsRunning(false);
    }
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
      </Content>
    </Layout>
  );
};

export default ScriptLab;
