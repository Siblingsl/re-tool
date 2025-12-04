import React, { useEffect, useRef, useState } from "react";
import { Button, Space, Tag } from "antd";
import {
  ClearOutlined,
  PoweroffOutlined,
  CodeOutlined,
} from "@ant-design/icons";
import { listen } from "@tauri-apps/api/event";

interface FridaConsoleProps {
  // 这里的 visible 和 container 都不需要了，由父级 CSS 控制
  onClose: () => void;
  appName: string;
  sessionId: string;
}

const FridaConsole: React.FC<FridaConsoleProps> = ({
  onClose,
  appName,
  sessionId,
}) => {
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  useEffect(() => {
    setLogs([`[System] Ready. Attaching to ${appName}...`]);
    const unlisten = listen<string>("frida-log", (event) => {
      setLogs((prev) => {
        const newLogs = [...prev, event.payload];
        if (newLogs.length > 1000) return newLogs.slice(newLogs.length - 1000);
        return newLogs;
      });
    });
    return () => {
      unlisten.then((f) => f());
    };
  }, [sessionId]);

  // 🔥 关键修改：不再返回 <Drawer>，而是返回一个占满父容器的 <div>
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "#1e1e1e",
        color: "#d4d4d4",
        borderLeft: "1px solid #333", // 左侧加一条分割线
      }}
    >
      {/* 1. 标题栏 */}
      <div
        style={{
          padding: "12px 16px",
          background: "#252526",
          borderBottom: "1px solid #333",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <Space>
          <CodeOutlined />
          <span style={{ fontWeight: 600 }}>控制台</span>
          <Tag color="blue" style={{ margin: 0 }}>
            {appName}
          </Tag>
        </Space>
        <Space>
          <Button
            size="small"
            icon={<ClearOutlined />}
            onClick={() => setLogs([])}
            ghost
          >
            清空
          </Button>
          <Button
            size="small"
            danger
            icon={<PoweroffOutlined />}
            onClick={onClose}
          >
            关闭
          </Button>
        </Space>
      </div>

      {/* 2. 日志区域 */}
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: 16,
          fontFamily: "'Menlo', 'Monaco', 'Courier New', monospace",
          fontSize: 12,
          lineHeight: 1.5,
        }}
      >
        {logs.map((log, index) => (
          <div
            key={index}
            style={{
              marginBottom: 2,
              wordBreak: "break-all",
              color: log.includes("ERROR") ? "#f48771" : "inherit",
            }}
          >
            <span style={{ opacity: 0.5, marginRight: 8 }}>&gt;</span>
            {log}
          </div>
        ))}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
};

export default FridaConsole;
