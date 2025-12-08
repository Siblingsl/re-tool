import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Layout,
  Table,
  Tag,
  Input,
  Button,
  Space,
  Tabs,
  Badge,
  Empty,
  Tooltip,
  Switch,
  Divider,
  Modal,
  Descriptions,
  Alert,
  Select,
  Spin,
  message,
} from "antd";
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  ClearOutlined,
  FilterOutlined,
  ArrowDownOutlined,
  RedoOutlined,
  CopyOutlined,
  SettingOutlined,
  SafetyCertificateOutlined,
  AndroidOutlined,
  AppleOutlined,
  AppstoreOutlined,
  CodeOutlined,
  FileTextOutlined,
  AppstoreAddOutlined,
  RobotOutlined,
} from "@ant-design/icons";
import Editor from "@monaco-editor/react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { NetworkRequest, Device } from "../../types";
import dayjs from "dayjs";
import { decodeProto, ProtoField } from "@/utils/protobufDecoder";

interface NetworkSnifferProps {
  devices?: Device[];
  deviceAliases?: Record<string, string>;
}

// 辅助函数：防抖/节流 (如果需要)
// 这里直接操作 DOM/State 通常不需要复杂的节流，React 18 处理得很好

const NetworkSniffer: React.FC<NetworkSnifferProps> = ({
  devices = [],
  deviceAliases = {},
}) => {
  const [requests, setRequests] = useState<NetworkRequest[]>([]);
  const [selectedReq, setSelectedReq] = useState<NetworkRequest | null>(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [targetDeviceId, setTargetDeviceId] = useState<string>("all");
  const [settingModalVisible, setSettingModalVisible] = useState(false);
  const [port, setPort] = useState(10086);
  const listContainerRef = useRef<HTMLDivElement>(null);
  const [currentIp, setCurrentIp] = useState<string>("");
  const [aiModalVisible, setAiModalVisible] = useState(false);
  const [aiResult, setAiResult] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  // 🔥 新增：底部面板高度状态 (默认 400px)
  const [bottomPanelHeight, setBottomPanelHeight] = useState(250);
  // 🔥 新增：是否正在拖拽 (用于控制鼠标样式，避免拖拽时选中文字)
  const [isResizing, setIsResizing] = useState(false);

  // IP 监控逻辑
  useEffect(() => {
    let intervalId: any;
    const checkIp = async () => {
      try {
        const ip = await invoke<string>("get_local_ip");
        if (!currentIp) {
          setCurrentIp(ip);
          return;
        }
        if (ip !== currentIp && currentIp !== "") {
          setIsCapturing(false);
          Modal.warning({
            title: "网络环境已变更",
            content: (
              <div>
                <p>检测到电脑 IP 地址已发生变化！</p>
                <p>
                  旧 IP: <Tag color="red">{currentIp}</Tag>
                </p>
                <p>
                  新 IP: <Tag color="green">{ip}</Tag>
                </p>
                <Divider />
                <p>
                  <b>请立即修改手机 WiFi 代理设置</b>，否则将无法抓包。
                </p>
              </div>
            ),
            okText: "知道了",
            onOk: () => setCurrentIp(ip),
          });
        }
      } catch (e) {
        console.error("IP check failed", e);
      }
    };
    checkIp();
    intervalId = setInterval(checkIp, 5000);
    return () => clearInterval(intervalId);
  }, [currentIp]);

  // 流量监听逻辑
  useEffect(() => {
    const unlistenPromise = listen<string>("mitm-traffic", (event) => {
      if (!isCapturing) return;
      const rawMsg = event.payload.trim();
      if (!rawMsg.startsWith("{")) return;

      try {
        const payload: NetworkRequest = JSON.parse(rawMsg);
        setRequests((prev) => {
          const exists = prev.findIndex((r) => r.id === payload.id);
          let newArr = [...prev];
          if (exists !== -1) {
            newArr[exists] = { ...newArr[exists], ...payload };
            if (selectedReq?.id === payload.id) {
              setSelectedReq({ ...newArr[exists], ...payload });
            }
          } else {
            newArr = [...prev, payload];
          }
          return newArr;
        });
      } catch (e) {
        console.error(e);
      }
    });
    return () => {
      unlistenPromise.then((f) => f());
    };
  }, [isCapturing, selectedReq]);

  // 自动滚动
  useEffect(() => {
    if (autoScroll && listContainerRef.current) {
      const tableBody =
        listContainerRef.current.querySelector(".ant-table-body");
      if (tableBody) {
        tableBody.scrollTop = tableBody.scrollHeight;
      }
    }
  }, [requests.length, autoScroll]);

  // 🔥 核心逻辑：处理拖拽改变高度
  const startResizing = React.useCallback(
    (mouseDownEvent: React.MouseEvent) => {
      mouseDownEvent.preventDefault();
      setIsResizing(true);

      const startY = mouseDownEvent.clientY;
      const startHeight = bottomPanelHeight;

      const onMouseMove = (mouseMoveEvent: MouseEvent) => {
        // 计算鼠标移动的距离 (向上拖动 delta 为负，向下为正)
        // 注意：这里我们改变的是底部高度。
        // 鼠标向上移(clientY 变小)，底部应该变高。
        const delta = startY - mouseMoveEvent.clientY;
        const newHeight = startHeight + delta;

        // 限制最小和最大高度，防止界面崩溃
        if (newHeight > 100 && newHeight < window.innerHeight - 150) {
          setBottomPanelHeight(newHeight);
        }
      };

      const onMouseUp = () => {
        setIsResizing(false);
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    },
    [bottomPanelHeight]
  );

  const filteredRequests = useMemo(() => {
    let list = requests;
    if (filterText) {
      const low = filterText.toLowerCase();
      list = list.filter(
        (r) =>
          r.url.toLowerCase().includes(low) ||
          r.method.toLowerCase().includes(low)
      );
    }
    return list;
  }, [requests, filterText, targetDeviceId]);

  const getStatusColor = (status?: number) => {
    if (!status) return "default";
    if (status >= 200 && status < 300) return "success";
    if (status >= 300 && status < 400) return "warning";
    return "error";
  };

  const toggleCapture = async () => {
    if (isCapturing) {
      try {
        await invoke("stop_mitmproxy");
        message.success("服务已停止");
      } catch (e) {
        console.error(e);
      }
      setIsCapturing(false);
    } else {
      const hide = message.loading("正在启动抓包服务...", 0);
      try {
        const res = await invoke("start_mitmproxy", { port: port });
        hide();
        message.success(res as string);
        setIsCapturing(true);
      } catch (e: any) {
        hide();
        Modal.error({
          title: "启动失败",
          content: (
            <div>
              <p>无法启动 mitmdump 服务，可能原因：</p>
              <ul>
                <li>端口 {port} 被占用</li>
                <li>未正确配置 Sidecar (bin/mitmdump-...)</li>
                <li>缺少 Python 脚本 (traffic_relay.py)</li>
              </ul>
              <div
                style={{
                  marginTop: 10,
                  background: "#f5f5f5",
                  padding: 8,
                  borderRadius: 4,
                  maxHeight: 200,
                  overflow: "auto",
                  fontFamily: "monospace",
                }}
              >
                {e.toString()}
              </div>
            </div>
          ),
        });
      }
    }
  };

  const handleReplay = async () => {
    if (!selectedReq) return;

    const hide = message.loading("正在重发请求...", 0);

    try {
      // 准备 Headers (过滤掉一些可能引起问题的 headers，虽然 rust 端也过滤了，双重保险)
      const cleanHeaders = { ...selectedReq.requestHeaders };
      delete cleanHeaders["Content-Length"];

      const res = await invoke<string>("replay_request", {
        method: selectedReq.method,
        url: selectedReq.url,
        headers: cleanHeaders,
        body: selectedReq.requestBody || null,
      });

      hide();

      // 用 Modal 展示结果，比 toast 更清晰
      Modal.success({
        title: "重发成功",
        width: 600,
        content: (
          <div
            style={{
              maxHeight: "400px",
              overflow: "auto",
              fontFamily: "monospace",
              whiteSpace: "pre-wrap",
            }}
          >
            {res}
          </div>
        ),
      });
    } catch (e: any) {
      hide();
      Modal.error({
        title: "重发失败",
        content: e.toString(),
      });
    }
  };

  const handleAIAnalyze = async () => {
    if (!selectedReq) return;
    setAiModalVisible(true);
    setAiResult("");
    setAiLoading(true);

    try {
      const prompt = `
        你是一个资深网络安全与逆向工程专家。请分析以下 HTTP 请求：
        
        URL: ${selectedReq.url}
        Method: ${selectedReq.method}
        Headers: ${JSON.stringify(selectedReq.requestHeaders)}
        Request Body: ${selectedReq.requestBody?.substring(0, 1000)} 
        Response Body: ${selectedReq.responseBody?.substring(0, 1000)}

        请完成以下任务：
        1. 【接口功能】用一句话总结这个接口的作用。
        2. 【参数分析】分析关键参数（如 sign, token, uuid 等）可能的生成方式或含义。
        3. 【Python 示例】生成一段使用 requests 库复现此请求的代码。
      `;

      const response = await fetch(
        "https://api.deepseek.com/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer sk-xxxxxxxxxxxxxxxxxxxx", // 🔥 请替换为你的 Key
          },
          body: JSON.stringify({
            model: "deepseek-chat",
            messages: [{ role: "user", content: prompt }],
            stream: true,
          }),
        }
      );

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) return;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split("\n").filter((line) => line.trim() !== "");
        for (const line of lines) {
          if (line.includes("[DONE]")) return;
          try {
            const json = JSON.parse(line.replace("data: ", ""));
            const content = json.choices[0]?.delta?.content || "";
            setAiResult((prev) => prev + content);
          } catch (e) {}
        }
      }
    } catch (e: any) {
      setAiResult("分析失败: " + e.message);
    } finally {
      setAiLoading(false);
    }
  };

  const handleInstallCert = async () => {
    if (targetDeviceId === "all") {
      Modal.warning({
        title: "请选择设备",
        content: "请先在上方下拉框中选择一台具体的设备，再安装证书。",
      });
      return;
    }
    try {
      const res = await invoke<string>("install_cert_to_phone", {
        deviceId: targetDeviceId,
      });
      Modal.success({ title: "证书推送成功", content: res });
    } catch (e: any) {
      Modal.error({ title: "证书安装失败", content: e.toString() });
    }
  };

  // Protobuf & Body Render Functions (Keeping these same as before)
  const renderProtoTree = (
    fields: ProtoField[],
    depth = 0
  ): React.ReactNode => {
    return fields.map((f, i) => (
      <div
        key={i}
        style={{
          marginLeft: depth * 16,
          fontFamily: "monospace",
          fontSize: 13,
          lineHeight: "20px",
        }}
      >
        <span style={{ color: "#d63384", fontWeight: "bold" }}>
          Field {f.id}
        </span>
        <span style={{ color: "#999" }}>
          {" "}
          ({f.type === 2 ? "Len" : "Var"}):{" "}
        </span>
        <span style={{ color: "#000", fontWeight: 500 }}>
          {typeof f.value === "string" && f.value.length > 50
            ? f.value.slice(0, 50) + "..."
            : f.value}
        </span>
        {f.subMessage && f.subMessage.length > 0 && (
          <div
            style={{
              borderLeft: "2px solid #eee",
              paddingLeft: 8,
              marginTop: 2,
            }}
          >
            {renderProtoTree(f.subMessage, depth + 1)}
          </div>
        )}
      </div>
    ));
  };

  const renderBodyContent = (bodyContent: string | undefined) => {
    if (!bodyContent)
      return (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No Body" />
      );

    if (bodyContent.startsWith("base64:")) {
      const base64Str = bodyContent.replace("base64:", "");
      let bytes: Uint8Array;
      try {
        const binaryString = atob(base64Str);
        const len = binaryString.length;
        bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
      } catch (e) {
        return <Alert message="Base64 解码失败" type="error" />;
      }
      const protoFields = decodeProto(bytes);

      return (
        <Tabs
          size="small"
          tabPosition="bottom"
          style={{ height: "100%" }}
          items={[
            {
              key: "proto",
              label: "Protobuf 解析",
              icon: <CodeOutlined />,
              children: (
                <div
                  style={{
                    height: "100%",
                    overflow: "auto",
                    padding: 16,
                    background: "#fff",
                  }}
                >
                  {protoFields.length > 0 ? (
                    renderProtoTree(protoFields)
                  ) : (
                    <div
                      style={{
                        color: "#999",
                        textAlign: "center",
                        marginTop: 20,
                      }}
                    >
                      非标准 Protobuf 数据或解析为空
                    </div>
                  )}
                </div>
              ),
            },
            {
              key: "hex",
              label: "Hex View",
              icon: <AppstoreAddOutlined />,
              children: (
                <div
                  style={{
                    height: "100%",
                    overflow: "auto",
                    fontFamily: "monospace",
                    fontSize: 12,
                    padding: 12,
                    background: "#f8f9fa",
                  }}
                >
                  {Array.from(bytes)
                    .reduce((acc: any[], byte, i) => {
                      if (i % 16 === 0) acc.push([]);
                      acc[acc.length - 1].push(byte);
                      return acc;
                    }, [])
                    .map((chunk, rowIdx) => (
                      <div
                        key={rowIdx}
                        style={{
                          display: "flex",
                          borderBottom: "1px solid #f0f0f0",
                        }}
                      >
                        <span
                          style={{
                            width: 50,
                            color: "#999",
                            userSelect: "none",
                            borderRight: "1px solid #eee",
                            marginRight: 10,
                          }}
                        >
                          {(rowIdx * 16)
                            .toString(16)
                            .padStart(4, "0")
                            .toUpperCase()}
                        </span>
                        <span style={{ width: 340, color: "#005cc5" }}>
                          {chunk
                            .map((b: number) =>
                              b.toString(16).padStart(2, "0").toUpperCase()
                            )
                            .join(" ")}
                        </span>
                        <span style={{ color: "#666", marginLeft: 16 }}>
                          {chunk
                            .map((b: number) =>
                              b >= 32 && b <= 126 ? String.fromCharCode(b) : "."
                            )
                            .join("")}
                        </span>
                      </div>
                    ))}
                </div>
              ),
            },
            {
              key: "base64",
              label: "Base64 原文",
              icon: <FileTextOutlined />,
              children: (
                <Editor
                  height="100%"
                  defaultLanguage="text"
                  value={base64Str}
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    wordWrap: "on",
                  }}
                />
              ),
            },
          ]}
        />
      );
    }

    let formattedContent = bodyContent;
    let language = "json";
    try {
      const jsonObj = JSON.parse(bodyContent);
      formattedContent = JSON.stringify(jsonObj, null, 2);
    } catch (e) {
      if (bodyContent.trim().startsWith("<")) {
        language = "html";
      } else {
        language = "plaintext";
      }
    }

    return (
      <Editor
        height="100%"
        language={language}
        value={formattedContent}
        options={{
          readOnly: true,
          minimap: { enabled: false },
          wordWrap: "on",
          scrollBeyondLastLine: false,
          folding: true,
          lineNumbers: "on",
        }}
      />
    );
  };

  const columns: any = [
    {
      title: "#",
      dataIndex: "id",
      width: 50,
      align: "center",
      render: (_: any, __: any, index: number) => (
        <span style={{ color: "#999" }}>{index + 1}</span>
      ),
    },
    {
      title: "方法",
      dataIndex: "method",
      width: 80,
      align: "center",
      render: (method: string) => {
        const color =
          method === "GET" ? "blue" : method === "POST" ? "green" : "orange";
        return <Tag color={color}>{method}</Tag>;
      },
    },
    {
      title: "地址路径",
      dataIndex: "host",
      width: 200,
      align: "center",
      ellipsis: true,
      render: (host: string) => <span style={{ fontWeight: 500 }}>{host}</span>,
    },
    {
      title: "参数",
      dataIndex: "path",
      align: "center",
      ellipsis: true,
      render: (path: string) => <span style={{ color: "#666" }}>{path}</span>,
    },
    {
      title: "状态",
      dataIndex: "status",
      width: 80,
      align: "center",
      render: (status: number) =>
        status ? (
          <Badge status={getStatusColor(status) as any} text={status} />
        ) : (
          <Spin size="small" />
        ),
    },
    {
      title: "类型",
      dataIndex: "contentType",
      width: 120,
      align: "center",
      ellipsis: true,
      render: (t: string) => (
        <span style={{ fontSize: 11, color: "#999" }}>{t?.split(";")[0]}</span>
      ),
    },
    {
      title: "时间",
      dataIndex: "startTime",
      width: 90,
      align: "center",
      render: (t: number) => (
        <span style={{ color: "#aaa", fontSize: 12 }}>
          {dayjs(t).format("HH:mm:ss")}
        </span>
      ),
    },
  ];

  const renderDetailPane = () => {
    if (!selectedReq)
      return (
        <div
          style={{
            height: "100%",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            color: "#ccc",
          }}
        >
          选择请求查看详情
        </div>
      );

    const headersText = (h: any) =>
      Object.entries(h || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n");

    const items = [
      {
        key: "headers",
        label: "Headers",
        children: (
          <div style={{ display: "flex", height: "100%" }}>
            <div
              style={{
                flex: 1,
                borderRight: "1px solid #eee",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  padding: "4px 13px",
                  background: "#f5f5f5",
                  fontSize: 11,
                  fontWeight: "bold",
                }}
              >
                Request Headers
              </div>
              <Editor
                height="100%"
                defaultLanguage="yaml"
                value={headersText(selectedReq.requestHeaders)}
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  lineNumbers: "off",
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
            <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
              <div
                style={{
                  padding: "4px 8px",
                  background: "#f5f5f5",
                  fontSize: 11,
                  fontWeight: "bold",
                }}
              >
                Response Headers
              </div>
              <Editor
                height="100%"
                defaultLanguage="yaml"
                value={headersText(selectedReq.responseHeaders)}
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  lineNumbers: "off",
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
          </div>
        ),
      },
      {
        key: "request",
        label: "Request Body",
        children: (
          <div style={{ height: "100%", overflow: "hidden" }}>
            {renderBodyContent(selectedReq.requestBody)}
          </div>
        ),
      },
      {
        key: "response",
        label: "Response Body",
        children: (
          <div
            style={{ height: "100%", display: "flex", flexDirection: "column" }}
          >
            <div
              style={{
                padding: "4px 8px",
                background: "#f5f5f5",
                display: "flex",
                justifyContent: "space-between",
                fontSize: 12,
              }}
            >
              <span style={{ marginLeft: 6 }}>
                Type: {selectedReq.contentType}
              </span>
              <Button size="small" icon={<CopyOutlined />} type="text">
                复制
              </Button>
            </div>
            <div style={{ flex: 1, overflow: "hidden" }}>
              {renderBodyContent(selectedReq.responseBody)}
            </div>
          </div>
        ),
      },
    ];

    return (
      <>
        <style>
          {`
            .full-height-tabs { height: 100%; display: flex; flex-direction: column; }
            .full-height-tabs .ant-tabs-content { height: 100%; flex: 1; }
            .full-height-tabs .ant-tabs-tabpane { height: 100%; }
            .ant-tabs-nav { margin-bottom: 0 !important; }
            .ant-tabs-nav .ant-tabs-nav-wrap { padding-left: 13px !important; }
          `}
        </style>
        <Tabs
          items={items}
          size="small"
          className="full-height-tabs"
          style={{ height: "100%" }}
        />
      </>
    );
  };

  const deviceOptions = [
    {
      label: (
        <span>
          <AppstoreOutlined /> 全部设备
        </span>
      ),
      value: "all",
    },
    ...devices
      .filter((d) => d.status === "online")
      .map((d) => ({
        label: (
          <span>
            {d.type === "android" ? <AndroidOutlined /> : <AppleOutlined />}{" "}
            {deviceAliases[d.id] || d.name}
          </span>
        ),
        value: d.id,
      })),
  ];

  return (
    <Layout
      style={{
        height: "100%",
        background: "#fff",
        userSelect: isResizing ? "none" : "auto",
      }}
    >
      <div
        style={{
          height: 48,
          borderBottom: "1px solid #e8e8e8",
          display: "flex",
          alignItems: "center",
          padding: "0 16px",
          justifyContent: "space-between",
          background: "#fafafa",
        }}
      >
        <Space>
          <Select
            value={targetDeviceId}
            onChange={setTargetDeviceId}
            style={{ width: 140 }}
            options={deviceOptions}
            variant="filled"
          />
          <Tooltip title={isCapturing ? "停止抓包" : "开始抓包"}>
            <Button
              type={isCapturing ? "primary" : "default"}
              danger={isCapturing}
              icon={
                isCapturing ? <PauseCircleOutlined /> : <PlayCircleOutlined />
              }
              onClick={toggleCapture}
            ></Button>
          </Tooltip>
        </Space>
        <Space>
          <Tooltip title="清空">
            <Button icon={<ClearOutlined />} onClick={() => setRequests([])} />
          </Tooltip>
          <Input
            prefix={<FilterOutlined style={{ color: "#ccc" }} />}
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="Filter URL..."
            style={{ width: 200 }}
            variant="filled"
          />
          <Tooltip title="设置">
            <Button
              icon={<SettingOutlined />}
              onClick={() => setSettingModalVisible(true)}
            />
          </Tooltip>
        </Space>
      </div>

      <Layout
        style={{
          height: "calc(100% - 48px)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* 🔥 上半部分：列表区域 (Flex 1 自动填满剩余空间) */}
        <div
          style={{
            flex: 1,
            overflow: "hidden",
            minHeight: 100, // 给上半部分一个最小高度
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            className="auto-fit-table no-scrollbar"
            style={{ flex: 1 }}
            ref={listContainerRef}
          >
            <Table
              dataSource={filteredRequests}
              columns={columns}
              rowKey="id"
              size="small"
              pagination={false}
              scroll={{ y: "100%" }}
              onRow={(record) => ({
                onClick: () => setSelectedReq(record),
                style: {
                  cursor: "pointer",
                  background:
                    selectedReq?.id === record.id ? "#e6f7ff" : "transparent",
                },
              })}
            />
          </div>
        </div>

        {/* 🔥 分割线：支持拖拽 */}
        <div
          onMouseDown={startResizing}
          style={{
            height: 6,
            background: isResizing ? "#1890ff" : "#f0f0f0", // 拖拽时变色
            cursor: "row-resize",
            borderTop: "1px solid #ddd",
            borderBottom: "1px solid #ddd",
            transition: "background 0.2s",
            zIndex: 10,
          }}
        />

        {/* 🔥 下半部分：高度由 bottomPanelHeight 状态控制 */}
        <div
          style={{
            height: bottomPanelHeight, // 动态高度
            minHeight: 250,
            background: "#fff",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {selectedReq && (
            <div
              style={{
                padding: "4px 12px",
                borderBottom: "1px solid #eee",
                background: "#fbfbfb",
                display: "flex",
                justifyContent: "space-between",
                fontSize: 12,
              }}
            >
              <Tooltip
                title={
                  <div
                    style={{
                      wordBreak: "break-all",
                      maxWidth: "600px",
                      maxHeight: "300px",
                      overflowY: "auto",
                    }}
                  >
                    {selectedReq.url}
                  </div>
                }
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    marginLeft: 2,
                    width: "71%",
                    fontFamily: "monospace",
                    fontWeight: "bold",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {selectedReq.url}
                </div>
              </Tooltip>

              <Space>
                <Divider orientation="vertical" />
                <Button
                  size="small"
                  icon={<RobotOutlined />}
                  type="primary"
                  ghost
                  onClick={handleAIAnalyze}
                >
                  AI 分析
                </Button>
                <Button
                  size="small"
                  icon={<RedoOutlined />}
                  onClick={handleReplay}
                >
                  重试
                </Button>
                <Button
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() => {
                    navigator.clipboard.writeText(selectedReq.url);
                    message.success("URL 已复制");
                  }}
                >
                  复制
                </Button>
              </Space>
            </div>
          )}
          <div style={{ flex: 1, overflow: "hidden" }}>
            {renderDetailPane()}
          </div>
        </div>
      </Layout>

      <Modal
        title="抓包设置"
        open={settingModalVisible}
        onCancel={() => setSettingModalVisible(false)}
        footer={null}
        width={500}
      >
        <Descriptions column={1} bordered size="small">
          <Descriptions.Item label="监听端口">
            <Input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              style={{ width: 100 }}
            />
          </Descriptions.Item>
          <Descriptions.Item label="HTTPS 证书">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                width: "100%",
              }}
            >
              <span>必须安装 CA 证书才能解密 HTTPS 流量</span>
              <Button
                type="primary"
                icon={<SafetyCertificateOutlined />}
                onClick={handleInstallCert}
              >
                安装证书到手机
              </Button>
            </div>
          </Descriptions.Item>
          <Descriptions.Item label="自动滚动">
            <Switch
              checkedChildren={<ArrowDownOutlined />}
              unCheckedChildren={<ArrowDownOutlined />}
              checked={autoScroll}
              onChange={setAutoScroll}
              size="small"
            />
          </Descriptions.Item>
        </Descriptions>
        <Alert
          style={{ marginTop: 16 }}
          message="使用说明"
          description={
            <ul style={{ paddingLeft: 20, margin: 0 }}>
              <li>1. 点击“安装证书到手机”，并在手机上信任该证书。</li>
              <li>2. 确保手机和电脑在同一 WiFi 下。</li>
              <li>3. 在手机 WiFi 设置中配置代理：电脑IP : {port}</li>
            </ul>
          }
          type="info"
          showIcon
        />
      </Modal>
      <Modal
        title={
          <span>
            <RobotOutlined style={{ color: "#1890ff" }} /> AI 智能分析
          </span>
        }
        open={aiModalVisible}
        onCancel={() => setAiModalVisible(false)}
        footer={null}
        width={800}
        styles={{ body: { height: "60vh", overflow: "auto" } }}
      >
        {aiLoading && !aiResult && <Spin tip="AI 正在思考中..." />}
        <div style={{ lineHeight: 1.6, fontSize: 14 }}>
          <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
            {aiResult}
          </pre>
        </div>
      </Modal>
    </Layout>
  );
};

export default NetworkSniffer;
