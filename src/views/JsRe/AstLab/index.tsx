import React, { useEffect, useState } from 'react';
import {
    Layout,
    Card,
    Button,
    Input,
    Space,
    Typography,
    Select,
    Divider,
    Tooltip,
    Row,
    Col,
    Empty,
    theme,
    message
} from 'antd';
import {
    ThunderboltOutlined,
    SaveOutlined,
    CopyOutlined,
    DeleteOutlined,
    BugOutlined,
    PlayCircleOutlined,
    FileTextOutlined
} from '@ant-design/icons';
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

const AstLab: React.FC = () => {
    const { token } = theme.useToken();
    const [inputCode, setInputCode] = useState<string>("");
    const [outputCode, setOutputCode] = useState<string>("");
    const [engine, setEngine] = useState<string>("babel");
    const [processing, setProcessing] = useState(false);

    // Use ref to track processing state without triggering effect re-run
    const processingRef = React.useRef(processing);
    React.useEffect(() => { processingRef.current = processing; }, [processing]);

    // 监听后端事件
    useEffect(() => {
        const unlistenPromise = listen("weblab-event", (event: any) => {
            const payload = event.payload;
            console.log("WebLab Event:", payload);
            if (!payload) return;

            // 处理 AST 结果
            if (payload.type === "ast_result") {
                const { code, cost } = payload.payload;
                setOutputCode(`// [AST还原成功] 耗时: ${cost}ms\n// 引擎: ${engine} (Node.js)\n\n${code}`);
                setProcessing(false);
                message.success(`还原成功 (耗时 ${cost}ms)`);
            }

            // 处理错误
            if (payload.type === "error") {
                console.error("WebLab Backend Error:", payload.payload);
                if (processingRef.current) {
                    message.error("处理失败: " + payload.payload);
                    setProcessing(false);
                }
            }
        });

        return () => {
            unlistenPromise.then(unlisten => unlisten());
        };
    }, []); // Empty dependency array = persistent listener

    const handleDeobfuscate = async () => {
        if (!inputCode) return;
        setProcessing(true);
        setOutputCode(""); // 清空旧结果

        try {
            // 发送命令到后端
            await invoke("send_web_command", {
                action: "ast_deobfuscate",
                data: {
                    code: inputCode,
                    // engine // 如果后端支持多引擎，这里可以传
                }
            });
            // 注意：因为是异步事件返回，所以这里不直接 setProcessing(false)
            // 设置一个超时，防止一直转圈
            setTimeout(() => {
                setProcessing((prev) => {
                    if (prev) {
                        message.warning("请求超时，请检查浏览器引擎是否已启动");
                        return false;
                    }
                    return prev;
                });
            }, 10000);

        } catch (e: any) {
            console.error(e);
            const errMsg = typeof e === 'string' ? e : (e.message || JSON.stringify(e));
            message.error("发送指令失败: " + errMsg);
            setProcessing(false);
        }
    };

    return (
        <div style={{ height: '100%', display: 'flex', flexDirection: 'column', backgroundColor: '#f0f2f5' }}>
            {/* Header Section */}
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
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <ThunderboltOutlined style={{ fontSize: 22, color: token.colorPrimary }} />
                        <span style={{ fontSize: 20, fontWeight: 600, color: "#1f1f1f" }}>
                            AST 混淆还原实验室
                        </span>
                    </div>
                </div>
                <Space>
                    <Select
                        defaultValue="babel"
                        style={{ width: 140 }}
                        value={engine}
                        onChange={setEngine}
                        options={[
                            { value: 'babel', label: 'Babel (AST)' },
                            { value: 'swc', label: 'SWC (Fast)' },
                            { value: 'ugly', label: 'UglifyJS (Clean)' },
                        ]}
                    />
                    <Button
                        type="primary"
                        icon={<PlayCircleOutlined />}
                        loading={processing}
                        onClick={handleDeobfuscate}
                    >
                        一键还原
                    </Button>
                </Space>
            </div>

            {/* Main Editor Area */}
            <div style={{ flex: 1, padding: 12, overflow: "hidden", display: "flex", flexDirection: "column" }}>
                <Row gutter={16} style={{ flex: 1, minHeight: 0 }}>
                    {/* Left: Input */}
                    <Col span={12} style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <Card
                            title={<Space><FileTextOutlined /> <Text strong>混淆代码输入</Text></Space>}
                            extra={
                                <Space size="small">
                                    <Tooltip title="清空"><Button type="text" size="small" icon={<DeleteOutlined />} onClick={() => setInputCode("")} /></Tooltip>
                                    <Tooltip title="从剪贴板粘贴"><Button type="text" size="small" icon={<CopyOutlined />} /></Tooltip>
                                </Space>
                            }
                            bodyStyle={{ padding: 0, flex: 1, display: 'flex', flexDirection: 'column' }}
                            style={{ height: '100%', display: 'flex', flexDirection: 'column', boxShadow: '0 4px 12px rgba(0,0,0,0.05)' }}
                        >
                            <TextArea
                                value={inputCode}
                                onChange={(e) => setInputCode(e.target.value)}
                                style={{
                                    flex: 1,
                                    resize: 'none',
                                    border: 'none',
                                    padding: 12,
                                    fontFamily: "'JetBrains Mono', monospace",
                                    fontSize: 13,
                                    backgroundColor: '#fafafa'
                                }}
                                placeholder="// 在此粘贴混淆后的 JavaScript 代码..."
                                spellCheck={false}
                            />
                            <div style={{ padding: '8px 16px', borderTop: '1px solid #f0f0f0', fontSize: 12, color: '#999', display: 'flex', justifyContent: 'space-between' }}>
                                <span>Ln: {inputCode.split('\n').length}, Col: 0</span>
                                <span>Length: {inputCode.length}</span>
                            </div>
                        </Card>
                    </Col>

                    {/* Right: Output */}
                    <Col span={12} style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <Card
                            title={<Space><BugOutlined /> <Text strong>还原结果</Text></Space>}
                            extra={
                                <Space size="small">
                                    <Button size="small" icon={<SaveOutlined />}>保存文件</Button>
                                    <Tooltip title="复制结果"><Button type="text" size="small" icon={<CopyOutlined />} /></Tooltip>
                                </Space>
                            }
                            bodyStyle={{ padding: 0, flex: 1, display: 'flex', flexDirection: 'column' }}
                            style={{ height: '100%', display: 'flex', flexDirection: 'column', boxShadow: '0 4px 12px rgba(0,0,0,0.05)' }}
                        >
                            {outputCode ? (
                                <TextArea
                                    value={outputCode}
                                    readOnly
                                    style={{
                                        flex: 1,
                                        resize: 'none',
                                        border: 'none',
                                        padding: 12,
                                        fontFamily: "'JetBrains Mono', monospace",
                                        fontSize: 13,
                                        color: '#389e0d',
                                        backgroundColor: '#f6ffed'
                                    }}
                                />
                            ) : (
                                <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无输出结果" />
                                </div>
                            )}
                        </Card>
                    </Col>
                </Row>
            </div>
        </div>
    );
}

export default AstLab;
