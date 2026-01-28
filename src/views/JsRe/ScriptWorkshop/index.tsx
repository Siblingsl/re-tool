import React, { useState } from 'react';
import {
    Card,
    Button,
    Input,
    Space,
    Typography,
    Row,
    Col,
    Empty,
    List,
    Tag,
    Segmented,
    Tooltip,
    Badge,
    Popconfirm,
    message,
    theme,
    Divider
} from 'antd';
import {
    FileTextOutlined,
    PlusOutlined,
    SearchOutlined,
    DeleteOutlined,
    SaveOutlined,
    PlayCircleOutlined,
    ThunderboltOutlined,
    ClockCircleOutlined,
    EditOutlined,
    ClockCircleFilled,
} from '@ant-design/icons';
import Editor from "@monaco-editor/react";

const { Title, Text } = Typography;

// Types
interface ScriptItem {
    id: string;
    name: string;
    code: string;
    timing: 'document_start' | 'document_end';
    description?: string;
    updatedAt: string;
}

// Mock Data
const MOCK_SCRIPTS: ScriptItem[] = [
    {
        id: '1',
        name: 'Anti-Debugger Bypass',
        code: '// Bypasses common anti-debugging checks\nif (window.outerHeight - window.innerHeight > 200) {\n  console.log("DevTools detected but ignored");\n}',
        timing: 'document_start',
        description: 'Bypass window size detection',
        updatedAt: '2023-11-15 10:30'
    },
    {
        id: '2',
        name: 'Log All Network Requests',
        code: '// Hook into XMLHttpRequest\nconst originalOpen = XMLHttpRequest.prototype.open;\nXMLHttpRequest.prototype.open = function(...args) {\n  console.log("XHR:", args);\n  return originalOpen.apply(this, args);\n};',
        timing: 'document_start',
        description: 'Monitor all XHR params',
        updatedAt: '2023-11-16 14:20'
    },
    {
        id: '3',
        name: 'DOM Element Highlighter',
        code: '// Highlights all div elements\ndocument.querySelectorAll("div").forEach(el => {\n  el.style.border = "1px solid red";\n});',
        timing: 'document_end', // Needs DOM ready
        description: 'Visualize structure',
        updatedAt: '2023-11-17 09:15'
    }
];

const ScriptWorkshop: React.FC = () => {
    const { token } = theme.useToken();

    // State
    const [scripts, setScripts] = useState<ScriptItem[]>(MOCK_SCRIPTS);
    const [activeScriptId, setActiveScriptId] = useState<string>(MOCK_SCRIPTS[0].id);
    const [currentCode, setCurrentCode] = useState<string>(MOCK_SCRIPTS[0].code);
    const [currentTiming, setCurrentTiming] = useState<'document_start' | 'document_end'>(MOCK_SCRIPTS[0].timing);
    const [searchText, setSearchText] = useState("");

    // Get active script object
    const activeScript = scripts.find(s => s.id === activeScriptId) || scripts[0];
    const filteredScripts = scripts.filter(s =>
        s.name.toLowerCase().includes(searchText.toLowerCase())
    );

    // Handlers
    const handleScriptSelect = (id: string) => {
        const script = scripts.find(s => s.id === id);
        if (script) {
            setActiveScriptId(id);
            setCurrentCode(script.code);
            setCurrentTiming(script.timing);
        }
    };

    const handleCodeChange = (value: string | undefined) => {
        setCurrentCode(value || '');
    };

    const handleNameChange = (newName: string) => {
        setScripts(prev => prev.map(s => s.id === activeScriptId ? { ...s, name: newName } : s));
    };

    const handleSave = () => {
        setScripts(prev => prev.map(s =>
            s.id === activeScriptId
                ? { ...s, code: currentCode, timing: currentTiming, updatedAt: new Date().toLocaleString() }
                : s
        ));
        message.success('脚本已保存');
    };

    const handleRun = () => {
        message.success({
            content: `已成功注入: ${activeScript.name}`,
            icon: <ThunderboltOutlined style={{ color: '#52c41a' }} />
        });
    };

    const handleCreateNew = () => {
        const newScript: ScriptItem = {
            id: Date.now().toString(),
            name: `未命名脚本 ${scripts.length + 1}`,
            code: '// Write your script here...',
            timing: 'document_start',
            description: '',
            updatedAt: new Date().toLocaleString()
        };
        setScripts([...scripts, newScript]);
        handleScriptSelect(newScript.id);
    };

    const handleDelete = (id: string) => {
        const newScripts = scripts.filter(s => s.id !== id);
        setScripts(newScripts);
        if (id === activeScriptId && newScripts.length > 0) {
            handleScriptSelect(newScripts[0].id);
        }
    };

    return (
        <div style={{ height: '100%', display: 'flex', flexDirection: 'column', backgroundColor: '#f0f2f5' }}>
            {/* Header Section (Matches BrowserHome) */}
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
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <div style={{
                        background: '#e6f7ff',
                        width: 36, height: 36,
                        borderRadius: 8,
                        display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                        <FileTextOutlined style={{ fontSize: 20, color: token.colorPrimary }} />
                    </div>
                    <span style={{ fontSize: 18, fontWeight: 600, color: "#1f1f1f" }}>
                        我的脚本工坊
                    </span>
                    <Divider type="vertical" />
                    <Text type="secondary" style={{ fontSize: 13 }}>
                        JS 逆向辅助脚本的编写、管理与注入
                    </Text>
                </div>
            </div>

            {/* Content Area */}
            <div style={{ flex: 1, padding: 10, minHeight: 0, overflow: 'hidden' }}>
                <Row gutter={20} style={{ height: '100%' }}>
                    {/* Left: Script List */}
                    <Col span={6} style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <Card
                            title={
                                <Input
                                    prefix={<SearchOutlined style={{ color: "#bfbfbf" }} />}
                                    placeholder="搜索脚本..."
                                    value={searchText}
                                    onChange={e => setSearchText(e.target.value)}
                                    style={{ width: 130, borderRadius: 15 }}
                                    allowClear
                                />}
                            extra={
                                <Tooltip title="时间排序">
                                    <Button type="text" size="small" icon={<PlusOutlined />} onClick={handleCreateNew} style={{ borderRadius: 6 }} />
                                </Tooltip>
                            }
                            styles={{ body: { padding: 0, flex: 1, overflowY: 'auto' } }}
                            style={{
                                height: '100%',
                                display: 'flex',
                                flexDirection: 'column',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.05)',
                                borderRadius: 8,
                                border: '1px solid #e8e8e8'
                            }}
                        >
                            <List
                                dataSource={filteredScripts}
                                locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无脚本" /> }}
                                renderItem={item => {
                                    const isActive = activeScriptId === item.id;
                                    return (
                                        <div
                                            onClick={() => handleScriptSelect(item.id)}
                                            style={{
                                                padding: '12px 16px',
                                                cursor: 'pointer',
                                                backgroundColor: isActive ? '#e6f7ff' : '#fff',
                                                borderLeft: isActive ? `3px solid ${token.colorPrimary}` : '3px solid transparent',
                                                borderBottom: '1px solid #f0f0f0',
                                                transition: 'all 0.2s'
                                            }}
                                            className="script-list-item"
                                        >
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                                                <Text strong={isActive} style={{ fontSize: 14, color: isActive ? token.colorPrimary : '#333' }} ellipsis>
                                                    {item.name}
                                                </Text>
                                                {item.timing === 'document_start' ?
                                                    <Tag color="orange" style={{ margin: 0, fontSize: 10, lineHeight: '18px', padding: '0 4px' }}>Start</Tag> :
                                                    <Tag color="green" style={{ margin: 0, fontSize: 10, lineHeight: '18px', padding: '0 4px' }}>End</Tag>
                                                }
                                            </div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <Text type="secondary" style={{ fontSize: 12 }}>{item.updatedAt.split(' ')[0]}</Text>
                                                {isActive && (
                                                    <Popconfirm title="确定删除此脚本？" onConfirm={(e) => { e?.stopPropagation(); handleDelete(item.id); }} onCancel={(e) => e?.stopPropagation()}>
                                                        <DeleteOutlined
                                                            style={{ color: '#ff4d4f', cursor: 'pointer' }}
                                                            onClick={(e) => e.stopPropagation()}
                                                        />
                                                    </Popconfirm>
                                                )}
                                            </div>
                                        </div>
                                    );
                                }}
                            />
                        </Card>
                    </Col>

                    {/* Right: Editor */}
                    <Col span={18} style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <Card
                            title={
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <EditOutlined style={{ color: token.colorPrimary }} />
                                    <Input
                                        value={activeScript.name}
                                        onChange={e => handleNameChange(e.target.value)}
                                        variant="borderless"
                                        style={{ fontWeight: 600, fontSize: 16, padding: '4px 0', width: 300, color: '#1f1f1f' }}
                                    />
                                </div>
                            }
                            extra={
                                <Space size="middle">
                                    <Divider type="vertical" />
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Segmented
                                            value={currentTiming}
                                            onChange={(v) => setCurrentTiming(v as any)}
                                            options={[
                                                { label: '加载前', value: 'document_start', icon: <ThunderboltOutlined /> },
                                                { label: '加载后', value: 'document_end', icon: <ClockCircleOutlined /> }
                                            ]}
                                            size="small"
                                        />
                                    </div>
                                    <Divider type="vertical" />
                                    <Button icon={<SaveOutlined />} onClick={handleSave}>保存</Button>
                                    <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleRun}>运行脚本</Button>
                                </Space>
                            }
                            styles={{
                                body: { padding: 0, flex: 1, display: 'flex', flexDirection: 'column' },
                                header: { padding: '0 24px', height: 56 }
                            }}
                            style={{
                                height: '100%',
                                display: 'flex',
                                flexDirection: 'column',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.05)',
                                borderRadius: 8,
                                border: '1px solid #e8e8e8'
                            }}
                        >
                            <Editor
                                height="100%"
                                defaultLanguage="javascript"
                                language="javascript"
                                value={currentCode}
                                onChange={handleCodeChange}
                                theme="light" // Matches standard AntD light theme
                                options={{
                                    minimap: { enabled: true, scale: 0.75 },
                                    fontSize: 13,
                                    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                    renderLineHighlight: 'all',
                                    padding: { top: 12 }
                                }}
                            />
                            <div style={{
                                padding: '8px 16px',
                                borderTop: '1px solid #f0f0f0',
                                fontSize: 12,
                                color: '#999',
                                display: 'flex',
                                justifyContent: 'space-between',
                                backgroundColor: '#fafafa',
                                borderBottomLeftRadius: 8,
                                borderBottomRightRadius: 8
                            }}>
                                <Space size={16}>
                                    <span>Ln: {currentCode.split('\n').length}</span>
                                    <span>Length: {currentCode.length}</span>
                                </Space>
                                <span>JavaScript</span>
                            </div>
                        </Card>
                    </Col>
                </Row>
            </div>
        </div>
    );
};

export default ScriptWorkshop;
