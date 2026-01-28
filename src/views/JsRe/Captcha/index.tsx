import React, { useState } from 'react';
import {
    Layout,
    Card,
    Button,
    Upload,
    Select,
    Typography,
    Statistic,
    Row,
    Col,
    Tag,
    Input,
    message,
    Steps,
    Divider,
    Empty
} from 'antd';
import {
    InboxOutlined,
    ScanOutlined,
    SettingOutlined,
    RocketOutlined,
    RobotOutlined
} from '@ant-design/icons';

const { Dragger } = Upload;
const { Title, Text } = Typography;
const { Option } = Select;
const { CheckableTag } = Tag;

const AiCaptcha: React.FC = () => {
    const [fileList, setFileList] = useState<any[]>([]);
    const [analyzing, setAnalyzing] = useState(false);
    const [result, setResult] = useState<string | null>(null);
    const [service, setService] = useState("ocr-local");

    const handleUpload = (info: any) => {
        const { status } = info.file;
        setFileList(info.fileList.slice(-1)); // Keep only last file
        if (status === 'done') {
            message.success(`${info.file.name} 上传成功.`);
            setResult(null);
        }
    };

    const handleAnalyze = () => {
        if (fileList.length === 0) {
            message.warning("请先上传验证码图片");
            return;
        }
        setAnalyzing(true);
        // Mock processing
        setTimeout(() => {
            setAnalyzing(false);
            setResult("X7dF9"); // Mock result
            message.success("识别成功!");
        }, 1200);
    };

    return (
        <div style={{ height: '100%', padding: 24, backgroundColor: '#f0f2f5', overflowY: 'auto' }}>
            {/* Header */}
            <div style={{ marginBottom: 24, textAlign: 'center' }}>
                <Title level={3} style={{ marginBottom: 8, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12 }}>
                    <RobotOutlined style={{ color: '#1890ff' }} />
                    AI 验证码识别测试台
                </Title>
                <Text type="secondary">集成多种 OCR 与深度学习模型的通用验证码识别接口测试工具</Text>
            </div>

            <Row gutter={24} style={{ maxWidth: 1000, margin: '0 auto' }}>
                {/* Left: Configuration */}
                <Col span={8}>
                    <Card
                        title="识别配置"
                        bordered={false}
                        style={{ height: '100%', boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }}
                    >
                        <div style={{ marginBottom: 16 }}>
                            <Text strong>识别引擎 Service</Text>
                            <Select
                                value={service}
                                onChange={setService}
                                style={{ width: '100%', marginTop: 8 }}
                            >
                                <Option value="ocr-local">本地 OCR (Tesseract)</Option>
                                <Option value="ocr-cloud">百度云 OCR (通用)</Option>
                                <Option value="cnn-custom">自定义 CNN 模型 (.onnx)</Option>
                                <Option value="human-platform">打码平台 (YesCaptcha 等)</Option>
                            </Select>
                        </div>

                        {service.includes("cloud") || service.includes("platform") ? (
                            <div style={{ marginBottom: 16 }}>
                                <Text strong>API Key / Token</Text>
                                <Input.Password placeholder="Enter API Key" style={{ marginTop: 8 }} />
                            </div>
                        ) : null}

                        <Divider />

                        <div style={{ marginBottom: 16 }}>
                            <Text strong>预处理 Pre-process</Text>
                            <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <CheckableTag checked={true} onChange={() => { }}>去噪点</CheckableTag>
                                <CheckableTag checked={false} onChange={() => { }}>二值化</CheckableTag>
                                <CheckableTag checked={false} onChange={() => { }}>干扰线移除</CheckableTag>
                            </div>
                        </div>

                        <Button type="primary" block icon={<RocketOutlined />} size="large" onClick={handleAnalyze} loading={analyzing} disabled={fileList.length === 0}>
                            开始识别 (Analyze)
                        </Button>
                    </Card>
                </Col>

                {/* Right: Upload & Result */}
                <Col span={16}>
                    <Card bordered={false} style={{ minHeight: 400, boxShadow: '0 2px 8px rgba(0,0,0,0.08)', display: 'flex', flexDirection: 'column' }} bodyStyle={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                        <Dragger
                            name="file"
                            multiple={false}
                            maxCount={1}
                            fileList={fileList}
                            onChange={handleUpload}
                            beforeUpload={() => false} // Manual upload
                            style={{ padding: 24, background: '#fafafa', border: '2px dashed #d9d9d9' }}
                            showUploadList={{ showRemoveIcon: true }}
                        >
                            <p className="ant-upload-drag-icon">
                                <InboxOutlined style={{ color: '#1890ff' }} />
                            </p>
                            <p className="ant-upload-text">点击或将验证码图片拖拽至此区域</p>
                            <p className="ant-upload-hint">
                                支持 JPG, PNG, BMP 格式. 单个文件不超过 2MB
                            </p>
                        </Dragger>

                        {/* Result Display */}
                        <div style={{ marginTop: 24, padding: 24, backgroundColor: '#f9f9f9', borderRadius: 8, flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                            {analyzing ? (
                                <div style={{ textAlign: 'center' }}>
                                    <ScanOutlined spin style={{ fontSize: 32, color: '#1890ff', marginBottom: 16 }} />
                                    <div>正在使用 {service} 分析中...</div>
                                </div>
                            ) : result ? (
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ color: '#52c41a', fontSize: 16, marginBottom: 8 }}>
                                        识别成功 (128ms)
                                    </div>
                                    <div style={{
                                        fontWeight: 700,
                                        fontSize: 42,
                                        color: '#333',
                                        letterSpacing: 4,
                                        border: '2px solid #52c41a',
                                        padding: '4px 32px',
                                        borderRadius: 8,
                                        backgroundColor: '#fff',
                                        fontFamily: 'monospace'
                                    }}>
                                        {result}
                                    </div>
                                    <div style={{ marginTop: 16 }}>
                                        <Tag color="green">置信度: 99.2%</Tag>
                                        <Tag>Type: Alphanumeric</Tag>
                                    </div>
                                </div>
                            ) : (
                                <Empty description="等待识别结果" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                            )}
                        </div>
                    </Card>
                </Col>
            </Row>
        </div>
    );
}

export default AiCaptcha;
