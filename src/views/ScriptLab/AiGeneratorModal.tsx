import React, { useState } from "react";
import { Modal, Form, Input, Select, Button, message, Card } from "antd";
import { RestOutlined, ThunderboltFilled } from "@ant-design/icons";
import { convertCode } from "../../services/aiService"; // 复用你之前的 AI 服务

interface AiGeneratorProps {
  visible: boolean;
  onClose: () => void;
  onGenerate: (code: string) => void;
}

const AiGeneratorModal: React.FC<AiGeneratorProps> = ({
  visible,
  onClose,
  onGenerate,
}) => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);

      // 1. 构建 Prompt (提示词工程)
      const prompt = `
You are a Frida Script Expert. Generate a robust Frida JavaScript hook script based on the following context.

Target Info:
- Class: ${values.className}
- Method: ${values.methodName}
- Goal: ${values.goal} (e.g. print args, modify return value)

Decompiled Code (Reference):
\`\`\`java
${values.codeSnippet}
\`\`\`

Requirements:
1. Use 'Java.use' or 'Java.choose' appropriately.
2. Handle method overloads (use .overload(...) if necessary, or catch error).
3. Log arguments and return value nicely.
4. Wrap in 'Java.perform'.
5. Return ONLY the JavaScript code, no markdown.
`;

      // 2. 调用 AI (假设 aiService 支持通用文本生成)
      // 这里复用你之前的 convertCode，或者新建一个 generateText 方法
      const result = await convertCode({
        sourceCode: prompt,
        sourceLang: "Prompt",
        targetLang: "Frida Script",
      });

      // 3. 回填代码
      onGenerate(result);
      message.success("生成成功！");
      onClose();
    } catch (e) {
      message.error("生成失败，请检查输入");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      title={
        <span>
          <ThunderboltFilled style={{ color: "#faad14" }} /> AI Hook 生成助手
        </span>
      }
      open={visible}
      onCancel={onClose}
      width={600}
      footer={[
        <Button key="cancel" onClick={onClose}>
          取消
        </Button>,
        <Button
          key="submit"
          type="primary"
          loading={loading}
          onClick={handleGenerate}
        >
          ✨ 生成脚本
        </Button>,
      ]}
    >
      <Form form={form} layout="vertical">
        <div style={{ display: "flex", gap: 16 }}>
          <Form.Item
            label="类名 (Class Name)"
            name="className"
            style={{ flex: 1 }}
            rules={[{ required: true, message: "请输入完整类名" }]}
            initialValue="com.example.app.MainActivity"
          >
            <Input placeholder="e.g. com.example.util.Security" />
          </Form.Item>
          <Form.Item
            label="方法名 (Method)"
            name="methodName"
            style={{ width: 180 }}
            rules={[{ required: true, message: "请输入方法名" }]}
            initialValue="isVip"
          >
            <Input placeholder="e.g. check" />
          </Form.Item>
        </div>

        <Form.Item
          label="Hook 目标 (你想要做什么？)"
          name="goal"
          initialValue="打印入参并强制返回 true"
        >
          <Input placeholder="例如：打印所有参数值、修改返回值为 true、打印堆栈..." />
        </Form.Item>

        <Form.Item
          label="参考代码 (从 Jadx/IDA 复制伪代码)"
          name="codeSnippet"
          tooltip="提供反编译后的 Java 或 Smali 代码，有助于 AI 理解参数类型和重载"
        >
          <Input.TextArea
            rows={6}
            placeholder="// 粘贴 Java 伪代码..."
            style={{ fontFamily: "monospace", fontSize: 12 }}
          />
        </Form.Item>
      </Form>

      <Card
        size="small"
        type="inner"
        style={{ background: "#f6ffed", borderColor: "#b7eb8f" }}
      >
        <span style={{ fontSize: 12, color: "#389e0d" }}>
          💡 提示：提供的伪代码越详细，AI 处理重载 (Overload) 就越准确。
        </span>
      </Card>
    </Modal>
  );
};

export default AiGeneratorModal;
