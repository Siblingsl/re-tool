import React, { useState, useEffect } from "react";
import { Select, Button, message } from "antd";
import {
  ArrowRightOutlined,
  SyncOutlined,
  CopyOutlined,
  CodeOutlined,
} from "@ant-design/icons";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { convertCode } from "../../services/aiService";

interface CodeConverterProps {
  initialCode?: string;
}

const CodeConverter: React.FC<CodeConverterProps> = ({ initialCode = "" }) => {
  const [inputCode, setInputCode] = useState(initialCode);
  const [outputCode, setOutputCode] = useState("");
  const [targetLang, setTargetLang] = useState("Python");
  const [converting, setConverting] = useState(false);

  // 当外部传入的初始代码变化时，更新输入框（例如从抽屉跳转过来）
  useEffect(() => {
    if (initialCode) setInputCode(initialCode);
  }, [initialCode]);

  const handleConvert = async () => {
    if (!inputCode.trim()) return message.warning("请输入代码");
    setConverting(true);
    try {
      const res = await convertCode({
        sourceCode: inputCode,
        sourceLang: "IDA C",
        targetLang,
      });
      setOutputCode(res);
      message.success("转换成功");
    } catch (e) {
      message.error("转换失败");
    } finally {
      setConverting(false);
    }
  };

  return (
    <>
      <div className="content-header">
        <span style={{ fontSize: 16, fontWeight: 600 }}>
          IDA 伪代码转译 / 算法还原
        </span>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontSize: 13, color: "#64748b" }}>目标语言:</span>
          <Select
            value={targetLang}
            onChange={setTargetLang}
            style={{ width: 120 }}
            options={[
              { value: "Python", label: "Python" },
              { value: "JavaScript", label: "JavaScript" },
              { value: "Java", label: "Java" },
            ]}
          />
          <Button
            type="primary"
            icon={converting ? <SyncOutlined spin /> : <ArrowRightOutlined />}
            onClick={handleConvert}
          >
            开始转译
          </Button>
        </div>
      </div>
      <div className="tool-container">
        <div className="code-editor-wrapper">
          <div className="editor-pane">
            <div className="pane-toolbar">
              <span>输入: IDA F5 伪代码 (C/C++)</span>
              <Button type="text" size="small" onClick={() => setInputCode("")}>
                清空
              </Button>
            </div>
            <textarea
              className="editor-area"
              placeholder="// 请在此粘贴 IDA Pro F5 生成的伪代码..."
              value={inputCode}
              onChange={(e) => setInputCode(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="editor-pane">
            <div className="pane-toolbar">
              <span>输出结果: {targetLang}</span>
              <Button
                type="text"
                size="small"
                icon={<CopyOutlined />}
                onClick={() => {
                  navigator.clipboard.writeText(outputCode);
                  message.success("已复制");
                }}
              >
                复制
              </Button>
            </div>
            <div
              style={{ flex: 1, position: "relative", background: "#1e1e1e" }}
            >
              {outputCode ? (
                <SyntaxHighlighter
                  language={targetLang.toLowerCase()}
                  style={vscDarkPlus}
                  customStyle={{
                    margin: 0,
                    height: "100%",
                    padding: "16px",
                    background: "transparent",
                  }}
                  showLineNumbers
                >
                  {outputCode}
                </SyntaxHighlighter>
              ) : (
                <div
                  style={{
                    height: "100%",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "center",
                    alignItems: "center",
                    color: "#666",
                  }}
                >
                  <CodeOutlined
                    style={{ fontSize: 32, opacity: 0.3, marginBottom: 10 }}
                  />
                  <div>等待输入与执行...</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default CodeConverter;
