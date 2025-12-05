import React, { useState, useRef } from "react";
import {
  Layout,
  Tree,
  Button,
  message,
  Empty,
  Spin,
  Steps,
  Space,
  Dropdown,
  Modal, // 确保引入了 Modal
} from "antd";
import {
  FolderOpenOutlined,
  BuildOutlined,
  SaveOutlined,
  FileTextOutlined,
  AndroidOutlined,
  RobotOutlined,
  TranslationOutlined,
  BugOutlined,
  ReadOutlined,
} from "@ant-design/icons";
import Editor, { OnMount } from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Device } from "../../types";
import { askAiAssistant, AiTaskType } from "../../services/aiService";

const { Sider, Content } = Layout;

interface ApkBuilderProps {
  currentDevice?: Device;
}

const ApkBuilder: React.FC<ApkBuilderProps> = ({ currentDevice }) => {
  const [step, setStep] = useState(0);
  const [projectDir, setProjectDir] = useState("");
  const [treeData, setTreeData] = useState<any[]>([]);
  const [fileContent, setFileContent] = useState("");
  const [currentFilePath, setCurrentFilePath] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingTip, setLoadingTip] = useState("");

  // 编辑器语言状态
  const [editorLanguage, setEditorLanguage] = useState("xml");

  // AI 相关状态
  const editorRef = useRef<any>(null);
  const [aiModalVisible, setAiModalVisible] = useState(false);
  const [aiResult, setAiResult] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiTitle, setAiTitle] = useState("");

  // 获取编辑器选中的文本
  const getSelectedCode = () => {
    if (!editorRef.current) return fileContent;
    const model = editorRef.current.getModel();
    const selection = editorRef.current.getSelection();
    const selectedText = model.getValueInRange(selection);
    return selectedText.trim().length > 0 ? selectedText : fileContent;
  };

  const handleEditorDidMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  // --- 核心业务逻辑 ---

  // 1. 解包 APK
  const handleDecompile = async () => {
    const file = await open({
      filters: [{ name: "APK", extensions: ["apk"] }],
    });
    if (!file) return;

    setLoading(true);
    setLoadingTip("正在使用 Apktool 解包 (耗时较长)...");
    setFileContent("");
    setCurrentFilePath("");

    try {
      const outDir = await invoke<string>("apk_decode", { apkPath: file });
      message.success("解包成功");
      setProjectDir(outDir);
      setStep(1); // 进入修改阶段

      const nodes = await invoke<any[]>("scan_local_dir", { path: outDir });
      setTreeData(nodes);
    } catch (e: any) {
      message.error("解包失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  // 2. 点击文件树
  const handleSelectNode = async (selectedKeys: any, info: any) => {
    if (info.node.isLeaf && info.node.key) {
      const path = info.node.key;
      setCurrentFilePath(path);

      const ext = path.split(".").pop()?.toLowerCase();
      if (ext === "smali") setEditorLanguage("java");
      else if (ext === "xml") setEditorLanguage("xml");
      else if (ext === "yml" || ext === "yaml") setEditorLanguage("yaml");
      else setEditorLanguage("plaintext");

      try {
        const content = await invoke<string>("read_local_file", { path });
        setFileContent(content);
      } catch (e) {
        message.error("读取失败");
        setFileContent("// 读取失败");
      }
    }
  };

  // 3. 保存修改
  const handleSave = async () => {
    if (!currentFilePath) return;
    try {
      await invoke("save_local_file", {
        path: currentFilePath,
        content: fileContent,
      });
      message.success("已保存");
    } catch (e) {
      message.error("保存失败");
    }
  };

  // 4. 一键编译、签名并安装
  const handleBuild = async () => {
    if (!currentDevice) {
      message.warning("请先在侧边栏连接并选中一台设备");
      return;
    }
    setLoading(true);
    setLoadingTip("正在回编译、签名并安装到手机 (请耐心等待)...");

    try {
      const res = await invoke<string>("apk_build_sign_install", {
        projectDir,
        deviceId: currentDevice.id,
      });

      // 🔥 修改点：使用 Modal 弹窗进行强提醒
      Modal.success({
        title: "大功告成！",
        content: (
          <div>
            <p style={{ fontSize: 16, fontWeight: 600, color: "#52c41a" }}>
              APK 已成功安装到设备
            </p>
            <p>设备名称：{currentDevice.name}</p>
            <div
              style={{
                marginTop: 10,
                padding: 8,
                background: "#f5f5f5",
                borderRadius: 4,
                fontSize: 12,
                color: "#666",
              }}
            >
              {res}
            </div>
          </div>
        ),
        okText: "知道了",
      });

      setStep(2); // 完成
    } catch (e: any) {
      // 🔥 修改点：错误也用 Modal 弹窗，方便查看详细日志
      Modal.error({
        title: "操作失败",
        width: 600,
        content: (
          <div style={{ maxHeight: "300px", overflow: "auto" }}>
            <p>在编译或安装过程中发生了错误：</p>
            <pre
              style={{
                fontSize: 12,
                background: "#fff1f0",
                padding: 8,
                borderRadius: 4,
                whiteSpace: "pre-wrap",
              }}
            >
              {e.toString()}
            </pre>
          </div>
        ),
      });
    } finally {
      setLoading(false);
    }
  };

  // --- AI 功能 ---
  const handleAiAction = async (task: AiTaskType) => {
    if (!fileContent) {
      message.warning("编辑器为空");
      return;
    }
    const codeToAnalyze = getSelectedCode();
    if (!codeToAnalyze) return;

    setAiLoading(true);
    setAiModalVisible(true);
    setAiResult("");

    let title = "";
    if (task === "explain") title = "AI 代码解释";
    if (task === "hook") title = "AI 生成 Frida Hook";
    if (task === "convert_java") title = "AI 转译 Java";
    setAiTitle(title);

    try {
      const result = await askAiAssistant(codeToAnalyze, task);
      setAiResult(result);
    } catch (e: any) {
      setAiResult("AI 请求失败: " + e.message);
    } finally {
      setAiLoading(false);
    }
  };

  const aiMenuProps = {
    items: [
      {
        key: "explain",
        label: "解释这段代码",
        icon: <ReadOutlined />,
        onClick: () => handleAiAction("explain"),
      },
      {
        key: "convert",
        label: "转译为 Java (预览)",
        icon: <TranslationOutlined />,
        onClick: () => handleAiAction("convert_java"),
      },
      { type: "divider" },
      {
        key: "hook",
        label: "生成 Frida Hook",
        icon: <BugOutlined />,
        onClick: () => handleAiAction("hook"),
      },
    ] as any,
  };

  return (
    <Layout style={{ height: "100%", background: "#fff" }}>
      {/* 顶部工具栏 */}
      <div
        style={{
          padding: "12px 24px",
          borderBottom: "1px solid #eee",
          background: "#fafafa",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Steps
          current={step}
          size="small"
          style={{ width: 400 }}
          items={[
            { title: "解包 APK" },
            { title: "修改代码" },
            { title: "编译安装" },
          ]}
        />
        <Space>
          <Button
            icon={<FolderOpenOutlined />}
            onClick={handleDecompile}
            disabled={loading}
          >
            {projectDir ? "重新打开" : "打开 APK"}
          </Button>
          <Button
            type="primary"
            icon={<AndroidOutlined />}
            onClick={handleBuild}
            loading={loading}
            disabled={!projectDir || !currentDevice}
          >
            一键编译安装
          </Button>
        </Space>
      </div>

      <Layout>
        <Sider
          width={280}
          theme="light"
          style={{ borderRight: "1px solid #eee", overflow: "auto" }}
        >
          {treeData.length > 0 ? (
            <Tree
              treeData={treeData}
              onSelect={handleSelectNode}
              fieldNames={{ title: "title", key: "key", children: "children" }}
              blockNode
              style={{ padding: 10 }}
              showIcon
              icon={(props) =>
                props.isLeaf ? <FileTextOutlined /> : <FolderOpenOutlined />
              }
            />
          ) : (
            <Empty
              description="请点击右上角打开 APK"
              style={{ marginTop: 100 }}
            />
          )}
        </Sider>

        <Content
          style={{
            position: "relative",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Loading 遮罩 */}
          {loading && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                background: "rgba(255,255,255,0.8)",
                zIndex: 10,
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
              }}
            >
              <Spin size="large" />
              <div style={{ marginTop: 16, fontWeight: 500 }}>{loadingTip}</div>
            </div>
          )}

          {currentFilePath ? (
            <>
              <div
                style={{
                  padding: "8px 16px",
                  background: "#1e1e1e",
                  color: "#ccc",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <span style={{ fontSize: 12 }}>{currentFilePath}</span>
                <Space>
                  <Dropdown menu={aiMenuProps} trigger={["click"]}>
                    <Button
                      size="small"
                      icon={<RobotOutlined />}
                      style={{
                        background: "transparent",
                        color: "#faad14",
                        borderColor: "#faad14",
                      }}
                    >
                      AI 助手
                    </Button>
                  </Dropdown>
                  <Button
                    size="small"
                    type="primary"
                    icon={<SaveOutlined />}
                    onClick={handleSave}
                  >
                    保存
                  </Button>
                </Space>
              </div>
              <div style={{ flex: 1 }}>
                <Editor
                  height="100%"
                  language={editorLanguage}
                  value={fileContent}
                  onChange={(v) => setFileContent(v || "")}
                  onMount={handleEditorDidMount}
                  theme="vs-dark"
                  options={{
                    minimap: { enabled: true },
                    fontSize: 14,
                    wordWrap: "on",
                    scrollBeyondLastLine: false,
                  }}
                />
              </div>
            </>
          ) : (
            <div
              style={{
                height: "100%",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                color: "#999",
              }}
            >
              请在左侧选择 Smali 或 XML 文件进行修改
            </div>
          )}
        </Content>
      </Layout>

      {/* AI 结果弹窗 */}
      <Modal
        title={
          <span>
            <RobotOutlined /> {aiTitle}
          </span>
        }
        open={aiModalVisible}
        onCancel={() => setAiModalVisible(false)}
        footer={null}
        width={800}
      >
        {aiLoading ? (
          <div style={{ textAlign: "center", padding: 40 }}>
            <Spin size="large" tip="AI 正在思考中..." />
          </div>
        ) : (
          <Editor
            height="500px"
            defaultLanguage={aiTitle.includes("Hook") ? "javascript" : "java"}
            value={aiResult}
            theme="vs-dark" // 🔥 修复：弹窗也用深色模式，避免闪烁
            options={{
              readOnly: true,
              minimap: { enabled: false },
              wordWrap: "on",
            }}
          />
        )}
      </Modal>
    </Layout>
  );
};

export default ApkBuilder;
