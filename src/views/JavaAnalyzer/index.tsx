import React, { useState, useRef, useEffect } from "react";
import {
  Layout,
  Tree,
  Button,
  message,
  Empty,
  Spin,
  Space,
  Input,
  Modal,
  List,
  Tag,
} from "antd";
import {
  FolderOpenOutlined,
  FileTextOutlined,
  CoffeeOutlined,
  SearchOutlined,
  FileOutlined,
  CodeOutlined,
} from "@ant-design/icons";
import Editor, { OnMount } from "@monaco-editor/react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Header } from "antd/es/layout/layout";

const { Sider, Content } = Layout;

interface SearchResult {
  file_path: string;
  line_num: number;
  content: string;
  match_type: "file" | "code";
}

const JavaAnalyzer: React.FC = () => {
  const [projectDir, setProjectDir] = useState("");
  const [treeData, setTreeData] = useState<any[]>([]);
  const [fileContent, setFileContent] = useState("");
  const [currentFilePath, setCurrentFilePath] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingTip, setLoadingTip] = useState("");

  // 🔥 新增：Tree 的受控状态
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>([]);
  const [selectedKeys, setSelectedKeys] = useState<React.Key[]>([]);

  // 搜索相关
  const [searchModalVisible, setSearchModalVisible] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searching, setSearching] = useState(false);

  const editorRef = useRef<any>(null);

  const handleEditorDidMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  // 1. 解包反编译
  const handleDecompile = async () => {
    const file = await open({
      filters: [{ name: "APK", extensions: ["apk"] }],
    });
    if (!file) return;

    setLoading(true);
    setLoadingTip("正在使用 JADX 反编译...");
    setFileContent("");
    setExpandedKeys([]); // 重置树状态

    try {
      const outDir = await invoke<string>("jadx_decompile", { apkPath: file });
      message.success("反编译成功");
      setProjectDir(outDir);
      const nodes = await invoke<any[]>("scan_local_dir", { path: outDir });
      setTreeData(nodes);
      // 默认展开第一层
      if (nodes.length > 0) {
        setExpandedKeys([nodes[0].key]);
      }
    } catch (e: any) {
      message.error("反编译失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  // 🔥 核心辅助函数：根据文件路径，计算所有父级目录路径
  // 输入: /a/b/c/d.java
  // 输出: [/a, /a/b, /a/b/c]
  const getAllParentKeys = (filePath: string, rootPath: string): string[] => {
    const keys: string[] = [];
    // 简单处理：假设路径分隔符是 / 或 \
    // 先统一分隔符
    const normalizedPath = filePath.replace(/\\/g, "/");
    const normalizedRoot = rootPath.replace(/\\/g, "/");

    // 如果文件不在项目根目录下，可能出错，直接返回
    if (!normalizedPath.startsWith(normalizedRoot)) return [];

    // 去掉根路径部分，剩下的就是相对结构
    let current = normalizedPath;
    while (true) {
      const lastSlashIndex = current.lastIndexOf("/");
      if (lastSlashIndex <= normalizedRoot.length) break; // 到了根目录就停

      const parent = current.substring(0, lastSlashIndex);
      if (parent === normalizedRoot) break;

      keys.push(parent);
      current = parent;
    }
    // 如果你在 Windows 上，原本的 key 可能是反斜杠的，这里可能需要做映射
    // 但既然后端 scan_local_dir 返回的 key 是 path.to_string_lossy()，它通常是系统原生路径
    // 这里的逻辑假设树节点的 key 就是完整路径。

    // 上面的 while 逻辑是通用的字符串截取。为了保险，我们再做一次简单的递归截取。
    // 更简单的做法：
    // 路径: C:\Users\xxx\project\sources\com\example\MainActivity.java
    // 父级: C:\Users\xxx\project\sources\com\example
    // 父级: C:\Users\xxx\project\sources\com
    // ...

    // 重新实现一个基于 split 的版本，适配不同系统分隔符
    const sep = filePath.includes("\\") ? "\\" : "/";
    const parts = filePath.split(sep);
    const parents: string[] = [];
    let currentPathBuild = parts[0]; // 盘符或空

    for (let i = 1; i < parts.length - 1; i++) {
      // 不包含文件名本身
      currentPathBuild += sep + parts[i];
      parents.push(currentPathBuild);
    }

    return parents;
  };

  // 2. 读取文件 (支持跳转)
  const loadFile = async (path: string, lineNum: number = 0) => {
    setCurrentFilePath(path);

    // 🔥 核心逻辑：更新树的选中和展开状态
    setSelectedKeys([path]); // 选中当前文件

    // 计算并展开所有父节点
    // 注意：我们需要传入当前的路径，它必须和 Tree 数据里的 key 完全一致
    const parentKeys = getAllParentKeys(path, projectDir);

    // 将新的父节点加入到现有的 expandedKeys 中 (去重)
    setExpandedKeys((prev) => {
      const newSet = new Set([...prev, ...parentKeys]);
      return Array.from(newSet);
    });

    try {
      const content = await invoke<string>("read_local_file", { path });
      setFileContent(content);

      if (lineNum > 0 && editorRef.current) {
        setTimeout(() => {
          editorRef.current.revealLineInCenter(lineNum);
          editorRef.current.setPosition({ lineNumber: lineNum, column: 1 });
          editorRef.current.focus();
        }, 100);
      }
    } catch (e) {
      message.error("读取失败");
    }
  };

  const handleSelectNode = (keys: any, info: any) => {
    if (info.node.isLeaf) {
      loadFile(info.node.key);
    } else {
      // 如果点击的是文件夹，切换展开状态
      const key = info.node.key;
      setExpandedKeys((prev) => {
        if (prev.includes(key)) return prev.filter((k) => k !== key);
        return [...prev, key];
      });
    }
  };

  // 3. 执行搜索
  const handleSearch = async () => {
    if (!searchQuery.trim() || !projectDir) return;
    setSearching(true);
    try {
      const res = await invoke<SearchResult[]>("search_project", {
        projectDir,
        query: searchQuery.trim(),
      });
      setSearchResults(res);
      if (res.length === 0) message.info("未找到相关内容");
    } catch (e: any) {
      message.error("搜索出错: " + e);
    } finally {
      setSearching(false);
    }
  };

  return (
    <Layout style={{ height: "100%", background: "#fff" }}>
      <Header
        className="content-header"
      >
        <Space>
          <Button
            icon={<FolderOpenOutlined />}
            onClick={handleDecompile}
            disabled={loading}
          >
            {projectDir ? "打开新 APK" : "打开 APK (JADX)"}
          </Button>
          <Button
            icon={<SearchOutlined />}
            onClick={() => setSearchModalVisible(true)}
            disabled={!projectDir}
          >
            全局搜索
          </Button>
        </Space>
        <div style={{ color: "#999", fontSize: 12 }}>
          <CoffeeOutlined /> JADX Java 分析模式
        </div>
      </Header>

      <Layout>
        <Sider
          width={280}
          theme="light"
          style={{ borderRight: "1px solid #eee", overflow: "auto" }}
        >
          {treeData.length > 0 ? (
            <Tree
              treeData={treeData}
              // 🔥 绑定受控属性
              expandedKeys={expandedKeys}
              selectedKeys={selectedKeys}
              // 处理展开收起事件，保证用户手动操作也生效
              onExpand={(keys) => setExpandedKeys(keys as string[])}
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
            <Empty description="请先打开 APK" style={{ marginTop: 100 }} />
          )}
        </Sider>

        <Content style={{ position: "relative" }}>
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
            <div
              style={{
                height: "100%",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  padding: "8px 16px",
                  background: "#1e1e1e",
                  color: "#ccc",
                  fontSize: 12,
                }}
              >
                {currentFilePath}
              </div>
              <Editor
                height="100%"
                defaultLanguage="java"
                value={fileContent}
                onMount={handleEditorDidMount}
                theme="vs-dark"
                options={{
                  minimap: { enabled: true },
                  fontSize: 14,
                  readOnly: true,
                }}
              />
            </div>
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
              请在左侧选择文件查看，或点击搜索查找代码
            </div>
          )}
        </Content>
      </Layout>

      {/* 全局搜索弹窗 */}
      <Modal
        title="全局搜索 (Fuzzy Search)"
        open={searchModalVisible}
        onCancel={() => setSearchModalVisible(false)}
        footer={null}
        width={700}
      >
        <Input.Search
          placeholder="输入类名、方法名或字符串..."
          enterButton="搜索"
          size="large"
          loading={searching}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onSearch={handleSearch}
        />

        <div style={{ marginTop: 16, maxHeight: "500px", overflowY: "auto" }}>
          <List
            itemLayout="horizontal"
            dataSource={searchResults}
            renderItem={(item) => (
              <List.Item
                style={{ cursor: "pointer" }}
                className="search-result-item"
                onClick={() => {
                  loadFile(item.file_path, item.line_num); // 🔥 这里会触发自动展开
                  setSearchModalVisible(false);
                }}
              >
                <List.Item.Meta
                  avatar={
                    item.match_type === "file" ? (
                      <FileOutlined style={{ color: "#1890ff" }} />
                    ) : (
                      <CodeOutlined style={{ color: "#fa8c16" }} />
                    )
                  }
                  title={
                    <span style={{ fontFamily: "monospace" }}>
                      {item.file_path.split(/[/\\]/).pop()}
                      {item.match_type === "code" && (
                        <span style={{ color: "#999", marginLeft: 8 }}>
                          :{item.line_num}
                        </span>
                      )}
                    </span>
                  }
                  description={
                    <div
                      style={{
                        fontFamily: "monospace",
                        fontSize: 12,
                        color: "#666",
                        background: "#f5f5f5",
                        padding: "2px 6px",
                        borderRadius: 4,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {item.content.trim()}
                    </div>
                  }
                />
              </List.Item>
            )}
          />
          {searchResults.length === 0 && !searching && searchQuery && (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="无搜索结果"
            />
          )}
        </div>
      </Modal>
    </Layout>
  );
};

export default JavaAnalyzer;
