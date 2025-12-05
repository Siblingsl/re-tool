import React, { useState } from "react";
import {
  Button,
  Card,
  Steps,
  message,
  Descriptions,
  Alert,
  Modal,
  Space,
  Tag,
} from "antd";
import {
  SafetyCertificateOutlined,
  CloudDownloadOutlined,
  FileSearchOutlined,
  RocketOutlined,
  RedoOutlined,
  MobileOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Device } from "../../types";

// --- 内置的通用脱壳脚本 ---
const DUMP_SCRIPT = `
rpc.exports = {
    dump: function() {
        var count = 0;
        var result = [];
        Process.enumerateRanges('r--').forEach(function (range) {
            try {
                Memory.scanSync(range.base, range.size, "64 65 78 0a 30 33 35 00").forEach(function (match) {
                    var dex_base = match.address;
                    var dex_size = dex_base.add(0x20).readInt();
                    if (dex_size > 0 && dex_size < 100 * 1024 * 1024) {
                        var path = "/data/data/" + Process.getCurrentPackage() + "/files/dump_dex/";
                        var filename = path + "dump_" + count + ".dex";
                        var mkdir = new NativeFunction(Module.findExportByName("libc.so", "mkdir"), 'int', ['pointer', 'int']);
                        var fopen = new NativeFunction(Module.findExportByName("libc.so", "fopen"), 'pointer', ['pointer', 'pointer']);
                        var fwrite = new NativeFunction(Module.findExportByName("libc.so", "fwrite"), 'int', ['pointer', 'int', 'int', 'pointer']);
                        var fclose = new NativeFunction(Module.findExportByName("libc.so", "fclose"), 'int', ['pointer']);
                        
                        mkdir(Memory.allocUtf8String(path), 0x1ed);
                        var fp = fopen(Memory.allocUtf8String(filename), Memory.allocUtf8String("wb"));
                        if (fp != 0) {
                            var buffer = dex_base.readByteArray(dex_size);
                            var buf_ptr = Memory.alloc(dex_size);
                            buf_ptr.writeByteArray(buffer);
                            fwrite(buf_ptr, dex_size, 1, fp);
                            fclose(fp);
                            console.log("[Dump] Saved to " + filename);
                            result.push(filename);
                            count++;
                        }
                    }
                });
            } catch (e) {}
        });
        return result;
    }
};
`;

interface PackerLabProps {
  currentDevice?: Device;
}

const PackerLab: React.FC<PackerLabProps> = ({ currentDevice }) => {
  const [step, setStep] = useState(0);
  const [packerInfo, setPackerInfo] = useState<string>("");
  const [loading, setLoading] = useState(false);

  // 1. 查壳
  const handleDetect = async () => {
    const file = await open({
      filters: [{ name: "APK", extensions: ["apk"] }],
    });
    if (!file) return;

    setLoading(true);
    setPackerInfo("");
    try {
      const info = await invoke<string>("detect_packer", { apkPath: file });
      setPackerInfo(info);
      message.success("分析完成");
      if (info) setStep(1); // 自动下一步
    } catch (e: any) {
      message.error("分析失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  // 2. 注入脱壳脚本
  const handleInjectDump = async () => {
    if (!currentDevice) {
      message.error("请先连接并选中一台设备");
      return;
    }

    setLoading(true);
    try {
      // 获取前台应用包名
      const pkg = await invoke<string>("get_foreground_app", {
        deviceId: currentDevice.id,
      });
      message.loading(`正在注入脱壳脚本到 ${pkg}...`, 2);

      // 注入脚本
      await invoke("run_frida_script", {
        deviceId: currentDevice.id,
        packageName: pkg,
        scriptContent: DUMP_SCRIPT + "\n\n// Auto-run\nrpc.exports.dump();",
      });

      message.success("注入成功！脚本正在后台 Dump Dex...");
      setStep(2);
    } catch (e: any) {
      message.error("注入失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  // 3. 导出 Dex 并整理
  const handleExportDex = async () => {
    if (!currentDevice) return;

    setLoading(true);
    try {
      const pkg = await invoke<string>("get_foreground_app", {
        deviceId: currentDevice.id,
      });

      const savePath = await invoke<string>("pull_and_organize_dex", {
        deviceId: currentDevice.id,
        pkg: pkg,
      });

      Modal.success({
        title: "脱壳成功！",
        content: (
          <div>
            <p>Dex 文件已整理并保存到：</p>
            <code
              style={{
                fontSize: 12,
                wordBreak: "break-all",
                display: "block",
                background: "#f5f5f5",
                padding: 8,
                borderRadius: 4,
              }}
            >
              {savePath}
            </code>
            <p style={{ marginTop: 10, color: "#666" }}>
              包含 classes.dex, classes2.dex ...
            </p>
          </div>
        ),
        okText: "打开文件夹",
        onOk: () => invoke("open_file_explorer", { path: savePath }),
      });
    } catch (e: any) {
      message.error("导出失败: " + e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        height: "100%",
        background: "#f0f2f5", // 浅灰背景区分
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* 顶部 Header */}
      <div className="content-header">
        <div>
          <h2
            style={{
              margin: 0,
              fontSize: 18,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <SafetyCertificateOutlined style={{ color: "#1890ff" }} /> 壳工坊
          </h2>
        </div>
      </div>

      {/* 主要内容区 */}
      <div
        style={{
          flex: 1,
          padding: 24,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <span style={{ marginBottom: 40, fontSize: 22, fontWeight: 700 }}>
          一键检测加固类型，并利用 Frida 动态脱壳
        </span>
        {/* 步骤条：响应式宽度 */}
        <Steps
          current={step}
          items={[
            { title: "查壳", description: "APK 特征分析" },
            { title: "动态脱壳", description: "Frida 内存 Dump" },
            { title: "导出整理", description: "拉取 Dex 文件" },
          ]}
          style={{ maxWidth: 800, marginBottom: 40, width: "100%" }}
        />

        {/* 卡片区域：宽度自适应但有上限 */}
        <div style={{ width: "100%", maxWidth: 600 }}>
          {/* 步骤 1: 查壳 */}
          {step === 0 && (
            <Card title="第一步：静态分析" bordered={false} hoverable>
              <Space
                direction="vertical"
                size="large"
                style={{ width: "100%" }}
              >
                <div
                  style={{
                    textAlign: "center",
                    padding: "20px 0",
                    color: "#666",
                  }}
                >
                  请选择电脑上的 APK 文件进行特征扫描
                </div>
                <Button
                  type="primary"
                  icon={<FileSearchOutlined />}
                  onClick={handleDetect}
                  loading={loading}
                  block
                  size="large"
                  style={{ height: 48 }}
                >
                  选择 APK 文件
                </Button>
              </Space>
            </Card>
          )}

          {/* 步骤 1.5: 查壳结果 (独立显示) */}
          {packerInfo && step === 0 && (
            <Alert
              message="检测结果"
              description={
                <div style={{ marginTop: 8 }}>
                  <div
                    style={{
                      fontSize: 16,
                      fontWeight: "bold",
                      color: "#333",
                      marginBottom: 12,
                    }}
                  >
                    {packerInfo}
                  </div>
                  <Button type="primary" ghost onClick={() => setStep(1)}>
                    下一步：开始脱壳
                  </Button>
                </div>
              }
              type={packerInfo.includes("未发现") ? "info" : "warning"}
              showIcon
              style={{ marginTop: 24 }}
            />
          )}

          {/* 步骤 2: 脱壳 */}
          {step === 1 && (
            <Card title="第二步：动态脱壳" bordered={false} hoverable>
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="当前设备">
                  {currentDevice?.name || (
                    <span style={{ color: "red" }}>
                      未选择 (请在左侧栏选择设备)
                    </span>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="目标应用">
                  <span style={{ color: "#1890ff" }}>
                    请确保 APP 正在手机前台运行
                  </span>
                </Descriptions.Item>
              </Descriptions>

              <div style={{ marginTop: 24 }}>
                <Button
                  type="primary"
                  danger
                  icon={<RocketOutlined />}
                  onClick={handleInjectDump}
                  loading={loading}
                  disabled={!currentDevice}
                  block
                  size="large"
                  style={{ height: 48 }}
                >
                  一键注入脱壳脚本
                </Button>
                <div
                  style={{
                    marginTop: 12,
                    color: "#999",
                    fontSize: 12,
                    lineHeight: 1.5,
                  }}
                >
                  * 原理：利用 Frida 搜索内存中的 Dex Header (dex.035) 并 Dump
                  到手机临时目录。
                  <br />* 适用于 360、腾讯、百度等大部分一代/二代壳。
                </div>
              </div>

              <Button
                type="link"
                icon={<RedoOutlined />}
                onClick={() => setStep(0)}
                style={{ marginTop: 12, padding: 0 }}
              >
                重新查壳
              </Button>
            </Card>
          )}

          {/* 步骤 3: 导出 */}
          {step === 2 && (
            <Card title="第三步：导出 Dex" bordered={false} hoverable>
              <Alert
                message="Dump 成功"
                description="脱壳脚本已执行，Dex 文件已生成在手机内存中。"
                type="success"
                showIcon
                style={{ marginBottom: 24 }}
              />

              <Button
                type="primary"
                icon={<CloudDownloadOutlined />}
                onClick={handleExportDex}
                loading={loading}
                block
                size="large"
                style={{ height: 48 }}
              >
                拉取并整理 Dex 文件
              </Button>

              <div style={{ textAlign: "center", marginTop: 24 }}>
                <Button onClick={() => setStep(0)}>完成并返回</Button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default PackerLab;
