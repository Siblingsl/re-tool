import React, { useState } from "react";
import {
  Button,
  Descriptions,
  Tag,
  Slider,
  message,
  Card,
  Switch,
  Radio,
  Tooltip,
  Divider,
} from "antd";
import {
  AndroidFilled,
  AppleFilled,
  PlayCircleFilled,
  ThunderboltOutlined,
  PictureOutlined,
  QuestionCircleOutlined,
} from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { Device } from "../../types";

interface DeviceScreenProps {
  device: Device;
}

const DeviceScreen: React.FC<DeviceScreenProps> = ({ device }) => {
  const [loading, setLoading] = useState(false);

  // 配置状态
  const [maxSize, setMaxSize] = useState(1024);
  const [bitRate, setBitRate] = useState(4); // 云手机建议默认 4M
  const [buffer, setBuffer] = useState(50); // 缓冲默认 50ms
  const [showTouches, setShowTouches] = useState(false);
  const [stayAwake, setStayAwake] = useState(true);

  // 预设模式切换
  const handleModeChange = (e: any) => {
    const mode = e.target.value;
    if (mode === "performance") {
      setMaxSize(800);
      setBitRate(2);
      setBuffer(100); // 增加缓冲以抗抖动
    } else if (mode === "balance") {
      setMaxSize(1024);
      setBitRate(4);
      setBuffer(50);
    } else if (mode === "quality") {
      setMaxSize(1440);
      setBitRate(8);
      setBuffer(0);
    }
  };

  const handleStartMirror = async () => {
    if (device.type === "ios") {
      message.warning("iOS 暂不支持");
      return;
    }

    setLoading(true);
    try {
      // 传递更多参数给 Rust
      await invoke("start_scrcpy", {
        serial: device.id,
        maxSize: maxSize,
        bitRate: bitRate,
        buffer: buffer, // 新增：缓冲
        showTouches: showTouches, // 新增：显示触摸
        stayAwake: stayAwake, // 新增：保持唤醒
      });
      message.success("已发送启动指令");
    } catch (error: any) {
      message.error(`启动失败: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: "100%", overflowY: "auto", paddingBottom: 20 }}>
      <div className="content-header">
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>设备投屏控制台</span>
          <Tag color={device.status === "online" ? "success" : "default"}>
            {device.status === "online" ? "在线" : "离线"}
          </Tag>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          marginTop: 24,
        }}
      >
        <Card
          style={{ width: 500, boxShadow: "0 4px 12px rgba(0,0,0,0.05)" }}
          title={
            <div style={{ textAlign: "center",paddingTop: 6  }}>
              {device.type === "android" ? (
                <AndroidFilled style={{ fontSize: 32, color: "#3ddc84" }} />
              ) : (
                <AppleFilled style={{ fontSize: 32, color: "#000" }} />
              )}
              <div style={{ marginTop: 8 }}>{device.name}</div>
              <div
                style={{ fontSize: 12, color: "#999", fontWeight: "normal" }}
              >
                {device.id}
              </div>
            </div>
          }
        >
          {/* 1. 快速模式选择 */}
          <div style={{ marginBottom: 24, textAlign: "center" }}>
            <Radio.Group
              defaultValue="balance"
              onChange={handleModeChange}
              buttonStyle="solid"
            >
              <Radio.Button value="performance">
                <ThunderboltOutlined /> 流畅(云手机)
              </Radio.Button>
              <Radio.Button value="balance">均衡模式</Radio.Button>
              <Radio.Button value="quality">
                <PictureOutlined /> 画质优先
              </Radio.Button>
            </Radio.Group>
          </div>

          <Descriptions
            column={1}
            bordered
            size="small"
            labelStyle={{ width: 120 }}
          >
            {/* 分辨率 */}
            <Descriptions.Item label="分辨率限制">
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <Slider
                  min={640}
                  max={1920}
                  step={128}
                  value={maxSize}
                  onChange={setMaxSize}
                  style={{ flex: 1 }}
                />
                <span style={{ width: 60, textAlign: "right" }}>
                  {maxSize} P
                </span>
              </div>
            </Descriptions.Item>

            {/* 比特率 */}
            <Descriptions.Item label="比特率">
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <Slider
                  min={1}
                  max={16}
                  value={bitRate}
                  onChange={setBitRate}
                  style={{ flex: 1 }}
                />
                <span style={{ width: 60, textAlign: "right" }}>
                  {bitRate} Mbps
                </span>
              </div>
            </Descriptions.Item>

            {/* 缓冲时间 - 核心优化 */}
            <Descriptions.Item
              label={
                <span>
                  网络缓冲{" "}
                  <Tooltip title="云手机网络不稳定时，调大此值(50-100ms)可减少卡顿，但会增加延迟">
                    <QuestionCircleOutlined />
                  </Tooltip>
                </span>
              }
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <Slider
                  min={0}
                  max={200}
                  step={10}
                  value={buffer}
                  onChange={setBuffer}
                  style={{ flex: 1 }}
                  trackStyle={{
                    backgroundColor: buffer > 100 ? "#faad14" : "#1677ff",
                  }}
                />
                <span style={{ width: 60, textAlign: "right" }}>
                  {buffer} ms
                </span>
              </div>
            </Descriptions.Item>
          </Descriptions>

          <Divider style={{ margin: "16px 0" }} />

          {/* 开关选项 */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-around",
              marginBottom: 24,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span>显示触摸点</span>
              <Switch checked={showTouches} onChange={setShowTouches} />
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span>保持常亮</span>
              <Switch checked={stayAwake} onChange={setStayAwake} />
            </div>
          </div>

          <Button
            type="primary"
            size="large"
            block
            icon={<PlayCircleFilled />}
            style={{ height: 48, fontSize: 16 }}
            onClick={handleStartMirror}
            loading={loading}
          >
            启动 Scrcpy 窗口
          </Button>

          <div
            style={{
              marginTop: 12,
              fontSize: 12,
              color: "#999",
              textAlign: "center",
            }}
          >
            * 将启动独立的 Scrcpy 窗口，支持原生键鼠操作
          </div>
        </Card>
      </div>
    </div>
  );
};

export default DeviceScreen;
