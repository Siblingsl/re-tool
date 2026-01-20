import React, { useState, useEffect } from "react";
import { Input, Tag, Avatar, Spin, Button, message, Switch, Badge } from "antd"; // 引入 Spin, Switch, Badge
import {
  SearchOutlined,
  AppstoreOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { Device, AppInfo, ViewMode } from "../../types";
import AppDrawer from "./AppDrawer";
import { getDeviceApps, getRunningApps } from "../../services/deviceService"; // 引入真实 App 获取服务

interface DeviceManagerProps {
  device: Device;
  scripts: any[];
  onNavigate: (view: ViewMode, contextData?: string) => void;
}

const DeviceManager: React.FC<DeviceManagerProps> = ({
  device,
  scripts,
  onNavigate,
}) => {
  const [searchText, setSearchText] = useState("");
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedApp, setSelectedApp] = useState<AppInfo | null>(null);

  // 真实 App 数据状态
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [runningPkgs, setRunningPkgs] = useState<string[]>([]); // 🔥 运行中的应用
  const [showOnlyRunning, setShowOnlyRunning] = useState(false); // 🔥 筛选开关
  const [loading, setLoading] = useState(false);

  // --- 加载 App 列表 ---
  const fetchApps = async () => {
    // 修改判断条件，支持 iOS 在线
    if (!device || device.status === "offline") return;

    setLoading(true);
    try {
      // 关键修改：传入 device.type
      const [realApps, running] = await Promise.all([
        getDeviceApps(device.id, device.type),
        device.type === "android" ? getRunningApps(device.id) : Promise.resolve([]),
      ]);
      setApps(realApps);
      setRunningPkgs(running);
    } catch (e) {
      message.error("获取应用列表失败");
    } finally {
      setLoading(false);
    }
  };

  // 当设备 ID 变化时，重新获取 App
  useEffect(() => {
    fetchApps();
  }, [device.id]);

  const filteredApps = apps.filter(
    (app) =>
      (app.name.toLowerCase().includes(searchText.toLowerCase()) ||
        app.pkg.toLowerCase().includes(searchText.toLowerCase())) &&
      (showOnlyRunning ? runningPkgs.includes(app.pkg) : true)
  );

  const handleAppClick = (app: AppInfo) => {
    setSelectedApp(app);
    setDrawerVisible(true);
  };

  return (
    <>
      <div className="content-header">
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>{device.name}</span>
          <Tag color={device.status === "online" ? "success" : "error"}>
            {device.status === "online" ? "在线" : "离线"}
          </Tag>
          <span style={{ fontSize: 12, color: "#888" }}>
            ({apps.length} 个应用)
          </span>
          {/* 🔥 筛选开关区域 */}

        </div>
        <div style={{ display: "flex", gap: 10 }}>
          {device.type === 'android' && (
            <div style={{ marginLeft: 10, display: 'flex', alignItems: 'center' }}>
              <Switch
                checked={showOnlyRunning}
                onChange={setShowOnlyRunning}
                checkedChildren="运行中"
                unCheckedChildren="全部应用"
              />
            </div>
          )}
          <Input
            prefix={<SearchOutlined style={{ color: "#94a3b8" }} />}
            placeholder="搜索包名..."
            style={{ width: 200, borderRadius: 8 }}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            allowClear
          />
          <Button
            icon={<ReloadOutlined />}
            onClick={fetchApps}
            loading={loading}
          />
        </div>


      </div>

      <div className="scroll-container">
        {loading ? (
          <div style={{ textAlign: "center", marginTop: 50 }}>
            <Spin size="large" tip="正在通过 ADB 读取应用列表..." />
          </div>
        ) : (
          <div className="app-grid">
            {filteredApps.map((app) => {
              const isRunning = runningPkgs.includes(app.pkg);
              return (
                <div
                  key={app.id}
                  className="app-card"
                  onClick={() => handleAppClick(app)}
                  style={isRunning ? { border: '1px solid #52c41a', background: '#f6ffed' } : {}}
                >
                  {/* 🔥 运行状态小点 */}
                  {isRunning && (
                    <div style={{ position: 'absolute', top: 5, right: 5 }}>
                      <Badge status="processing" color="#52c41a" />
                    </div>
                  )}

                  <Avatar
                    shape="square"
                    size={48}
                    style={{ backgroundColor: app.icon }}
                    icon={<AppstoreOutlined />}
                  />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    {/* 🔥 修改：第一行展示应用名称 (加粗，字号大一点) */}
                    <div
                      style={{
                        fontWeight: 600,
                        fontSize: 15,
                        color: "#1f2937",
                        marginBottom: 2, // 加一点间距
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={app.name} // 鼠标悬停显示全名
                    >
                      {app.name}
                    </div>

                    {/* 🔥 修改：第二行展示包名 (灰色，等宽字体更专业) */}
                    <div
                      style={{
                        fontSize: 12,
                        color: "#9ca3af",
                        fontFamily: "Menlo, Monaco, 'Courier New', monospace", // 适合显示包名
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={app.pkg}
                    >
                      {app.pkg}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <AppDrawer
        visible={drawerVisible}
        app={selectedApp}
        device={device} // 🔥 新增：把当前 device 传进去
        scripts={scripts}
        onClose={() => setDrawerVisible(false)}
        onNavigate={onNavigate}
      />
    </>
  );
};

export default DeviceManager;
