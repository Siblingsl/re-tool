import React, { useState, useEffect } from "react";
import { Empty, Button, Spin, message } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event"; // 🔥 引入 event
import "./App.css";

import Sidebar from "./components/Sidebar";
import DeviceManager from "./views/DeviceManager";
import CodeConverter from "./views/CodeConverter";
import DeviceScreen from "./views/DeviceScreen"; // 投屏组件
import { getConnectedDevices } from "./services/deviceService";

import { ViewMode, Device } from "./types";
import ScriptLab from "./views/ScriptLab";
import FileExplorer from "./views/FileExplorer";
import ApkBuilder from "./views/ApkBuilder";
import JavaAnalyzer from "./views/JavaAnalyzer";
import PackerLab from "./views/PackerLab";
import NetworkSniffer from "./views/NetworkSniffer";
import WebLab from "./views/WebLab";

// 定义脚本接口
export interface ScriptItem {
  id: string;
  desc: string;
  name: string;
  code: string;
}

// 默认脚本
const DEFAULT_SCRIPTS: ScriptItem[] = [
  {
    id: "1",
    name: "通用 SSL Bypass",
    desc: "绕过大多数 App 的证书校验",
    code: `
            Java.perform(function() {
                var array_list = Java.use("java.util.ArrayList");
                var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                    console.log('Bypassing SSL Pinning');
                    return array_list.$new();
                }
            }, 0);
        `,
  },
  {
    id: "2",
    name: "打印堆栈 (Stack Trace)",
    desc: "在关键位置调用，查看调用链",
    code: `
            function printStack() {
                var Exception = Java.use("java.lang.Exception");
                var ins = Exception.$new("Exception");
                var straces = ins.getStackTrace();
                if (straces != undefined && straces != null) {
                    var stacktrace = straces.toString();
                    var replaceStr = stacktrace.replace(/,/g, "\\n");
                    console.log("=============================" + replaceStr);
                }
            }
        `,
  },
  {
    id: "3",
    name: "Hook OkHttp3",
    desc: "打印网络请求 URL 和 Header",
    code: `
            // 这是一个简化的示例，实际脚本通常很长
            Java.perform(function () {
                // 你的 Hook 代码...
                console.log("Hooking OkHttp3...");
            });
        `,
  },
  { id: "4", desc: "", name: "自定义 Hook", code: "// 在此编写你的代码" },
];

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewMode>("device");
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>("");
  const [loadingDevices, setLoadingDevices] = useState(false);
  const [converterContext, setConverterContext] = useState("");

  // 🔥 新增：全局脚本状态
  const [scripts, setScripts] = useState<ScriptItem[]>(() => {
    const saved = localStorage.getItem("my_scripts");
    return saved ? JSON.parse(saved) : DEFAULT_SCRIPTS;
  });

  // 保存脚本的方法
  const handleSaveScript = (newScript: ScriptItem) => {
    const newList = scripts.map((s) => (s.id === newScript.id ? newScript : s));
    // 如果是新的，就 push (这里简化处理，假设只修改)
    setScripts(newList);
    localStorage.setItem("my_scripts", JSON.stringify(newList));
  };

  // 🔥 1. 新增：在 App 层级管理别名 (从 Sidebar 搬过来的逻辑)
  const [deviceAliases, setDeviceAliases] = useState<Record<string, string>>(
    () => {
      try {
        const saved = localStorage.getItem("device_aliases");
        return saved ? JSON.parse(saved) : {};
      } catch (e) {
        return {};
      }
    }
  );

  // 🔥 2. 新增：更新别名的函数 (传给 Sidebar 用)
  const handleRenameDevice = (id: string, newName: string) => {
    const newAliases = { ...deviceAliases, [id]: newName };
    setDeviceAliases(newAliases);
    localStorage.setItem("device_aliases", JSON.stringify(newAliases));
  };

  const refreshDevices = async () => {
    setLoadingDevices(true);
    try {
      const realDevices = await getConnectedDevices();
      // 如果获取失败或是空，回退到 Mock 数据方便调试 (可选)
      const finalDevices = realDevices.length > 0 ? realDevices : []; // 或者 MOCK_DEVICES
      setDevices(finalDevices);

      if (finalDevices.length > 0) {
        if (
          !selectedDeviceId ||
          !finalDevices.find((d) => d.id === selectedDeviceId)
        ) {
          setSelectedDeviceId(finalDevices[0].id);
        }
      }
    } catch (e) {
      message.error("获取设备失败");
    } finally {
      setLoadingDevices(false);
    }
  };

  useEffect(() => {
    // 1. 初次加载
    refreshDevices();

    // 2. 🔥 监听后端发来的 "设备变动" 事件
    const unlistenPromise = listen("device-changed", () => {
      console.log("检测到设备变动，自动刷新...");
      refreshDevices(); // 自动调用刷新
    });

    // 3. 清理监听器
    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const handleNavigate = (view: ViewMode, contextData?: string) => {
    setCurrentView(view);
    if (contextData) setConverterContext(contextData);
  };

  // --- 🔥 关键逻辑：计算当前选中的设备，并应用别名 ---
  const rawDevice =
    devices.find((d) => d.id === selectedDeviceId) || devices[0];
  // 如果有别名，覆盖原始 name，这样右侧所有组件都会显示新名字！
  const currentDevice = rawDevice
    ? {
        ...rawDevice,
        name: deviceAliases[rawDevice.id] || rawDevice.name,
      }
    : undefined;

  return (
    <div className="layout-container">
      <Sidebar
        currentView={currentView}
        onViewChange={setCurrentView}
        devices={devices}
        selectedDeviceId={selectedDeviceId}
        onDeviceSelect={setSelectedDeviceId}
        onRefresh={refreshDevices}
        // 🔥 传下去：别名数据和修改方法
        deviceAliases={deviceAliases}
        onRenameDevice={handleRenameDevice}
      />

      <div className="main-content">
        {currentView === "device" &&
          (currentDevice ? (
            <DeviceManager
              device={currentDevice} // 这里的 device.name 已经是别名了
              onNavigate={handleNavigate}
              scripts={scripts}
            />
          ) : (
            <div
              style={{
                height: "100%",
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
              }}
            >
              {loadingDevices ? (
                <Spin size="large" tip="扫描中..." />
              ) : (
                <>
                  <Empty description="未检测到设备" />
                  <Button
                    icon={<ReloadOutlined />}
                    onClick={refreshDevices}
                    style={{ marginTop: 16 }}
                  >
                    刷新
                  </Button>
                </>
              )}
            </div>
          ))}
        {currentView === "network-sniffer" && (
          <NetworkSniffer devices={devices} deviceAliases={deviceAliases} /> // ✅ 把设备列表传进去
        )}
        {currentView === "file-manager" && currentDevice && (
          <FileExplorer
            deviceId={currentDevice.id}
            initialPath="/sdcard"
            mode="full"
          />
        )}
        {currentView === "script-lab" && (
          <ScriptLab
            scripts={scripts} // 🔥 传给脚本工坊
            onSave={handleSaveScript} // 🔥 允许修改
            currentDeviceId={selectedDeviceId}
          />
        )}

        {currentView === "apk-builder" && (
          <ApkBuilder currentDevice={currentDevice} />
        )}

        {currentView === "java-analyzer" && <JavaAnalyzer />}

        {currentView === "packer-lab" && (
          <PackerLab currentDevice={currentDevice} />
        )}

        {currentView === "show" && currentDevice && (
          <DeviceScreen device={currentDevice} /> // 投屏页的标题也会自动变
        )}
        {currentView === "algo-converter" && (
          <CodeConverter initialCode={converterContext} />
        )}
        {currentView === "web-lab" && <WebLab />}
        {currentView === "asm-lab" && (
          <Empty description="ARM 汇编实验室" style={{ marginTop: 100 }} />
        )}
      </div>
    </div>
  );
};

export default App;
