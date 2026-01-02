import React, { useState, useEffect } from "react";
import { Empty, Button, Spin, message } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

import Sidebar from "./components/Sidebar";
import DeviceManager from "./views/DeviceManager";
import CodeConverter from "./views/CodeConverter";
import DeviceScreen from "./views/DeviceScreen";
import { getConnectedDevices } from "./services/deviceService";

import { ViewMode, Device } from "./types";
import ScriptLab from "./views/ScriptLab";
import FileExplorer from "./views/FileExplorer";
import ApkBuilder from "./views/ApkBuilder";
import JavaAnalyzer from "./views/JavaAnalyzer";
import NetworkSniffer from "./views/NetworkSniffer";
import WebLab from "./views/WebLab";
import AiWorkbenchPage from "./views/AiChatPage"; // 确保引用的是工作台组件

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

  const [scripts, setScripts] = useState<ScriptItem[]>(() => {
    const saved = localStorage.getItem("my_scripts");
    return saved ? JSON.parse(saved) : DEFAULT_SCRIPTS;
  });

  const handleSaveScript = (newScript: ScriptItem) => {
    const newList = scripts.map((s) => (s.id === newScript.id ? newScript : s));
    setScripts(newList);
    localStorage.setItem("my_scripts", JSON.stringify(newList));
  };

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

  const handleRenameDevice = (id: string, newName: string) => {
    const newAliases = { ...deviceAliases, [id]: newName };
    setDeviceAliases(newAliases);
    localStorage.setItem("device_aliases", JSON.stringify(newAliases));
  };

  const refreshDevices = async () => {
    setLoadingDevices(true);
    try {
      const realDevices = await getConnectedDevices();
      const finalDevices = realDevices.length > 0 ? realDevices : [];
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
    refreshDevices();
    const unlistenPromise = listen("device-changed", () => {
      console.log("检测到设备变动，自动刷新...");
      refreshDevices();
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const handleNavigate = (view: ViewMode, contextData?: string) => {
    setCurrentView(view);
    if (contextData) setConverterContext(contextData);
  };

  const rawDevice =
    devices.find((d) => d.id === selectedDeviceId) || devices[0];
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
        deviceAliases={deviceAliases}
        onRenameDevice={handleRenameDevice}
      />

      <div className="main-content">
        {currentView === "device" &&
          (currentDevice ? (
            <DeviceManager
              device={currentDevice}
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
          <NetworkSniffer devices={devices} deviceAliases={deviceAliases} />
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
            scripts={scripts}
            onSave={handleSaveScript}
            currentDeviceId={selectedDeviceId}
          />
        )}

        {currentView === "apk-builder" && (
          <ApkBuilder currentDevice={currentDevice} />
        )}

        {currentView === "java-analyzer" && <JavaAnalyzer />}

        {currentView === "show" && currentDevice && (
          <DeviceScreen device={currentDevice} />
        )}
        {currentView === "algo-converter" && (
          <CodeConverter initialCode={converterContext} />
        )}
        {currentView === "web-lab" && <WebLab />}
        {currentView === "asm-lab" && (
          <Empty description="ARM 汇编实验室" style={{ marginTop: 100 }} />
        )}
        {currentView.startsWith("ai-chat") && (
          <AiWorkbenchPage sessionId={currentView.replace("ai-chat-", "")} />
        )}
      </div>
    </div>
  );
};

export default App;
