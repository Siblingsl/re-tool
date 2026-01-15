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
  {
    id: "4",
    name: "动态类加载监控",
    desc: "监控 DexClassLoader/PathClassLoader 动态加载",
    code: `
// 🔥 动态类加载监控 - 用于分析热更新、插件化框架
Java.perform(function () {
    console.log("[ClassLoader Monitor] Starting...");

    // Hook DexClassLoader 构造函数
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("[🔥 DexClassLoader] 加载新 DEX:");
        console.log("    dexPath: " + dexPath);
        console.log("    optimizedDir: " + optimizedDirectory);
        console.log("    libPath: " + librarySearchPath);
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };

    // Hook PathClassLoader 构造函数
    var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, parent) {
        console.log("[🔥 PathClassLoader] 加载路径: " + dexPath);
        return this.$init(dexPath, parent);
    };

    // Hook InMemoryDexClassLoader (Android 8.0+，内存加载)
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buffer, parent) {
            console.log("[🔥 InMemoryDexClassLoader] 内存加载 DEX! 大小: " + buffer.capacity() + " bytes");
            return this.$init(buffer, parent);
        };
    } catch (e) {
        console.log("[Info] InMemoryDexClassLoader 不可用 (Android < 8.0)");
    }

    // Hook ClassLoader.loadClass - 监控所有类加载
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
        // 过滤系统类，只打印业务类
        if (className.indexOf("com.") === 0 || className.indexOf("cn.") === 0 || 
            className.indexOf("net.") === 0 || className.indexOf("org.") === 0) {
            console.log("[ClassLoader] loadClass: " + className);
        }
        return this.loadClass(className);
    };

    // Hook Class.forName - 反射加载类
    var JavaClass = Java.use("java.lang.Class");
    JavaClass.forName.overload('java.lang.String').implementation = function (className) {
        if (className.indexOf("com.") === 0 || className.indexOf("cn.") === 0) {
            console.log("[Class.forName] 反射加载: " + className);
        }
        return this.forName(className);
    };

    console.log("[ClassLoader Monitor] Hooks 已注入!");
});
        `,
  },
  {
    id: "5",
    name: "Dex 文件 Dump",
    desc: "发现动态加载的 Dex 时自动保存到 /sdcard",
    code: `
// 🔥 Dex 文件 Dump - 配合动态类加载监控使用
Java.perform(function () {
    console.log("[Dex Dumper] Starting...");

    var dexCount = 0;

    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        dexCount++;
        console.log("[🔥 Dex Dump] 发现 DEX #" + dexCount + ": " + dexPath);
        
        // 复制 Dex 文件到 /sdcard
        try {
            var File = Java.use("java.io.File");
            var FileInputStream = Java.use("java.io.FileInputStream");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            
            var srcFile = File.$new(dexPath);
            var dstPath = "/sdcard/dumped_dex_" + dexCount + ".dex";
            var dstFile = File.$new(dstPath);
            
            var fis = FileInputStream.$new(srcFile);
            var fos = FileOutputStream.$new(dstFile);
            
            var buffer = Java.array('byte', new Array(4096).fill(0));
            var len;
            while ((len = fis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fis.close();
            fos.close();
            
            console.log("[✅ Dumped] 保存到: " + dstPath);
        } catch (e) {
            console.log("[❌ Dump Failed] " + e);
        }
        
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };

    console.log("[Dex Dumper] Ready!");
});
        `,
  },
  { id: "6", desc: "", name: "自定义 Hook", code: "// 在此编写你的代码" },
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
