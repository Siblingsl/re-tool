import { invoke } from "@tauri-apps/api/core"; // 确认这里是 core (Tauri v2)
import { Device, AppInfo } from "../types";

interface RustDevice {
  id: string;
  name: string;
  status: string;
  os: string;
  type_: string;
}

interface RustApp {
  id: string;
  name: string;
  pkg: string;
  ver: string;
  icon: string;
}

// 1. 获取所有设备
export const getConnectedDevices = async (): Promise<Device[]> => {
  try {
    // 调用新的后端接口 get_all_devices
    const devices = await invoke<RustDevice[]>("get_all_devices");

    return devices.map((d) => ({
      id: d.id,
      name: d.name,
      os: d.os,
      type: d.type_ as "android" | "ios",
      status: d.status as "online" | "offline",
      battery: 100,
    }));
  } catch (error) {
    console.error("Failed to fetch devices:", error);
    return [];
  }
};

// 2. 获取 App 列表 (新增 deviceType 参数)
export const getDeviceApps = async (
  deviceId: string,
  deviceType: "android" | "ios"
): Promise<AppInfo[]> => {
  try {
    // 传给后端 device_type，方便后端判断用 adb 还是 tidevice
    const apps = await invoke<RustApp[]>("get_device_apps", {
      deviceId,
      deviceType,
    });

    return apps.map((app) => ({
      id: app.id,
      name: app.name,
      pkg: app.pkg,
      ver: app.ver,
      icon: deviceType === "android" ? getRandomColor() : "#000000", // iOS 用黑色区分
    }));
  } catch (error) {
    console.error(`Failed to fetch apps for ${deviceId}:`, error);
    return [];
  }
};

const getRandomColor = () => {
  const colors = [
    "#f56a00",
    "#7265e6",
    "#ffbf00",
    "#00a2ae",
    "#3ddc84",
    "#1890ff",
  ];
  return colors[Math.floor(Math.random() * colors.length)];
};
