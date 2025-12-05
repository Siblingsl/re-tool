// 在联合类型最后加上 'show'
export type ViewMode =
  | "device"
  | "algo-converter"
  | "so-analyzer"
  | "asm-lab"
  | "install"
  | "show"
  | "script-lab"
  | "file-manager"
  | "apk-builder"
  | "java-analyzer"
  | "packer-lab";

export interface Device {
  id: string;
  name: string;
  os: string;
  type_: string;
  type: "android" | "ios";
  status: "online" | "offline";
  battery: number;
}

export interface AppInfo {
  id: string;
  name: string;
  pkg: string;
  ver: string;
  icon: string;
}

// 应用详细信息接口，用于展示应用详细信息
export interface AppDetail {
  versionName: string;
  versionCode: string;
  minSdk: string;
  targetSdk: string;
  dataDir: string;
  sourceDir: string; // APK 路径
  uid: string;
  firstInstallTime: string;
  lastUpdateTime: string;
}

export interface FileItem {
  name: string;
  is_dir: boolean;
  size: string;
  permissions: string;
  date: string;
}
