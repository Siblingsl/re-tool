// 在联合类型最后加上 'show'
export type ViewMode =
  | "device"
  | "algo-converter"
  | "asm-lab"
  | "install"
  | "show"
  | "script-lab"
  | "file-manager"
  | "apk-builder"
  | "java-analyzer"
  | "packer-lab"
  | "network-sniffer"
  | "unidbg-runner";

export interface AiRequest {
  prompt: string;
  task_type: string;
  context_code?: string;
  error_log?: string;
}

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

// 🔥 新增：网络请求结构
export interface NetworkRequest {
  id: string; // 唯一 ID (UUID)
  method: string; // GET, POST...
  url: string; // 完整 URL
  host: string; // 域名
  path: string; // 路径
  scheme: string; // http/https
  status?: number; // 响应状态码 (200, 404...)
  startTime: number; // 开始时间戳
  duration?: number; // 耗时 (ms)
  requestHeaders: Record<string, string>;
  requestBody?: string;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  contentType?: string; // application/json...
}
