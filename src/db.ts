import Dexie, { Table } from "dexie";

// 任务步骤结构
export interface TaskStep {
  id: string;
  title: string;
  description?: string;
  status: "wait" | "process" | "finish" | "error";
}

// 定义消息结构
export interface ChatMessage {
  id?: number;
  sessionId: string;
  role: "user" | "ai";
  content: string;
  reasoning?: string; // ✅ 新增：存储深度思考过程
  steps?: TaskStep[]; // ✅ 新增：存储该消息对应的执行计划
  time: string;
}

// 定义会话结构
export interface ChatSession {
  id: string;
  title: string;
  date: string;
  lastUpdated: number;
}

export interface AiConfig {
  id?: number;
  name: string;
  provider: string;
  modelId: string;
  apiKey: string;
  baseUrl?: string;
  isActive: boolean;
}

export interface SessionLog {
  id?: number;
  sessionId: string;
  source: "Local" | "Device" | "Agent" | "Cloud";
  msg: string;
  type: "info" | "success" | "warning" | "error";
  isKeyResult?: boolean;
  time?: number; // timestamp
}

export interface NetworkCapture {
  id: string; // uuid
  sessionId: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status?: number;
  duration?: number;
  requestHeaders: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBody?: string;
  timestamp: number;
}

// 🔥 新增：已解包的项目记录
export interface RecentProject {
  id?: number;
  name: string;           // 项目名称 (APK 文件名)
  path: string;           // 解包后的路径
  packageName?: string;   // 包名 (从 Manifest 解析)
  apkPath?: string;       // 原始 APK 路径
  lastUsed: number;       // 最后使用时间戳
  createdAt: number;      // 创建时间戳
}

class MyAppDatabase extends Dexie {
  chatSessions!: Table<ChatSession>;
  chatMessages!: Table<ChatMessage>;
  aiConfigs!: Table<AiConfig>;
  sessionLogs!: Table<SessionLog>;
  networkCaptures!: Table<NetworkCapture>;
  recentProjects!: Table<RecentProject>; // 🔥 新增

  constructor() {
    super("ReverseWorkbenchDB");
    // Version 3 (Old)
    this.version(3).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId",
      aiConfigs: "++id, isActive",
    });

    // Version 4 (New - Logs)
    this.version(4).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId",
      aiConfigs: "++id, isActive",
      sessionLogs: "++id, sessionId",
    });

    // Version 5 (New - Network)
    this.version(5).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId",
      aiConfigs: "++id, isActive",
      sessionLogs: "++id, sessionId",
      networkCaptures: "id, sessionId",
    });

    // 🔥 Version 6 (New - RecentProjects)
    this.version(6).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId",
      aiConfigs: "++id, isActive",
      sessionLogs: "++id, sessionId",
      networkCaptures: "id, sessionId",
      recentProjects: "++id, path, lastUsed", // 支持按路径和时间查询
    });
  }
}

export const db = new MyAppDatabase();
