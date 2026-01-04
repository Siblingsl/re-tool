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

class MyAppDatabase extends Dexie {
  chatSessions!: Table<ChatSession>;
  chatMessages!: Table<ChatMessage>;
  aiConfigs!: Table<AiConfig>;

  constructor() {
    super("ReverseWorkbenchDB");
    this.version(3).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId",
      aiConfigs: "++id, isActive",
    });
  }
}

export const db = new MyAppDatabase();
