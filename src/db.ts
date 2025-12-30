// src/db.ts
import Dexie, { Table } from "dexie";

// 定义消息结构
export interface ChatMessage {
  id?: number; // 自增主键
  sessionId: string; // 关联的会话ID
  role: "user" | "ai";
  content: string;
  reasoning?: string; // 附加信息，如推理过程
  time: string;
}

// 定义会话结构
export interface ChatSession {
  id: string; // 使用时间戳或UUID字符串
  title: string;
  date: string;
  lastUpdated: number; // 用于排序
}

// ✅ 新增：AI 配置的接口
export interface AiConfig {
  id?: number;
  name: string; // 自定义名称，如 "公司 GPT-4"
  provider: string; // 服务商，如 'openai', 'deepseek'
  modelId: string; // 模型ID，如 'gpt-4o'
  apiKey: string;
  baseUrl?: string;
  isActive: boolean; // 是否为当前启用模型
}

class MyAppDatabase extends Dexie {
  chatSessions!: Table<ChatSession>;
  chatMessages!: Table<ChatMessage>;
  aiConfigs!: Table<AiConfig>;

  constructor() {
    super("ReverseWorkbenchDB");

    // ❗ 修改点 1：如果你修改了 stores 结构，必须升级 version 版本号 (例如从 2 改为 3)
    this.version(3).stores({
      chatSessions: "id, lastUpdated",
      chatMessages: "++id, sessionId", // 确保 sessionId 是索引
      aiConfigs: "++id, isActive", // 确保 isActive 是索引
    });
  }
}

export const db = new MyAppDatabase();
