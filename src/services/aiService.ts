import { GoogleGenAI } from "@google/genai";

// 警告：实际生产中 API Key 不建议直接写在前端代码里。
// 建议从环境变量 (process.env) 或 localStorage 读取。
const API_KEY = "你的_GOOGLE_GEMINI_API_KEY";

// 初始化客户端 (注意：新版 SDK 不需要 getGenerativeModel，而是直接在调用时指定模型)
const genAI = new GoogleGenAI({ apiKey: API_KEY });

// 模型选择建议：
// gemini-2.0-flash: 速度极快，适合大批量简单的伪代码转换
// gemini-1.5-pro: 逻辑推理能力更强，适合复杂的混淆代码分析
const MODEL_NAME = "gemini-2.0-flash";

export interface ConvertRequest {
  sourceCode: string;
  sourceLang: string; // e.g., "IDA Pseudocode"
  targetLang: string; // e.g., "Python", "JavaScript"
}

/**
 * 移除可能存在的 Markdown 代码块标记 (```javascript ... ```)
 */
const cleanMarkdown = (text: string): string => {
  if (!text) return "";
  // 移除开头的 ```xxx
  text = text.replace(/^```[a-zA-Z]*\n?/, "");
  // 移除结尾的 ```
  text = text.replace(/\n?```$/, "");
  return text.trim();
};

export const convertCode = async (req: ConvertRequest): Promise<string> => {
  // 使用 systemInstruction 设置角色，这是 Gemini 1.5/2.0 的推荐做法
  // 这样可以让模型更专注于遵守约束条件
  const systemPrompt = `
    Role: Android Reverse Engineering Expert.
    Task: Translate ${req.sourceLang} code into executable ${req.targetLang}.

    Guidelines:
    1.  **Logic Preservation**: Handle IDA/Ghidra specific macros (LOBYTE, HIBYTE, v4, a1, etc.) by converting them to equivalent ${req.targetLang} logic or bitwise operations.
    2.  **Dependencies**: Use standard libraries where possible. If external deps are needed, add comments.
    3.  **Readability**: Improve variable names if context allows, otherwise keep strict mapping.
    4.  **Output**: Return ONLY the raw code. No markdown backticks, no explanatory text before or after.
  `;

  try {
    const result = await genAI.models.generateContent({
      model: MODEL_NAME,
      config: {
        // 温度设低一点，保证代码生成的确定性和准确性
        temperature: 0.1,
        systemInstruction: {
          parts: [{ text: systemPrompt }],
        },
      },
      contents: [
        {
          role: "user",
          parts: [{ text: req.sourceCode }],
        },
      ],
    });

    // 解析响应
    const responseText = result.text;

    if (!responseText) {
      throw new Error("Empty response from AI");
    }

    return cleanMarkdown(responseText);
  } catch (error) {
    console.error("AI Conversion Error:", error);
    // 可以在这里根据 error 类型返回更友好的错误信息
    throw new Error(
      `Failed to convert code: ${
        error instanceof Error ? error.message : "Unknown error"
      }`
    );
  }
};
