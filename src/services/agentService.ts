import { invoke } from "@tauri-apps/api/core";
import { message } from "antd";

const AGENT_API_URL = "http://localhost:3000/api";

export interface StartAgentOptions {
    manifestContent?: string;
    fileTree?: any[];
    socketId?: string;
    modelConfig?: any;
    sessionId?: string; // 🔥 Added sessionId
}

export const agentService = {
    /**
     * 启动智能体任务
     */
    async startAgentTask(
        projectDir: string,
        instruction: string = "对该应用进行全面的逆向分析，重点关注加密逻辑和潜在漏洞。",
        existingData?: StartAgentOptions
    ) {
        try {
            // 1. Manifest
            let manifestContent = existingData?.manifestContent;
            if (!manifestContent) {
                try {
                    const manifestPath = `${projectDir}\\AndroidManifest.xml`;
                    manifestContent = await invoke<string>("read_local_file", { path: manifestPath });
                } catch (e) {
                    console.warn("Failed to read AndroidManifest.xml", e);
                }
            }

            // 2. File Tree
            // Rust notify_cloud_job_start expects the TREE structure (Vec<FileNode>), not flat list.
            // It will flatten it internally.
            let fileTree = existingData?.fileTree;
            if (!fileTree || fileTree.length === 0) {
                try {
                    fileTree = await invoke<any[]>("scan_local_dir", { path: projectDir });
                } catch (e) {
                    console.warn("Failed to scan directory", e);
                    fileTree = [];
                }
            }

            // 3. Call Rust Backend
            // fn notify_cloud_job_start(session_id: String, file_path: String, instruction: String, model_config: Option<ModelConfig>, manifest: Option<String>, file_tree: Option<Vec<FileNode>>, network_captures: Option<Vec<Value>>, frida_mode: Option<String>, use_stealth_mode: Option<bool>)

            // We need sessionId. Where do we get it? 
            // Usually passed from UI or generated. 
            // But wait, the previous code returned sessionId from server.
            // Here we need to generate it or reuse one.
            // AiChatPage generates a sessionId (passed as prop).
            // But agentService.startAgentTask didn't take sessionId before (it returned one).
            // The Rust command REQUIRES sessionId.

            // Let's generate a temporary one if not provided, or change interface?
            // Actually AiChatPage calls this with a sessionId context usually available.
            // But startAgentTask signature currently is (projectDir, instruction, existingData).
            // We should add sessionId to existingData or arguments.

            // However, Looking at AiChatPage usage:
            // const res = await agentService.startAgentTask(..., { socketId: ... })
            // It expects `res.sessionId`.

            // If we use invoke 'notify_cloud_job_start', we must pass the sessionId.
            // The Rust command returns `Ok("Started")` string (line 816), NOT a sessionId.

            // CRITICAL: AiChatPage creates the sessionId (AiWorkbenchPage takes sessionId prop).
            // The `socketId` logic in AiChatPage implies a session exists.

            // But `JavaAnalyzer` (which I reverted) also used it.

            // Let's assume usage in AiChatPage:
            // The AiChatPage uses `sessionId` prop.
            // Use that.

            // I will update existingData to include sessionId.
            const sessionId = existingData?.sessionId || `sess-${Date.now()}`;

            const response = await invoke("notify_cloud_job_start", {
                sessionId: sessionId,
                filePath: projectDir,
                instruction: instruction,
                modelConfig: existingData?.modelConfig,
                manifest: manifestContent,
                fileTree: fileTree,
                networkCaptures: [], // Optional, passed separately usually
                fridaMode: "spawn",  // Default
                useStealthMode: false // Default
            });

            return { success: true, sessionId: sessionId, message: response };

        } catch (error: any) {
            console.error("Agent Start Error:", error);
            throw error;
        }
    },
};

// Remove flattenTree as Rust handles it

