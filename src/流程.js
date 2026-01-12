// 第一阶段：接收、预处理与记忆构建 (Ingestion & Memory)
// 目标：处理加壳，建立全量代码的语义索引。

// 用户动作：上传 Target.apk，需求：“破解 Sign 算法”。

// [Client] 环境侦测：

// 扫描 APK 结构。

// ⚠️ 坑 1：加壳检测

// 检测：发现 libjiagu.so / libsec.so。

// 应对：启动 内存脱壳流程。自动安装运行 -> 使用 frida-dexdump 提取 Dex -> 重组 APK。

// [Client] 本地反编译：

// 调用 JADX 将 Dex (或脱壳后的 Dex) 反编译为 Java/Smali 源码。

// [Client] 向量化索引 (RAG Build)：

// 切片：将源码按类或方法进行切片（Chunking）。

// Embedding：调用本地小模型将代码片段转为向量 (Vectors)。

// 存储：存入本地向量数据库。

// 优势：完全本地运行，数据不出域，不耗云端 Token。

// 🔵 第二阶段：握手与语义检索 (Handshake & Retrieval)
// 目标：云端通过自然语言“问”出关键代码，解决幻觉和上下文丢失。

// [Client] 握手：发送 { manifest_summary, user_prompt } (仅几 KB)。

// [Cloud] 初始规划：

// Agent 思考：“我要找 Sign 算法，通常和 encrypt, security, hash 有关。”

// [Cloud -> Client] 语义检索 (RAG Query)：

// 指令：VECTOR_SEARCH("signing algorithm encryption md5 sha256", top_k=5)。

// [Client] 本地搜索：

// 在向量库中匹配最相似的代码片段（即使用户代码混淆写成 a.b()，只要逻辑像加密，向量距离就会很近）。

// 返回：5 个最相关的代码片段（含文件名、行号）。

// 解决问题：AI 不会因为文件太多而遗忘，也不会因为找不到关键词（混淆）而产生幻觉。

// 🟡 第三阶段：深度分析与攻防对抗 (Deep Analysis)
// 目标：理解核心逻辑，解决混淆和 Native 难题。

// [Cloud] 逻辑分析：Agent 阅读返回的代码片段。

// ⚠️ 坑 2：严重混淆 (Obfuscation)

// 现象：代码全是 a.b.c(d)，控制流扁平化。

// 应对：语义重命名。AI 识别出 a.b 是 AES，建立映射表 a.b -> AES_Encrypt。

// ⚠️ 坑 3：动态加载 (Dynamic Loading)

// 现象：代码里全是 Reflect 或 DexClassLoader，找不到实现类。

// 应对：下发 Hook ClassLoader 脚本，监控 App 运行时到底加载了什么文件，把加载的 Dex 抓回来重新索引。

// ⚠️ 坑 4：Native 分析 (VMP/OLLVM)

// 现象：Java 调用了 native 方法。

// 应对 A (常规)：Client 用 Capstone 提取汇编 -> Cloud AI 脑补反编译。

// 应对 B (恶心混淆)：Cloud 发现汇编不可读 -> 请求 IDA 支援 -> 用户手动粘贴 F5 伪代码。

// 🔴 第四阶段：动态验证与反检测 (Verification & Anti-Anti)
// 目标：在真机上跑通逻辑，解决 Frida 对抗。

// [Cloud] 脚本生成：基于分析结果生成 Hook 脚本。

// [Client] 预检：连接手机。

// ⚠️ 坑 5：多进程 (Multi-Process)

// 现象：App 有主进程、UI 进程、守护进程。

// 应对：Client 运行 frida-ps 枚举进程 -> Cloud 判断应注入哪个进程（通常是 :core 或主进程） -> 指定注入目标。

// [Client] 注入执行：

// ⚠️ 坑 6：Frida 检测 (Anti-Frida)

// 现象：注入瞬间 App 闪退，或日志中断。

// 应对：

// Client 捕获 Crash 信号。

// Cloud 切换策略：MODE_SPAWN (重启注入) vs MODE_ATTACH (运行时注入)。

// Cloud 下发 Bypass 脚本（Hook ptrace, maps, read 等检测点）。

// Client 切换 hluda-server (去特征版 Frida)。

// ⚠️ 坑 7：Native 协议 (Socket/QUIC)

// 现象：Java 层 Hook 不到流量。

// 应对：Cloud 下发 libc.so 的 send/recv Hook 脚本，直接在 Native 层截获数据。

// 🟣 第五阶段：交付与迭代
// [Cloud] 验证：确认 Hook 抓到的 Sign 值与预期格式一致。

// [Client] 报告：生成最终报告，包含还原后的算法逻辑、可用的 Python 调用代码。

// sequenceDiagram
//     participant User as 👤 用户
//     participant Client as 🖥️ 客户端 (Worker + VectorDB)
//     participant Cloud as ☁️ 云端 Agent
//     participant Phone as 📱 手机

//     Note over User, Client: === 阶段 1: 预处理 & 记忆构建 ===
//     User->>Client: 上传 APK
//     Client->>Client: 🛡️ 检测并脱壳 (如有)
//     Client->>Client: JADX 反编译
//     Client->>Client: 🧠 Chunking & Embedding -> 存入本地 VectorDB

//     Note over Client, Cloud: === 阶段 2: 握手 & 语义检索 ===
//     Client->>Cloud: 发送 Manifest + apk解包后的文件目录树 + 任务目标（就是固定提示词与用户要求）
//     Cloud->>Client: 🔍 指令: VECTOR_SEARCH("加密 签名 Sign", k=5)
//     Client->>Client: 本地向量搜索
//     Client->>Cloud: 返回相关代码片段 (Top 5 Chunks)

//     Note over Cloud, Client: === 阶段 3: 深度分析 ===
//     Cloud->>Cloud: 分析代码 (解决混淆 a.b -> AES)
    
//     alt 发现 Native 方法
//         Cloud->>Client: 指令: GET_ASM (Capstone)
//         Client->>Cloud: 返回汇编文本
//     end
    
//     alt 发现动态加载
//         Cloud->>Client: 指令: Hook ClassLoader
//         Client->>Phone: 注入监控
//         Phone-->>Client: 捕获新 Dex
//         Client->>Client: 更新 VectorDB 索引
//     end

//     Note over Cloud, Phone: === 阶段 4: 动态验证 (循环攻防) ===
//     loop 攻防循环
//         Cloud->>Client: 下发 Frida 脚本
//         Client->>Client: 🛡️ 选择进程 (Multi-process)
//         Client->>Phone: 注入执行
        
//         alt 崩溃 (Anti-Frida)
//             Phone-->>Client: 💥 Crash!
//             Client->>Cloud: 报错
//             Cloud->>Client: 🔄 切换策略 (Bypass/Hluda)
//         else 成功
//             Phone-->>Client: ✅ Log: Sign=xxx
//             Client-->>Cloud: 回传日志
//         end
//     end

//     Note over Cloud, User: === 阶段 5: 交付 ===
//     Cloud->>User: 生成报告 (准确无幻觉)







// Dumper 集成：集成 frida-dexdump 的 Python 脚本或二进制，供 Agent 调遣。

// 多版本 Frida 管理：最好内置一个标准的 frida-server 和一个去特征的 hluda-server，Agent 可以命令切换。

// Crash 监听器：在运行 ADB 命令时，要能识别 Segmentation fault 或进程消失，并告诉云端“出事了”，而不是一直傻等。