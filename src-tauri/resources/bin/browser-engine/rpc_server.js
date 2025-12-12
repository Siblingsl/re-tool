const WebSocket = require("ws");

let wss = null;
let currentPage = null;
let sendLog = null; // 用于发回给前端 UI 显示日志

const startRpcServer = (port = 9999, page, logCallback) => {
  if (wss) {
    logCallback("RPC Server 已经在运行中");
    return;
  }

  currentPage = page;
  sendLog = logCallback;

  try {
    wss = new WebSocket.Server({ port });

    logCallback(`RPC 服务已启动: ws://127.0.0.1:${port}`);

    wss.on("connection", (ws) => {
      logCallback("RPC 客户端已连接");

      ws.on("message", async (message) => {
        try {
          // 协议格式: { "action": "call", "func": "encrypt", "args": ["hello"] }
          const req = JSON.parse(message);

          if (req.action === "call") {
            if (!currentPage || currentPage.isClosed()) {
              ws.send(
                JSON.stringify({ status: 500, error: "浏览器页面未就绪" })
              );
              return;
            }

            logCallback(`[RPC Call] ${req.func}(${JSON.stringify(req.args)})`);

            // 🔥 核心：在浏览器上下文中执行注册的函数
            const result = await currentPage.evaluate(
              async ({ funcName, args }) => {
                if (!window.rpc_registry || !window.rpc_registry[funcName]) {
                  throw new Error(
                    `函数 ${funcName} 未注册。请先在浏览器控制台执行 window.rpc.register("${funcName}", func)`
                  );
                }
                return await window.rpc_registry[funcName](...args);
              },
              { funcName: req.func, args: req.args || [] }
            );

            ws.send(JSON.stringify({ status: 200, data: result }));
            logCallback(
              `[RPC Result] ${JSON.stringify(result).substring(0, 50)}...`
            );
          }
        } catch (e) {
          logCallback(`[RPC Error] ${e.message}`);
          ws.send(JSON.stringify({ status: 500, error: e.message }));
        }
      });

      ws.on("close", () => {
        logCallback("RPC 客户端断开");
      });
    });

    wss.on("error", (e) => {
      logCallback(`RPC 服务错误: ${e.message}`);
    });
  } catch (e) {
    logCallback(`RPC 启动失败: ${e.message}`);
  }
};

const stopRpcServer = () => {
  if (wss) {
    wss.close();
    wss = null;
  }
};

const updatePage = (page) => {
  currentPage = page;
};

module.exports = { startRpcServer, stopRpcServer, updatePage };
