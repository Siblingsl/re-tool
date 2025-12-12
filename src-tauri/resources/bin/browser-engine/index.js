const { chromium, firefox, webkit } = require("playwright-extra");
const stealthPlugin = require("puppeteer-extra-plugin-stealth");
const readline = require("readline");
const { injectHooks } = require("./hooks");
const { startRpcServer, stopRpcServer, updatePage } = require("./rpc_server"); // 🔥 引入 RPC

// 仅 Chromium 支持完美隐身
chromium.use(stealthPlugin());

let browser = null;
let context = null;
let page = null;
let isBrowserActive = false;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const sendEvent = (type, payload) => {
  try {
    console.log(JSON.stringify({ type, payload }));
  } catch (e) {}
};

// 发送 RPC 专用日志
const sendRpcLog = (msg) => {
  sendEvent("rpc_log", msg);
};

const handleExit = (source) => {
  if (isBrowserActive) {
    isBrowserActive = false;
    sendEvent("status", "Browser Closed");

    // 浏览器关闭时，是否要关闭 RPC 服务？
    // 策略：保持 RPC 服务开启，但置空 page，等待下次启动自动重连
    updatePage(null);

    browser = null;
    context = null;
    page = null;
  }
};

const handlers = {
  async launch(config) {
    if (isBrowserActive) {
      sendEvent("status", "Browser Already Running");
      return;
    }

    if (
      !config.url ||
      typeof config.url !== "string" ||
      !config.url.startsWith("http")
    ) {
      sendEvent("error", "Launch Failed: Invalid URL");
      return;
    }

    const isHeadless = config.headless !== false;
    const browserType = config.browserType || "firefox";

    // 🔥 强制注入 RPC Hook (默认开启)
    const activeHooks = config.hooks || [];
    if (!activeHooks.includes("rpc_inject")) {
      activeHooks.push("rpc_inject");
    }

    sendEvent("status", `Launching ${browserType}...`);
    isBrowserActive = true;

    try {
      let launcher;
      let launchArgs = [];

      switch (browserType) {
        case "firefox":
          launcher = firefox;
          launchArgs = ["--no-remote", "--wait-for-browser"];
          break;
        case "webkit":
          launcher = webkit;
          break;
        case "chromium":
        default:
          launcher = chromium;
          launchArgs = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-blink-features=AutomationControlled",
          ];
          break;
      }

      browser = await launcher.launch({
        headless: isHeadless,
        args: launchArgs,
      });

      browser.on("disconnected", () => handleExit("browser_disconnected"));

      context = await browser.newContext({
        viewport: { width: 1280, height: 800 },
        locale: "zh-CN",
        timezoneId: "Asia/Shanghai",
        deviceScaleFactor: 1,
        userAgent:
          browserType === "chromium"
            ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            : undefined,
      });

      context.on("close", () => handleExit("context_closed"));

      await context.addInitScript(() => {
        Object.defineProperty(navigator, "webdriver", { get: () => undefined });
        if (navigator.userAgent.includes("Chrome")) {
          window.navigator.chrome = { runtime: {} };
        }
        if (!navigator.plugins || navigator.plugins.length === 0) {
          Object.defineProperty(navigator, "plugins", {
            get: () => [1, 2, 3, 4, 5],
          });
        }
      });

      page = await context.newPage();

      // 🔥 更新 RPC 服务的页面引用
      updatePage(page);

      page.on("close", () => handleExit("page_closed"));

      page.on("console", (msg) => {
        if (msg.type() === "log" || msg.text().startsWith("[")) {
          sendEvent("console", msg.text());
        }
      });

      await injectHooks(page, activeHooks);

      await page.goto(config.url, { timeout: 30000 });

      sendEvent("status", `Browser Launched (${browserType})`);
    } catch (e) {
      if (isBrowserActive) {
        sendEvent("error", `Launch Failed: ${e.message}`);
        if (browser) await browser.close().catch(() => {});
        handleExit("launch_error");
      }
    }
  },

  // 🔥 新增：RPC 控制指令
  async rpc_ctrl(data) {
    if (data.action === "start") {
      startRpcServer(data.port, page, sendRpcLog);
    } else if (data.action === "stop") {
      stopRpcServer();
      sendRpcLog("RPC 服务已停止");
    }
  },

  async eval(code) {
    if (!page || !isBrowserActive) {
      sendEvent("error", "Page not ready");
      return;
    }
    try {
      const result = await page.evaluate(code);
      sendEvent("eval_result", result);
    } catch (e) {
      sendEvent("error", e.message);
    }
  },

  async close() {
    stopRpcServer(); // 关闭 RPC
    sendEvent("status", "Browser Force Closed");
    process.exit(0);
  },
};

rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (handlers[msg.action]) {
      handlers[msg.action](msg.data).catch((e) => {
        if (isBrowserActive) sendEvent("error", e.toString());
      });
    }
  } catch (e) {}
});

sendEvent("status", "Engine Ready");
