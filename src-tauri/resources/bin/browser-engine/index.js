const { chromium, firefox, webkit } = require("playwright-extra");
const stealthPlugin = require("puppeteer-extra-plugin-stealth");
const readline = require("readline");
const { injectHooks } = require("./hooks");
const { startRpcServer, stopRpcServer, updatePage } = require("./rpc_server");
const inspectorScript = require("./hooks/inspector_inject");

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

const sendRpcLog = (msg) => {
  sendEvent("rpc_log", msg);
};

const handleExit = (source) => {
  if (isBrowserActive) {
    isBrowserActive = false;
    sendEvent("status", "Browser Closed");
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
    const activeHooks = config.hooks || [];
    const interceptRules = config.intercepts || [];

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
        ignoreHTTPSErrors: true,
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
      updatePage(page);

      // 注入拦截规则
      for (const rule of interceptRules) {
        if (!rule.enabled) continue;
        await page.route(rule.urlPattern, async (route) => {
          const request = route.request();
          const resourceType = request.resourceType();
          if (
            rule.resourceType !== "All" &&
            resourceType.toLowerCase() !== rule.resourceType.toLowerCase()
          ) {
            return route.continue();
          }
          sendEvent(
            "console",
            `[Intercept] Matched: ${request.url()} (${rule.action})`
          );
          if (rule.action === "Abort") return route.abort();
          if (rule.action === "MockBody") {
            let contentType = "application/json";
            if (rule.resourceType === "Script")
              contentType = "application/javascript";
            return route.fulfill({
              status: 200,
              contentType: contentType,
              body: rule.payload,
            });
          }
          return route.continue();
        });
      }

      page.on("close", () => handleExit("page_closed"));

      page.on("console", (msg) => {
        if (msg.type() === "log" || msg.text().startsWith("[")) {
          sendEvent("console", msg.text());
        }
      });

      await injectHooks(page, activeHooks);

      // ============================================
      // 🔥🔥🔥 注入用户自定义脚本 (Script Manager) 🔥🔥🔥
      // ============================================
      const customScripts = config.customScripts || [];
      for (const scriptCode of customScripts) {
        try {
          // 使用 content 属性注入纯字符串代码
          await page.addInitScript({ content: scriptCode });
        } catch (e) {
          sendEvent("error", `自定义脚本注入失败: ${e.message}`);
        }
      }

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

  async rpc_ctrl(data) {
    if (data.action === "start") {
      startRpcServer(data.port, page, sendRpcLog);
    } else if (data.action === "stop") {
      stopRpcServer();
      sendRpcLog("RPC 服务已停止");
    }
  },

  async toggle_inspector(data) {
    if (!page || !isBrowserActive) {
      sendEvent("error", "请先启动浏览器");
      return;
    }
    try {
      try {
        await page.exposeFunction("__weblab_onPick", (selector) => {
          sendEvent("inspector_picked", selector);
        });
      } catch (e) {}
      await page.evaluate(inspectorScript);
      sendEvent("console", "[Inspector] 拾取模式已激活，请点击网页元素");
    } catch (e) {
      sendEvent("error", `Inspector Error: ${e.message}`);
    }
  },

  // 🔥🔥🔥 新增：元素截图 (用于 AI 识别) 🔥🔥🔥
  async screenshot_element(data) {
    if (!page || !isBrowserActive) {
      sendEvent("error", "Browser not active");
      return;
    }
    try {
      const buffer = await page
        .locator(data.selector)
        .screenshot({ type: "png" });
      const base64 = buffer.toString("base64");
      sendEvent("element_screenshot", {
        selector: data.selector,
        image: base64,
      });
    } catch (e) {
      sendEvent("error", `Screenshot Failed: ${e.message}`);
    }
  },

  async eval(code) {
    if (!page || !isBrowserActive) {
      sendEvent("error", "Page not ready");
      return;
    }
    try {
      const result = await eval(`(async () => { ${code} })()`);
      let output;
      if (result === undefined) output = "undefined";
      else if (typeof result === "object") output = JSON.stringify(result);
      else output = String(result);
      sendEvent("eval_result", output);
    } catch (e) {
      sendEvent("error", e.message);
    }
  },

  async close() {
    stopRpcServer();
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
