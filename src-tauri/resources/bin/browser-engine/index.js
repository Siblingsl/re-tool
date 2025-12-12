const { chromium, firefox, webkit } = require("playwright-extra");
const stealthPlugin = require("puppeteer-extra-plugin-stealth");
const readline = require("readline");
const { injectHooks } = require("./hooks");

// 仅 Chromium 支持完美隐身
chromium.use(stealthPlugin());

let browser = null;
let context = null;
let page = null;
let isBrowserActive = false; // 🔥 全局运行状态锁

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const sendEvent = (type, payload) => {
  try {
    console.log(JSON.stringify({ type, payload }));
  } catch (e) {
    // ignore json error
  }
};

// 🔥 统一的退出处理器
const handleExit = (source) => {
  // 只要标记为活跃，收到任何一个关闭信号都执行清理
  if (isBrowserActive) {
    isBrowserActive = false; // 立即锁死，防止重复发送
    sendEvent("status", "Browser Closed");

    // 尝试清理引用
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

    // 🔥 校验 URL
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

    sendEvent("status", `Launching ${browserType}...`);
    isBrowserActive = true; // 🔥 标记为开始运行

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

      // 🔥 监听 1: 浏览器进程断开
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

      // 🔥 监听 2: 上下文关闭 (用户点击窗口X通常触发这个)
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

      // 🔥 监听 3: 页面关闭 (用户关闭唯一标签页)
      page.on("close", () => handleExit("page_closed"));

      page.on("console", (msg) => {
        if (msg.type() === "log" || msg.text().startsWith("[")) {
          sendEvent("console", msg.text());
        }
      });

      await injectHooks(page, activeHooks);

      // 设置超时
      await page.goto(config.url, { timeout: 30000 });

      // 如果到了这一步，说明加载完成，但还没有关闭
      // 此时 isBrowserActive 依然是 true
      sendEvent("status", `Browser Launched (${browserType})`);
    } catch (e) {
      // 只有当不是因为"浏览器被关闭"导致的错误时，才报错
      // 比如：如果用户在加载中关闭了，handleExit 会先执行将 isBrowserActive 设为 false
      // 这里的 catch 会捕获到 Target closed 错误

      if (isBrowserActive) {
        sendEvent("error", `Launch Failed: ${e.message}`);
        // 尝试强制关闭以重置
        if (browser) await browser.close().catch(() => {});
        handleExit("launch_error");
      }
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
    sendEvent("status", "Browser Force Closed");
    process.exit(0);
  },
};

rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (handlers[msg.action]) {
      handlers[msg.action](msg.data).catch((e) => {
        // 顶层捕获，防止崩掉
        if (isBrowserActive) sendEvent("error", e.toString());
      });
    }
  } catch (e) {}
});

sendEvent("status", "Engine Ready");
