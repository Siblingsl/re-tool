const { chromium, firefox, webkit } = require("playwright-extra");
const stealthPlugin = require("puppeteer-extra-plugin-stealth");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { injectHooks } = require("./hooks");
const { startRpcServer, stopRpcServer, updatePage } = require("./rpc_server");
const inspectorScript = require("./hooks/inspector_inject");
const { deobfuscate } = require("./ast_transform");
const { setupRiskControl } = require("./risk_solver");
const ProxyChain = require("proxy-chain"); // ✅ Import proxy-chain

const LOG_FILE = path.join(os.tmpdir(), "retool_engine_debug.log");
const logToFile = (msg) => {
  try {
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${msg}\n`);
  } catch (e) { }
};

chromium.use(stealthPlugin());

let browser = null;
let context = null;
let page = null;
let isBrowserActive = false;
let anonymizedProxyUrl = null; // ✅ Track anonymized proxy URL

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const sendEvent = (type, payload) => {
  try {
    const jsonStr = JSON.stringify({ type, payload });
    logToFile(`SEND: ${jsonStr}`);
    console.log(jsonStr);
  } catch (e) {
    logToFile(`SEND ERROR: ${e.message}`);
  }
};
// ... (skip lines)

// ... (inside handlers)
// Update handlers logic to log usage? No, I'll log in the line receiver.

const sendRpcLog = (msg) => {
  sendEvent("rpc_log", msg);
};

const handleExit = (source) => {
  if (isBrowserActive) {
    isBrowserActive = false;
    sendEvent("status", "Browser Closed");
    updatePage(null);
    if (anonymizedProxyUrl) {
      // ✅ Cleanup proxy server
      ProxyChain.closeAnonymizedProxy(anonymizedProxyUrl, true).catch(() => { });
      anonymizedProxyUrl = null;
    }
    browser = null;
    context = null;
    page = null;
  }
};

const handlers = {
  // ...
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
    const customScripts = config.customScripts || [];

    // 🔥🔥🔥 分离不同时机的脚本 🔥🔥🔥
    const startScripts = customScripts.filter(
      (s) => !s.timing || s.timing === "start"
    );
    const loadScripts = customScripts.filter((s) => s.timing === "load");

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

      // 🔥🔥🔥 代理配置 🔥🔥🔥
      let proxyOption = undefined;
      // Define proxyServer manually as proxyOption.server might be overwritten below
      if (config.proxy && config.proxy.mode !== "direct" && config.proxy.host && config.proxy.port) {
        const protocol = config.proxy.mode; // http, https, socks5
        let upstreamUrl = `${protocol}://${config.proxy.host}:${config.proxy.port}`;

        if (config.proxy.username) {
          // If auth is present, construct full URL with auth for proxy-chain
          upstreamUrl = `${protocol}://${config.proxy.username}:${config.proxy.password}@${config.proxy.host}:${config.proxy.port}`;

          // 🔥 Use proxy-chain to handle auth locally
          sendEvent("console", `[Proxy] Starting local forwarder for ${protocol} auth...`);
          try {
            anonymizedProxyUrl = await ProxyChain.anonymizeProxy(upstreamUrl);
            sendEvent("console", `[Proxy] Forwarder started: ${anonymizedProxyUrl}`);

            // Playwright gets the local ANONYMOUS proxy
            proxyOption = {
              server: anonymizedProxyUrl
            };
          } catch (e) {
            sendEvent("error", `[Proxy] Failed to start forwarder: ${e.message}`);
            // Fallback to original (will fail likely)
            proxyOption = { server: upstreamUrl };
          }
        } else {
          // No auth, direct usage
          proxyOption = {
            server: upstreamUrl
          };
        }

        if (!anonymizedProxyUrl) {
          sendEvent("console", `[Proxy] Enabled: ${proxyOption.server}`);
        }
      }

      browser = await launcher.launch({
        headless: isHeadless,
        args: launchArgs,
        proxy: proxyOption,
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

      // 🔥🔥🔥 注入风控对抗 (Cloudflare 等) 🔥🔥🔥
      if (config.risk) {
        sendEvent("console", `[Risk] Applying Risk Control Config...`);
        await setupRiskControl(page, config.risk);
      }

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
          if (rule.action === "AST_Transform") {
            try {
              const response = await route.fetch();
              const originalBody = await response.text();
              sendEvent("console", `[AST] 正在还原 ${request.url()} ...`);
              const cleanCode = deobfuscate(originalBody);
              sendEvent("console", `[AST] 还原成功: ${request.url()}`);
              return route.fulfill({
                response,
                body: cleanCode,
                headers: {
                  ...response.headers(),
                  "content-length": String(Buffer.byteLength(cleanCode)),
                },
              });
            } catch (e) {
              sendEvent(
                "error",
                `[AST] 还原失败: ${request.url()} - ${e.message}`
              );
              return route.continue();
            }
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

      // 🔥🔥🔥 注入 Start 时机的脚本 (Pre-load) 🔥🔥🔥
      for (const scriptObj of startScripts) {
        try {
          // 兼容旧格式(字符串)和新格式(对象)
          const codeContent =
            typeof scriptObj === "string" ? scriptObj : scriptObj.code;
          await page.addInitScript({ content: codeContent });
        } catch (e) {
          sendEvent("error", `Pre-load Script Error: ${e.message}`);
        }
      }

      // 导航页面
      await page.goto(config.url, { timeout: 30000 });

      // 🔥🔥🔥 注入 Load 时机的脚本 (Post-load) 🔥🔥🔥
      // 此时页面已加载完成 (Playwright 的 goto 默认等待 load 事件)
      if (loadScripts.length > 0) {
        sendEvent(
          "console",
          `[Script] 正在执行 ${loadScripts.length} 个加载后脚本...`
        );
        for (const scriptObj of loadScripts) {
          try {
            await page.evaluate(scriptObj.code);
            sendEvent("console", `[Script] 加载后脚本执行成功`);
          } catch (e) {
            sendEvent("error", `Post-load Script Error: ${e.message}`);
          }
        }
      }

      sendEvent("status", `Browser Launched (${browserType})`);
    } catch (e) {
      if (isBrowserActive) {
        sendEvent("error", `Launch Failed: ${e.message}`);
        if (browser) await browser.close().catch(() => { });
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
      } catch (e) { }
      await page.evaluate(inspectorScript);
      sendEvent("console", "[Inspector] 拾取模式已激活，请点击网页元素");
    } catch (e) {
      sendEvent("error", `Inspector Error: ${e.message}`);
    }
  },

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

  async ast_deobfuscate(data) {
    const sourceCode = data.code;
    if (!sourceCode) return;
    sendEvent("console", "[AST] 正在解析并还原代码...");
    try {
      const startTime = Date.now();
      const resultCode = deobfuscate(sourceCode, data.engine);
      const cost = Date.now() - startTime;
      sendEvent("ast_result", { code: resultCode, cost: cost });
      // sendEvent("console", `[AST] 还原成功 (耗时 ${cost}ms)`);
    } catch (e) {
      logToFile(`AST ERROR: ${e.message}`); // Log to file instead of sending error immediately if risky
      sendEvent("error", `AST Error: ${e.message}`);
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
    logToFile(`RECV: ${line}`);
    const msg = JSON.parse(line);
    if (handlers[msg.action]) {
      handlers[msg.action](msg.data).catch((e) => {
        logToFile(`HANDLER ERROR: ${e.message}`);
        if (isBrowserActive) sendEvent("error", e.toString());
        else sendEvent("error", "Engine Error (Inactive): " + e.toString());
      });
    } else {
      logToFile(`UNKNOWN ACTION: ${msg.action}`);
    }
  } catch (e) {
    logToFile(`PARSE ERROR: ${e.message}`);
  }
});

sendEvent("status", "Engine Ready");
