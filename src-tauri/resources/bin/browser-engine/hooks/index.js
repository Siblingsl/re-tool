const jsonHook = require("./json");
const cookieHook = require("./cookie");
const antiDebugHook = require("./anti_debug");
const networkHook = require("./network");
const websocketHook = require("./websocket");
const cryptoHook = require("./crypto");
const rpcInjectHook = require('./rpc_inject');

// 映射表：Key 必须和前端传过来的 value 一致
const HOOK_REGISTRY = {
  json_hook: jsonHook,
  cookie_hook: cookieHook,
  anti_debug: antiDebugHook,
  network_hook: networkHook,
  websocket_hook: websocketHook,
  crypto_hook: cryptoHook,
  rpc_inject: rpcInjectHook
};

/**
 * 批量注入 Hooks
 * @param {object} page - Playwright Page 对象
 * @param {string[]} hooksToInject - 前端勾选的 Hook 列表 ['json_hook', 'network_hook']
 */
async function injectHooks(page, hooksToInject) {
  if (!hooksToInject || !Array.isArray(hooksToInject)) return;

  for (const hookName of hooksToInject) {
    const handler = HOOK_REGISTRY[hookName];
    if (handler) {
      try {
        await handler(page);
        // 可以在这里发送一个 debug 日志给前端，说明注入成功
      } catch (e) {
        console.error(`Failed to inject hook: ${hookName}`, e);
      }
    }
  }
}

module.exports = { injectHooks };
