module.exports = async (page) => {
  await page.addInitScript(() => {
    // 全局注册表
    window.rpc_registry = {};

    // 暴露给用户的 API
    window.rpc = {
      // 用户调用这个来注册函数
      // 例子: window.rpc.register("encrypt", (text) => btoa(text));
      register: function (name, func) {
        if (typeof func !== "function") {
          console.error(`[RPC] 注册失败: ${name} 必须是一个函数`);
          return;
        }
        window.rpc_registry[name] = func;
        console.log(
          `%c[RPC] 函数已注册: ${name}`,
          "color: #10b981; font-weight: bold;"
        );
        console.log(
          `现在可以通过 WebSocket 调用: { "action": "call", "func": "${name}", "args": [...] }`
        );
      },

      // 查看已注册列表
      list: function () {
        return Object.keys(window.rpc_registry);
      },
    };

    console.log(
      "%c[RPC] 桥接已就绪。使用 window.rpc.register(name, func) 暴露函数。",
      "color: #3b82f6;"
    );
  });
};
