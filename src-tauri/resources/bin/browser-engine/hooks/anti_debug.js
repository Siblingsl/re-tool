// (反调试)

module.exports = async (page) => {
  await page.addInitScript(() => {
    // 1. Hook Function 构造器
    const _constructor = Function.prototype.constructor;
    Function.prototype.constructor = function (string) {
      if (typeof string === "string" && string.includes("debugger")) {
        console.log('[反调试] 拦截到 Function("debugger")');
        return function () {};
      }
      return _constructor.apply(this, arguments);
    };

    // 2. Hook eval
    const _eval = window.eval;
    window.eval = function (string) {
      if (typeof string === "string" && string.includes("debugger")) {
        console.log('[反调试] 拦截到 eval("debugger")');
        return _eval(string.replace(/debugger/g, ""));
      }
      return _eval(string);
    };

    // 3. Hook 定时器
    const _setInterval = window.setInterval;
    window.setInterval = function (func, delay) {
      if (func.toString().includes("debugger")) {
        console.log("[反调试] 拦截到定时器 debugger");
        return null;
      }
      return _setInterval(func, delay);
    };
  });
};
