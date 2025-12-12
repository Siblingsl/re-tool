// (JSON 监控)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const _parse = JSON.parse;
    const _stringify = JSON.stringify;

    const getStack = () => {
      try {
        throw new Error();
      } catch (e) {
        return e.stack ? e.stack.split("\n").slice(2).join("\n") : "无堆栈信息";
      }
    };

    JSON.parse = function (...args) {
      const str = args[0];
      if (typeof str === "string" && str.length > 2) {
        console.log(
          `[JSON 解析] ${str.substring(0, 100)}${str.length > 100 ? "..." : ""}`
        );
        console.log(`[调用堆栈] \n${getStack()}`);
      }
      return _parse.apply(this, args);
    };

    JSON.stringify = function (...args) {
      const result = _stringify.apply(this, args);
      if (result && result.length > 2) {
        console.log(
          `[JSON 序列化] ${result.substring(0, 100)}${
            result.length > 100 ? "..." : ""
          }`
        );
        console.log(`[调用堆栈] \n${getStack()}`);
      }
      return result;
    };
  });
};
