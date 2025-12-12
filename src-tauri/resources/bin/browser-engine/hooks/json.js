// (JSON 监控)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const _parse = JSON.parse;
    const _stringify = JSON.stringify;

    JSON.parse = function (...args) {
      const str = args[0];
      if (typeof str === "string" && str.length > 2) {
        // 限制长度防止刷屏
        console.log(
          `[JSON.parse] ${str.substring(0, 100)}${
            str.length > 100 ? "..." : ""
          }`
        );
      }
      return _parse.apply(this, args);
    };

    JSON.stringify = function (...args) {
      const result = _stringify.apply(this, args);
      if (result && result.length > 2) {
        console.log(
          `[JSON.stringify] ${result.substring(0, 100)}${
            result.length > 100 ? "..." : ""
          }`
        );
      }
      return result;
    };
  });
};
