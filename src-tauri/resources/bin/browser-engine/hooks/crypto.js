// (Web Crypto 监控)，有些网站使用浏览器原生加密 (window.crypto)，这个脚本可以把密钥打印出来。

module.exports = async (page) => {
  await page.addInitScript(() => {
    if (!window.crypto || !window.crypto.subtle) return;

    const getStack = () => {
      try {
        throw new Error();
      } catch (e) {
        return e.stack ? e.stack.split("\n").slice(2).join("\n") : "无堆栈信息";
      }
    };

    const _importKey = window.crypto.subtle.importKey;
    const _encrypt = window.crypto.subtle.encrypt;
    const _decrypt = window.crypto.subtle.decrypt;

    window.crypto.subtle.importKey = async function (format, keyData, ...args) {
      const buf = new Uint8Array(keyData);
      const hex = Array.from(buf)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      console.log(`[Crypto 导入密钥] 格式:${format} 密钥Hex:${hex}`);
      console.log(`[调用堆栈] \n${getStack()}`);
      return _importKey.call(this, format, keyData, ...args);
    };

    window.crypto.subtle.encrypt = async function (algo, key, data) {
      console.log(`[Crypto 执行加密] 算法:${algo.name}`);
      console.log(`[调用堆栈] \n${getStack()}`);
      return _encrypt.call(this, algo, key, data);
    };
  });
};
