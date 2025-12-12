// (Web Crypto 监控)，有些网站使用浏览器原生加密 (window.crypto)，这个脚本可以把密钥打印出来。

module.exports = async (page) => {
  await page.addInitScript(() => {
    if (!window.crypto || !window.crypto.subtle) return;

    const _importKey = window.crypto.subtle.importKey;
    const _encrypt = window.crypto.subtle.encrypt;
    const _decrypt = window.crypto.subtle.decrypt;

    window.crypto.subtle.importKey = async function (format, keyData, ...args) {
      // 将 ArrayBuffer 转为 Hex 字符串方便查看
      const buf = new Uint8Array(keyData);
      const hex = Array.from(buf)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      console.log(`[Crypto ImportKey] Format:${format} Key:${hex}`);
      return _importKey.call(this, format, keyData, ...args);
    };

    window.crypto.subtle.encrypt = async function (algo, key, data) {
      console.log(`[Crypto Encrypt] Algo:${algo.name}`);
      return _encrypt.call(this, algo, key, data);
    };
  });
};
