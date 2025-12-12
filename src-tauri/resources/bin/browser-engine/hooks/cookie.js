// (Cookie 变化)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const cookieDesc =
      Object.getOwnPropertyDescriptor(Document.prototype, "cookie") ||
      Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");

    const getStack = () => {
      try {
        throw new Error();
      } catch (e) {
        return e.stack ? e.stack.split("\n").slice(2).join("\n") : "无堆栈信息";
      }
    };

    if (cookieDesc && cookieDesc.set) {
      Object.defineProperty(document, "cookie", {
        get: function () {
          return cookieDesc.get.call(document);
        },
        set: function (val) {
          console.log(`[Cookie 变更] ${val}`);
          console.log(`[调用堆栈] \n${getStack()}`);
          cookieDesc.set.call(document, val);
        },
      });
    }
  });
};
