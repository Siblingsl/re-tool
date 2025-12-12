// (Cookie 变化)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const cookieDesc =
      Object.getOwnPropertyDescriptor(Document.prototype, "cookie") ||
      Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");

    if (cookieDesc && cookieDesc.set) {
      Object.defineProperty(document, "cookie", {
        get: function () {
          return cookieDesc.get.call(document);
        },
        set: function (val) {
          console.log(`[Cookie Set] ${val}`);
          cookieDesc.set.call(document, val);
        },
      });
    }
  });
};
