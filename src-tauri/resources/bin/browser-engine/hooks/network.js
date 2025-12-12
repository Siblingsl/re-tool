// (网络请求拦截)，这个脚本会拦截 XMLHttpRequest 和 fetch，打印 URL 和请求头，方便你找签名参数

module.exports = async (page) => {
  await page.addInitScript(() => {
    const getStack = () => {
      try {
        throw new Error();
      } catch (e) {
        return e.stack ? e.stack.split("\n").slice(2).join("\n") : "无堆栈信息";
      }
    };

    // 1. 拦截 XMLHttpRequest
    const _open = XMLHttpRequest.prototype.open;
    const _setRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    const _send = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url) {
      this._url = url;
      this._method = method;
      this._headers = {};
      return _open.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function (key, val) {
      this._headers[key] = val;
      return _setRequestHeader.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function (body) {
      console.log(`[XHR 请求] ${this._method} ${this._url}`);
      if (Object.keys(this._headers).length > 0) {
        console.log(`[XHR 请求头] ${JSON.stringify(this._headers)}`);
      }
      if (body) {
        console.log(`[XHR 请求体] ${body}`);
      }
      console.log(`[调用堆栈] \n${getStack()}`);
      return _send.apply(this, arguments);
    };

    // 2. 拦截 Fetch
    const _fetch = window.fetch;
    window.fetch = function (url, options) {
      if (url) {
        const method = options?.method || "GET";
        console.log(`[Fetch 请求] ${method} ${url}`);
        if (options?.headers) {
          console.log(`[Fetch 请求头] ${JSON.stringify(options.headers)}`);
        }
        if (options?.body) {
          console.log(`[Fetch 请求体] ${options.body}`);
        }
        console.log(`[调用堆栈] \n${getStack()}`);
      }
      return _fetch.apply(this, arguments);
    };
  });
};
