// (WS 消息监控)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const _WebSocket = window.WebSocket;

    const getStack = () => {
      try {
        throw new Error();
      } catch (e) {
        return e.stack ? e.stack.split("\n").slice(2).join("\n") : "无堆栈信息";
      }
    };

    window.WebSocket = function (url, protocols) {
      const ws = new _WebSocket(url, protocols);
      console.log(`[WS 连接] ${url}`);
      console.log(`[调用堆栈] \n${getStack()}`);

      const _send = ws.send;
      ws.send = function (data) {
        console.log(`[WS 发送] ${data}`);
        console.log(`[调用堆栈] \n${getStack()}`);
        return _send.apply(this, arguments);
      };

      ws.addEventListener("message", function (event) {
        console.log(`[WS 接收] ${event.data}`);
      });

      return ws;
    };
    window.WebSocket.prototype = _WebSocket.prototype;
  });
};
