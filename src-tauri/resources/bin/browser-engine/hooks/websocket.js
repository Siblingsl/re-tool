// (WS 消息监控)

module.exports = async (page) => {
  await page.addInitScript(() => {
    const _WebSocket = window.WebSocket;

    window.WebSocket = function (url, protocols) {
      const ws = new _WebSocket(url, protocols);
      console.log(`[WS Connect] ${url}`);

      const _send = ws.send;
      ws.send = function (data) {
        console.log(`[WS Send] ${data}`);
        return _send.apply(this, arguments);
      };

      ws.addEventListener("message", function (event) {
        console.log(`[WS Recv] ${event.data}`);
      });

      return ws;
    };
    window.WebSocket.prototype = _WebSocket.prototype;
  });
};
