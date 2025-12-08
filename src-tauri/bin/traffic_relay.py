import json
import sys
import time
import uuid
import base64

# mitmproxy 流量转发脚本 (增强版)


def request(flow):
    if not hasattr(flow, "id"):
        flow.id = str(uuid.uuid4())

    data = {
        "id": flow.id,
        "method": flow.request.method,
        "url": flow.request.url,
        "host": flow.request.host,
        "path": flow.request.path,
        "scheme": flow.request.scheme,
        "startTime": time.time() * 1000,
        "requestHeaders": dict(flow.request.headers),
        # 自动处理 Body
        "requestBody": get_content_safe(flow.request),
        "contentType": flow.request.headers.get("Content-Type", ""),
    }
    print(json.dumps(data), flush=True)


def response(flow):
    req_id = getattr(flow, "id", "")

    data = {
        "id": req_id,
        "status": flow.response.status_code,
        "responseHeaders": dict(flow.response.headers),
        # 自动处理 Body
        "responseBody": get_content_safe(flow.response),
        "contentType": flow.response.headers.get("Content-Type", ""),
    }
    print(json.dumps(data), flush=True)


def get_content_safe(message):
    try:
        content = message.content
        if content is None:
            return ""
        try:
            # 尝试解码为文本
            return content.decode("utf-8")
        except UnicodeDecodeError:
            # 🔥 修改：直接返回带前缀的 Base64，不加多余的废话
            return "base64:" + base64.b64encode(content).decode("ascii")
    except Exception as e:
        return f"[Error: {str(e)}]"
