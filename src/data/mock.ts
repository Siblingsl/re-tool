import { Device, AppInfo } from "../types";

export const MOCK_DEVICES: Device[] = [
  {
    id: "1",
    name: "Pixel 6 Pro",
    os: "Android 13",
    type: "android",
    status: "online",
    battery: 85,
  },
  {
    id: "2",
    name: "iPhone 14",
    os: "iOS 16.4",
    type: "ios",
    status: "online",
    battery: 42,
  },
];

export const MOCK_APPS: AppInfo[] = [
  {
    id: "1",
    name: "抖音 (TikTok)",
    pkg: "com.ss.android.ugc.aweme",
    ver: "28.0.0",
    icon: "#000",
  },
  {
    id: "2",
    name: "微信 (WeChat)",
    pkg: "com.tencent.mm",
    ver: "8.0.42",
    icon: "#25d366",
  },
  {
    id: "3",
    name: "哔哩哔哩",
    pkg: "tv.danmaku.bili",
    ver: "7.20.0",
    icon: "#fb7299",
  },
  {
    id: "4",
    name: "某加密Demo",
    pkg: "com.example.cryptotest",
    ver: "1.0.1",
    icon: "#666",
  },
];
