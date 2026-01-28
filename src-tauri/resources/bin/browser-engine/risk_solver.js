const { chromium } = require("playwright-extra");

/**
 * 模拟人类鼠标移动轨迹
 */
async function humanClick(page, box) {
    if (!box) return false;
    // 移动到目标区域中心附近
    const targetX = box.x + box.width / 2 + (Math.random() * 10 - 5);
    const targetY = box.y + box.height / 2 + (Math.random() * 10 - 5);

    // 1. 缓慢移动过去
    await page.mouse.move(targetX, targetY, { steps: 25 });
    // 2. 也是人类行为：稍微停顿
    await page.waitForTimeout(Math.random() * 200 + 100);
    // 3. 点击
    await page.mouse.down();
    await page.waitForTimeout(Math.random() * 100 + 50);
    await page.mouse.up();
    return true;
}

/**
 * Cloudflare 5s 盾穿透逻辑
 * @param {import('playwright').Page} page
 */
async function bypassCloudflare(page) {
    console.log("[RiskControl] Cloudflare Bypass Active");

    // 后台检测循环
    (async () => {
        let attempts = 0;
        // 增加尝试次数和持续时间
        while (!page.isClosed() && attempts < 100) {
            try {
                // 1. 遍历所有 Frame 寻找 Turnstile / Challenge
                const frames = page.frames();
                let clicked = false;

                for (const frame of frames) {
                    // 策略 A: 查找 Shadow DOM 里的 Checkbox
                    // Playwright 的 locator 会自动穿透 open shadow roots
                    // 我们尝试找几个关键特征
                    const indicators = [
                        "input[type='checkbox']",
                        ".ctp-checkbox-label",
                        "#challenge-stage input",
                        // 特定于 Turnstile 的 Shadow DOM 结构
                        "input[name='cf_challenge_response']",
                        // 有些时候是一个带有特定 aria-label 的 div
                        "[aria-label*='Verify you are human']",
                        "[aria-label*='确认您是真人']"
                    ];

                    for (const sel of indicators) {
                        try {
                            const el = frame.locator(sel).first();
                            if (await el.isVisible()) {
                                console.log(`[RiskControl] Found Challenge Element: ${sel}`);
                                const box = await el.boundingBox();
                                if (box) {
                                    console.log(`[RiskControl] Clicking at ${box.x}, ${box.y}`);
                                    await humanClick(page, box);
                                    clicked = true;
                                    await page.waitForTimeout(3000); // 点完等一会
                                    break;
                                }
                            }
                        } catch (e) { }
                    }
                    if (clicked) break;
                }

                if (clicked) {
                    // 如果点过了，多等一会看看过没过，或者是否需要再点
                    await page.waitForTimeout(2000);
                }

                // 2. 检查 Cookie 是否拿到
                const cookies = await page.context().cookies();
                if (cookies.find(c => c.name === 'cf_clearance')) {
                    console.log("[RiskControl] 🎉 CF Clearance Cookie Obtained!");
                    break;
                }

                await page.waitForTimeout(1000);
                attempts++;
            } catch (e) {
                // Ignore transient errors
            }
        }
    })();
}

async function setupRiskControl(page, riskConfig) {
    if (!riskConfig) return;
    if (riskConfig.bypassCF) {
        await bypassCloudflare(page);
    }
}

module.exports = { setupRiskControl };
