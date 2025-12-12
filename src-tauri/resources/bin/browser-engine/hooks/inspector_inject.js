// 这是一个自包含的拾取器逻辑，将被注入到浏览器页面中
module.exports = `
(function() {
    if (window.__weblab_inspector_active) return;
    window.__weblab_inspector_active = true;

    // 1. 创建高亮遮罩层
    const overlay = document.createElement('div');
    overlay.style.position = 'absolute'; 
    overlay.style.pointerEvents = 'none'; 
    overlay.style.zIndex = '2147483647';
    overlay.style.border = '2px solid #ff4d4f';
    overlay.style.backgroundColor = 'rgba(255, 77, 79, 0.1)';
    overlay.style.boxSizing = 'border-box';
    overlay.style.transition = 'all 0.05s';
    overlay.style.display = 'none';
    overlay.id = '__weblab_inspector_overlay__';
    document.documentElement.appendChild(overlay);

    // 显示 Tooltip
    const tooltip = document.createElement('div');
    tooltip.style.position = 'absolute';
    tooltip.style.zIndex = '2147483647';
    tooltip.style.backgroundColor = '#222';
    tooltip.style.color = '#fff';
    tooltip.style.padding = '4px 8px';
    tooltip.style.borderRadius = '4px';
    tooltip.style.fontSize = '12px';
    tooltip.style.pointerEvents = 'none';
    tooltip.style.display = 'none';
    tooltip.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
    tooltip.style.whiteSpace = 'nowrap';
    document.documentElement.appendChild(tooltip);

    let lastElement = null;

    // 2. 生成 Playwright Selector 的智能算法
    function getSelector(el) {
        if (!el) return '';
        
        // 策略 1: ID (最强)
        // 排除看起来像随机生成的 ID (包含数字且长度>10)
        if (el.id && !/\d/.test(el.id)) return \`#\${el.id}\`;
        
        const tagName = el.tagName.toLowerCase();

        // 策略 2: 关键属性 (name, placeholder, type)
        const name = el.getAttribute('name');
        const placeholder = el.getAttribute('placeholder');
        const type = el.getAttribute('type');
        const dataTestId = el.getAttribute('data-testid') || el.getAttribute('data-test-id');

        if (dataTestId) return \`[data-testid="\${dataTestId}"]\`;
        
        if (tagName === 'input') {
            if (name) return \`input[name="\${name}"]\`;
            if (placeholder) return \`input[placeholder="\${placeholder}"]\`;
            if (type) return \`input[type="\${type}"]\`;
        }

        // 策略 3: Text (如果是按钮或链接)
        // Playwright 的 text= 引擎非常强大，优先使用
        if ((tagName === 'button' || tagName === 'a' || tagName === 'span' || tagName === 'div') && el.innerText.trim().length > 0 && el.innerText.trim().length < 20) {
            // 确保没有子元素干扰
            if (el.children.length === 0) return \`text=\${el.innerText.trim()}\`;
        }

        // 策略 4: Class 组合 (降级使用)
        // 过滤掉框架生成的垃圾 Class (如 ng-untouched, css-1x2y3z)
        if (el.className && typeof el.className === 'string') {
            const classes = el.className.split(' ')
                .filter(c => c.trim().length > 0)
                .filter(c => !c.startsWith('ng-')) // 过滤 Angular
                .filter(c => !c.startsWith('css-')) // 过滤 Emotion/Styled
                .filter(c => !/^s-\w+/.test(c)) // 过滤 Svelte
                .filter(c => !/^\d/.test(c)); // 过滤数字开头

            if (classes.length > 0) {
                // 只取前两个最有意义的 class，防止过长
                return \`\${tagName}.\${classes.slice(0, 2).join('.')}\`;
            }
        }

        // 策略 5: 降级到 nth-child (最弱但通用)
        if (el.parentElement) {
            const siblings = Array.from(el.parentElement.children);
            const index = siblings.indexOf(el) + 1;
            // 如果父元素只有一个子元素，不需要 nth-child
            if (siblings.length === 1) return tagName;
            return \`\${tagName}:nth-child(\${index})\`;
        }

        return tagName;
    }

    // 3. 鼠标移动事件
    function onMouseOver(e) {
        e.preventDefault();
        e.stopPropagation();
        
        const el = e.target;
        if (el === overlay || el === tooltip || el.id === '__weblab_inspector_overlay__') return;
        
        lastElement = el;
        const rect = el.getBoundingClientRect();
        
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const scrollLeft = window.scrollX || document.documentElement.scrollLeft;

        overlay.style.display = 'block';
        overlay.style.top = (rect.top + scrollTop) + 'px';
        overlay.style.left = (rect.left + scrollLeft) + 'px';
        overlay.style.width = rect.width + 'px';
        overlay.style.height = rect.height + 'px';

        const selector = getSelector(el);
        tooltip.style.display = 'block';
        
        let tooltipTop = rect.top + scrollTop - 30;
        if (rect.top < 30) tooltipTop = rect.bottom + scrollTop + 5;
        
        tooltip.style.top = tooltipTop + 'px';
        tooltip.style.left = (rect.left + scrollLeft) + 'px';
        tooltip.innerText = selector;
    }

    // 4. 点击事件
    function onClick(e) {
        e.preventDefault();
        e.stopPropagation(); 

        if (lastElement && window.__weblab_onPick) {
            const selector = getSelector(lastElement);
            window.__weblab_onPick(selector);
        }
        
        cleanup();
    }

    function cleanup() {
        document.removeEventListener('mouseover', onMouseOver, true);
        document.removeEventListener('click', onClick, true);
        if (overlay) overlay.remove();
        if (tooltip) tooltip.remove();
        window.__weblab_inspector_active = false;
    }

    document.addEventListener('mouseover', onMouseOver, true);
    document.addEventListener('click', onClick, true);

    console.log('[Inspector] 智能拾取模式已开启...');
})();
`;
