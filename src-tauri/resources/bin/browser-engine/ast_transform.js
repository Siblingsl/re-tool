const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

/**
 * 执行 AST 还原
 * @param {string} code - 混淆的源代码
 * @returns {string} - 还原后的代码
 */
function deobfuscate(code) {
    if (!code) return '';

    try {
        // 1. 解析成 AST
        const ast = parser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript'] // 支持更多语法
        });

        // 2. 遍历并修改 AST (Visitor 模式)
        traverse(ast, {
            // --- 策略 A: 十六进制/Unicode 字符串还原 ---
            // 例如: "\x61" -> "a"
            StringLiteral(path) {
                if (path.node.extra && /\\x|\\u/.test(path.node.extra.raw)) {
                    delete path.node.extra; // 删除原始格式，生成器会使用默认格式(正常字符串)
                }
            },
            
            // --- 策略 B: 数字常量还原 ---
            // 例如: 0x10 -> 16
            NumericLiteral(path) {
                if (path.node.extra) {
                    delete path.node.extra;
                }
            },

            // --- 策略 C: 常量折叠 (计算简单的表达式) ---
            // 例如: "a" + "b" -> "ab", 1 + 2 -> 3, !![] -> true
            "BinaryExpression|UnaryExpression"(path) {
                const { confident, value } = path.evaluate(); // Babel 自带的强大求值器
                if (confident) {
                    // 特殊处理：避免把 Infinity 或 NaN 变成字符串
                    if (value === Infinity || value === -Infinity || Number.isNaN(value)) return;
                    
                    // 创建对应的字面量节点替换原表达式
                    if (typeof value === 'number') {
                        path.replaceWith(t.numericLiteral(value));
                    } else if (typeof value === 'string') {
                        path.replaceWith(t.stringLiteral(value));
                    } else if (typeof value === 'boolean') {
                        path.replaceWith(t.booleanLiteral(value));
                    }
                }
            },

            // --- 策略 D: 属性访问简化 ---
            // 例如: window['location'] -> window.location
            MemberExpression(path) {
                const { property, computed } = path.node;
                if (computed && t.isStringLiteral(property)) {
                    const propName = property.value;
                    // 检查是否是合法的标识符 (例如 "123" 不能转为 .123, "a-b" 不能转为 .a-b)
                    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName)) {
                        path.node.property = t.identifier(propName);
                        path.node.computed = false;
                    }
                }
            },

            // --- 策略 E: 移除空语句 ---
            // 例如: ;;;
            EmptyStatement(path) {
                path.remove();
            },
            
            // --- 策略 F: 还原常见的逗号表达式序列 ---
            // (0, func)(args) -> func(args)
            SequenceExpression(path) {
                const expressions = path.node.expressions;
                if (expressions.length === 2 && t.isNumericLiteral(expressions[0]) && expressions[0].value === 0) {
                    path.replaceWith(expressions[1]);
                }
            }
        });

        // 3. 生成代码
        // jsescOption: minimal 确保中文不被转义
        const output = generate(ast, { jsescOption: { minimal: true } });
        return output.code;

    } catch (e) {
        throw new Error(`AST Parse Error: ${e.message}`);
    }
}

module.exports = { deobfuscate };