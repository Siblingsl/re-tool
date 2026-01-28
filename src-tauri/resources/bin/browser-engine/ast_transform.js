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
        const ast = parser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript']
        });

        const MAX_LOOPS = 15; // 增加循环次数以应对深度嵌套
        for (let i = 0; i < MAX_LOOPS; i++) {
            let changed = false;

            traverse(ast, {
                // --- 策略 A: 十六进制/Unicode 字符串还原 ---
                StringLiteral(path) {
                    if (path.node.extra && /\\x|\\u/.test(path.node.extra.raw)) {
                        delete path.node.extra;
                        changed = true;
                    }
                },

                // --- 策略 B: 数字常量还原 ---
                NumericLiteral(path) {
                    if (path.node.extra) {
                        delete path.node.extra;
                        changed = true;
                    }
                },

                // --- 策略 C: 常量折叠 ---
                "BinaryExpression|UnaryExpression|LogicalExpression"(path) {
                    try {
                        const { confident, value } = path.evaluate();
                        if (confident) {
                            if (value === Infinity || value === -Infinity || Number.isNaN(value)) return;

                            if (typeof value === 'number') {
                                path.replaceWith(t.numericLiteral(value));
                                changed = true;
                            } else if (typeof value === 'string') {
                                path.replaceWith(t.stringLiteral(value));
                                changed = true;
                            } else if (typeof value === 'boolean') {
                                path.replaceWith(t.booleanLiteral(value));
                                changed = true;
                            } else if (value === null) {
                                path.replaceWith(t.nullLiteral());
                                changed = true;
                            }
                        }
                    } catch (e) { }
                },

                // --- 策略 D: 属性访问简化 & 数组/对象内联 ---
                MemberExpression(path) {
                    const { property, computed, object } = path.node;

                    // 1. 点符号优化: obj['prop'] -> obj.prop
                    if (computed && t.isStringLiteral(property)) {
                        const propName = property.value;
                        if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName)) {
                            path.node.property = t.identifier(propName);
                            path.node.computed = false;
                            changed = true;
                        }
                    }

                    // 2. 字面量对象访问优化: ({a:1})['a'] -> 1
                    if (t.isObjectExpression(object)) {
                        let keyName = null;
                        if (computed && t.isStringLiteral(property)) keyName = property.value;
                        else if (!computed && t.isIdentifier(property)) keyName = property.name;

                        if (keyName) {
                            const prop = object.properties.find(p => t.isObjectProperty(p) && (
                                (t.isIdentifier(p.key) && p.key.name === keyName) ||
                                (t.isStringLiteral(p.key) && p.key.value === keyName)
                            ));
                            if (prop && prop.value) {
                                path.replaceWith(t.cloneNode(prop.value));
                                changed = true;
                                return;
                            }
                        }
                    }

                    // 3. 变量引用的数组/对象内联
                    if (t.isIdentifier(object)) {
                        const binding = path.scope.getBinding(object.name);
                        // 移除 .constant 检查，因为某些混淆可能会让 babel 误判，
                        // 但对于这种定义后立即使用的模式，只要是 VariableDeclarator 且有 init，我们就可以尝试内联。
                        if (binding && binding.path.isVariableDeclarator()) {
                            const init = binding.path.node.init;

                            // 3.1 数组: arr[0] -> element
                            if (t.isArrayExpression(init)) {
                                if (computed && t.isNumericLiteral(property)) {
                                    const idx = property.value;
                                    if (idx >= 0 && idx < init.elements.length) {
                                        const el = init.elements[idx];
                                        // 允许内联字面量、对象、数组
                                        if (t.isLiteral(el) || t.isObjectExpression(el) || t.isArrayExpression(el)) {
                                            path.replaceWith(t.cloneNode(el));
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            // 3.2 对象: obj['key'] -> value
                            else if (t.isObjectExpression(init)) {
                                let keyName = null;
                                if (computed && t.isStringLiteral(property)) keyName = property.value;
                                else if (!computed && t.isIdentifier(property)) keyName = property.name;

                                if (keyName) {
                                    const prop = init.properties.find(p => t.isObjectProperty(p) && (
                                        (t.isIdentifier(p.key) && p.key.name === keyName) ||
                                        (t.isStringLiteral(p.key) && p.key.value === keyName)
                                    ));
                                    if (prop && prop.value) {
                                        // 同样允许内联复杂结构
                                        if (t.isLiteral(prop.value) || t.isObjectExpression(prop.value) || t.isArrayExpression(prop.value)) {
                                            path.replaceWith(t.cloneNode(prop.value));
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                },

                // --- 策略 G: 三元表达式简化 ---
                ConditionalExpression(path) {
                    const { test, consequent, alternate } = path.node;
                    // 尝试求值 test
                    const testEval = path.get('test').evaluate();
                    if (testEval.confident) {
                        if (testEval.value) {
                            path.replaceWith(consequent);
                            changed = true;
                        } else {
                            path.replaceWith(alternate);
                            changed = true;
                        }
                    }
                },

                // --- 策略 E: 移除空语句 ---
                EmptyStatement(path) {
                    path.remove();
                    changed = true;
                },

                // --- 策略 F: 逗号表达式还原 ---
                SequenceExpression(path) {
                    const expressions = path.node.expressions;
                    if (expressions.length === 2 && t.isNumericLiteral(expressions[0]) && expressions[0].value === 0) {
                        path.replaceWith(expressions[1]);
                        changed = true;
                    }
                }
            });

            if (!changed) break;
        }

        // --- 策略 Z: 死代码移除 (最后执行) ---
        traverse(ast, {
            VariableDeclarator(path) {
                const { id } = path.node;
                if (t.isIdentifier(id)) {
                    const binding = path.scope.getBinding(id.name);
                    if (binding && binding.referencePaths.length === 0) {
                        const init = path.node.init;
                        // 仅移除纯数组/对象定义
                        // 保留 Literal, Function, Call 等
                        if (t.isArrayExpression(init) || t.isObjectExpression(init)) {
                            path.remove();
                        }
                    }
                }
            }
        });

        const output = generate(ast, { jsescOption: { minimal: true } });
        return output.code;

    } catch (e) {
        throw new Error(`AST Parse Error: ${e.message}`);
    }
}

module.exports = { deobfuscate };