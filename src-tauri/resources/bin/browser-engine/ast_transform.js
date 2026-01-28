const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');
const UglifyJS = require('uglify-js');
const swc = require('@swc/core');

/**
 * Babel 深度 AST 还原 (保留之前的最强逻辑)
 */
function babelDeobfuscate(code) {
    try {
        const ast = parser.parse(code, {
            sourceType: 'module',
            plugins: ['jsx', 'typescript']
        });

        const MAX_LOOPS = 15;
        for (let i = 0; i < MAX_LOOPS; i++) {
            let changed = false;

            traverse(ast, {
                // ... (保留之前的全部策略) ...
                // 策略 A: 字符串
                StringLiteral(path) {
                    if (path.node.extra && /\\x|\\u/.test(path.node.extra.raw)) {
                        delete path.node.extra;
                        changed = true;
                    }
                },
                // 策略 B: 数字
                NumericLiteral(path) {
                    if (path.node.extra) {
                        delete path.node.extra;
                        changed = true;
                    }
                },
                // 策略 C: 常量折叠 (含逻辑运算)
                "BinaryExpression|UnaryExpression|LogicalExpression"(path) {
                    try {
                        const { confident, value } = path.evaluate();
                        if (confident) {
                            if (value === Infinity || value === -Infinity || Number.isNaN(value)) return;
                            if (typeof value === 'number') { path.replaceWith(t.numericLiteral(value)); changed = true; }
                            else if (typeof value === 'string') { path.replaceWith(t.stringLiteral(value)); changed = true; }
                            else if (typeof value === 'boolean') { path.replaceWith(t.booleanLiteral(value)); changed = true; }
                            else if (value === null) { path.replaceWith(t.nullLiteral()); changed = true; }
                        }
                    } catch (e) { }
                },
                // 策略 D: 成员访问优化
                MemberExpression(path) {
                    const { property, computed, object } = path.node;
                    // Obj.prop
                    if (computed && t.isStringLiteral(property)) {
                        const propName = property.value;
                        if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName)) {
                            path.node.property = t.identifier(propName);
                            path.node.computed = false;
                            changed = true;
                        }
                    }
                    // {a:1}['a'] -> 1
                    if (t.isObjectExpression(object)) {
                        let keyName = null;
                        if (computed && t.isStringLiteral(property)) keyName = property.value;
                        else if (!computed && t.isIdentifier(property)) keyName = property.name;
                        if (keyName) {
                            const prop = object.properties.find(p => t.isObjectProperty(p) && ((t.isIdentifier(p.key) && p.key.name === keyName) || (t.isStringLiteral(p.key) && p.key.value === keyName)));
                            if (prop && prop.value) { path.replaceWith(t.cloneNode(prop.value)); changed = true; return; }
                        }
                    }
                    // 变量内联
                    if (t.isIdentifier(object)) {
                        const binding = path.scope.getBinding(object.name);
                        if (binding && binding.path.isVariableDeclarator()) {
                            const init = binding.path.node.init;
                            if (t.isArrayExpression(init) && computed && t.isNumericLiteral(property)) {
                                const el = init.elements[property.value];
                                if (el && (t.isLiteral(el) || t.isObjectExpression(el) || t.isArrayExpression(el))) { path.replaceWith(t.cloneNode(el)); changed = true; }
                            } else if (t.isObjectExpression(init)) {
                                let keyName = null;
                                if (computed && t.isStringLiteral(property)) keyName = property.value;
                                else if (!computed && t.isIdentifier(property)) keyName = property.name;
                                if (keyName) {
                                    const prop = init.properties.find(p => t.isObjectProperty(p) && ((t.isIdentifier(p.key) && p.key.name === keyName) || (t.isStringLiteral(p.key) && p.key.value === keyName)));
                                    if (prop && prop.value && (t.isLiteral(prop.value) || t.isObjectExpression(prop.value) || t.isArrayExpression(prop.value))) { path.replaceWith(t.cloneNode(prop.value)); changed = true; }
                                }
                            }
                        }
                    }
                },
                // 策略 G: 三元
                ConditionalExpression(path) {
                    const testEval = path.get('test').evaluate();
                    if (testEval.confident) {
                        path.replaceWith(testEval.value ? path.node.consequent : path.node.alternate);
                        changed = true;
                    }
                },
                // 策略 E/F
                EmptyStatement(path) { path.remove(); changed = true; },
                SequenceExpression(path) {
                    if (path.node.expressions.length === 2 && t.isNumericLiteral(path.node.expressions[0]) && path.node.expressions[0].value === 0) {
                        path.replaceWith(path.node.expressions[1]); changed = true;
                    }
                }
            });
            if (!changed) break;
        }

        // 死代码移除
        traverse(ast, {
            VariableDeclarator(path) {
                const { id } = path.node;
                if (t.isIdentifier(id)) {
                    const binding = path.scope.getBinding(id.name);
                    // 只删除未被引用的数组/对象 (安全模式)
                    if (binding && binding.referencePaths.length === 0) {
                        const init = path.node.init;
                        if (t.isArrayExpression(init) || t.isObjectExpression(init)) path.remove();
                    }
                }
            }
        });

        const output = generate(ast, { jsescOption: { minimal: true } });
        return output.code;
    } catch (e) {
        throw new Error(`Babel Error: ${e.message}`);
    }
}

/**
 * SWC 极速格式化/压缩
 */
function swcDeobfuscate(code) {
    try {
        // SWC 主要优势是快。在“混淆还原”场景，它主要能做的是格式化和基础的死代码消除/常量折叠（取决于 minification 配置）
        // 这里我们配置它做代码美化 (minify: false)
        // 如果想利用 SWC 做一些优化，可以开 minify: true 但关闭 mangle
        const output = swc.transformSync(code, {
            jsc: {
                parser: { syntax: "ecmascript" },
                target: "es2022",
                minify: {
                    compress: {
                        unused: true,
                        dead_code: true,
                        loops: true,
                        conditionals: true
                    },
                    mangle: false // 不混淆变量名
                }
            },
            minify: false, // 整体 minify 关掉，只用 compress 里的选项？不，swc transformSync 的 minify 选项控制是否输出压缩代码
            // 实际上为了“还原”，我们希望输出格式化好的代码
        });

        // 由于 SWC API 复杂，简单的用法是先 transform 再 print，或者直接用它的 printSync
        // 为了稳定，我们直接用 SWC 的解析和生成能力来做 "Format"
        // 实际上 swc.printSync(swc.parseSync(code)) 会非常快地格式化代码
        return swc.printSync(swc.parseSync(code, { syntax: "ecmascript" }), { minify: false }).code;
    } catch (e) {
        // Fallback manual formatting if SWC fails (e.g. syntax error)
        throw new Error(`SWC Error: ${e.message}`);
    }
}

/**
 * UglifyJS 代码美化
 */
function uglifyDeobfuscate(code) {
    try {
        const result = UglifyJS.minify(code, {
            mangle: false,
            compress: {
                booleans: true,
                conditionals: true,
                dead_code: true,
                evaluate: true,
                if_return: true,
                join_vars: false,
                sequences: false, // 保持逗号表达式展开
                unused: true
            },
            output: {
                beautify: true, // 核心：美化输出
                comments: true
            }
        });
        if (result.error) throw result.error;
        return result.code;
    } catch (e) {
        throw new Error(`UglifyJS Error: ${e.message}`);
    }
}

/**
 * 主入口
 */
function deobfuscate(code, engine = 'babel') {
    if (!code) return '';

    switch (engine) {
        case 'swc':
            return swcDeobfuscate(code);
        case 'ugly':
            return uglifyDeobfuscate(code);
        case 'babel':
        default:
            return babelDeobfuscate(code);
    }
}

module.exports = { deobfuscate };