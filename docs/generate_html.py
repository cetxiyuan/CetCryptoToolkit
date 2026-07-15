#!/usr/bin/env python3
"""将 CetCryptoToolkit 的 Markdown 文档转换为 HTML。"""
import re, os, sys

# 确保 UTF-8 输出
sys.stdout.reconfigure(encoding='utf-8')

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/cpp.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/json.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/yaml.min.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #fafafa; color: #1e2a3e; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.7; }
#doc-content { max-width: 1000px; margin: 0 auto; padding: 40px 24px; }
h1 { font-size: 2em; margin: 0.8em 0 0.4em; padding-bottom: 0.3em; border-bottom: 2px solid #e2e8f0; color: #1a202c; }
h2 { font-size: 1.5em; margin: 1.2em 0 0.5em; padding-bottom: 0.2em; border-bottom: 1px solid #e2e8f0; color: #2d3748; }
h3 { font-size: 1.2em; margin: 1em 0 0.4em; color: #4a5568; }
h4 { font-size: 1.05em; margin: 0.8em 0 0.3em; color: #4a5568; }
p { margin: 0.6em 0; }
a { color: #3182ce; text-decoration: none; }
a:hover { text-decoration: underline; }
pre { background: #1e1e1e; border-radius: 6px; padding: 16px; overflow-x: auto; margin: 1em 0; }
pre code { color: #abb2bf; font-family: "Cascadia Code", "Fira Code", Consolas, monospace; font-size: 0.9em; line-height: 1.5; }
#doc-content code:not(pre code) { background: #f0f4f8 !important; color: #c7254e !important; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; font-size: 0.9em; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
th, td { border: 1px solid #e2e8f0; padding: 10px 14px; text-align: left; }
th { background: #f6f8fa; font-weight: 600; color: #2d3748; }
tr:nth-child(even) { background: #fafbfc; }
blockquote { border-left: 4px solid #3182ce; padding: 0.5em 1em; margin: 1em 0; background: #f0f7ff; color: #4a5568; }
ul, ol { padding-left: 2em; margin: 0.6em 0; }
li { margin: 0.3em 0; }
hr { border: none; border-top: 1px solid #e2e8f0; margin: 2em 0; }
.copy-btn { position: fixed; top: 16px; right: 24px; padding: 8px 20px; background: #3182ce; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; z-index: 1000; }
.copy-btn:hover { background: #2b6cb0; }
.toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #2d3748; color: #fff; padding: 12px 24px; border-radius: 8px; font-size: 14px; z-index: 2000; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
.toast.show { opacity: 1; }
.code-block-wrapper { position: relative; }
.code-copy-btn { position: absolute; top: 8px; right: 8px; padding: 4px 10px; background: rgba(255,255,255,0.12); color: #abb2bf; border: 1px solid rgba(255,255,255,0.15); border-radius: 4px; cursor: pointer; font-size: 12px; }
.code-copy-btn:hover { background: rgba(255,255,255,0.2); color: #fff; }
.footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; color: #a0aec0; font-size: 0.9em; text-align: center; }
@media (max-width: 768px) { #doc-content { padding: 20px 12px; } pre { padding: 12px; font-size: 0.8em; } }
</style>
</head>
<body>
<button class="copy-btn" onclick="copyFullText()">📋 Copy</button>
<div id="toast" class="toast"></div>
<div id="doc-content">
__BODY__
</div>
<div class="footer"><p>📄 文档转换 · 笔名 CetXiyuan</p></div>
<script>
hljs.highlightAll();

function copyFullText() {{
    var content = document.getElementById("doc-content");
    var text = content.innerText || content.textContent;
    navigator.clipboard.writeText(text).then(function() {{
        showToast("✅ 已复制全文");
    }});
}}

function copyCodeBlock(btn) {{
    var code = btn.parentElement.querySelector("code").textContent;
    navigator.clipboard.writeText(code).then(function() {{
        showToast("✅ 已复制代码");
    }});
}}

function showToast(msg) {{
    var t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(function() {{
        t.classList.remove("show");
    }}, 2000);
}}
</script>
</body>
</html>'''


def parse_frontmatter(text):
    """提取 YAML frontmatter 中的 title"""
    title = ""
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            fm = text[3:end]
            m = re.search(r'title:\s*["\']?(.+?)["\']?\s*$', fm, re.MULTILINE)
            if m:
                title = m.group(1)
            text = text[end + 3:].lstrip()
    return title, text


def code_blocks(md_text):
    """包裹代码块,处理语言标记,添加复制按钮"""
    lines = md_text.split('\n')
    result = []
    in_code = False
    code_buf = []
    lang = ''

    for line in lines:
        m = re.match(r'^```(\w*)\s*$', line)
        if m and not in_code:
            in_code = True
            lang = m.group(1) or ''
            code_buf = []
            continue
        if line == '```' and in_code:
            in_code = False
            code_text = '\n'.join(code_buf)
            escaped = escape_html(code_text)
            cls = f' class="language-{lang}"' if lang else ''
            result.append(f'<div class="code-block-wrapper"><pre><code{cls}>{escaped}</code></pre>')
            result.append('<button class="code-copy-btn" onclick="copyCodeBlock(this)">📋 复制</button></div>')
            continue
        if in_code:
            code_buf.append(line)
        else:
            result.append(line)

    # 未闭合代码块
    if in_code and code_buf:
        escaped = escape_html('\n'.join(code_buf))
        cls = f' class="language-{lang}"' if lang else ''
        result.append(f'<pre><code{cls}>{escaped}</code></pre>')

    return '\n'.join(result)


def escape_html(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def convert_md_to_html(md_text):
    """简单的 Markdown → HTML 转换器"""
    text = md_text.strip()

    # YAML frontmatter
    title, text = parse_frontmatter(text)

    # 代码块处理（先处理，防止误匹配）
    text = code_blocks(text)

    lines = text.split('\n')
    result = []
    in_table = False
    in_list = False
    in_blockquote = False

    for line in lines:
        # 代码块标记（包裹的 div 已由 code_blocks 处理）
        if '<div class="code-block-wrapper">' in line or '</div>' in line:
            result.append(line)
            continue
        if line.startswith('<pre>') or line.startswith('<button'):
            result.append(line)
            continue

        # 水平线
        if re.match(r'^---+\s*$', line):
            result.append('<hr>')
            continue

        # 标题
        m = re.match(r'^(#{1,6})\s+(.+?)\s*$', line)
        if m:
            level = len(m.group(1))
            heading = m.group(2)
            result.append(f'<h{level}>{heading}</h{level}>')
            continue

        # 表格
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                result.append('<table>')
                in_table = True
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if re.match(r'^[\s\-:|]+$', ''.join(cells)):  # 分隔行
                result.append('<thead>')
                header_html = result.pop()  # 上一行是表头
                result.append(header_html)
                result.append('</thead><tbody>')
                continue
            is_header = all(re.match(r'^[\-\s:|]+$', c) for c in cells)
            if not is_header:
                tag = 'th' if ('<thead>' in ''.join(result[-3:]) and '</thead>' not in ''.join(result[-3:])) else 'td'
                row = ''.join(f'<{tag}>{c}</{tag}>' for c in cells)
                result.append(f'<tr>{row}</tr>')
            continue
        else:
            if in_table:
                result.append('</tbody></table>')
                in_table = False

        # 引用块
        m = re.match(r'^>\s?(.*)', line)
        if m:
            if not in_blockquote:
                result.append('<blockquote>')
                in_blockquote = True
            result.append(m.group(1))
            continue
        else:
            if in_blockquote:
                result.append('</blockquote>')
                in_blockquote = False

        # 无序列表
        m = re.match(r'^(\s*)[-*+]\s+(.+)$', line)
        if m:
            if not in_list:
                result.append('<ul>')
                in_list = True
            result.append(f'<li>{m.group(2)}</li>')
            continue

        # 有序列表
        m = re.match(r'^(\s*)\d+\.\s+(.+)$', line)
        if m:
            if not in_list:
                result.append('<ol>')
                in_list = True
            result.append(f'<li>{m.group(2)}</li>')
            continue
        else:
            if in_list:
                tag = '</ul>' if '<ul>' in result[-1] or any('<ul>' in r for r in result[-5:]) else '</ol>'
                result.append(tag)
                in_list = False

        # 空行
        if not line.strip():
            result.append('')
            continue

        # 粗体/斜体
        line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
        line = re.sub(r'\*(.+?)\*', r'<em>\1</em>', line)
        # 行内代码
        line = re.sub(r'`([^`]+)`', r'<code>\1</code>', line)
        # 链接
        line = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', line)

        # 普通段落
        result.append(line)

    # 收尾
    if in_table:
        result.append('</tbody></table>')
    if in_list:
        tag = '</ul>' if any('<ul>' in r for r in result[-5:]) else '</ol>'
        result.append(tag)
    if in_blockquote:
        result.append('</blockquote>')

    # 合并连续行
    html = []
    prev_empty = False
    for line in result:
        is_html_tag = line.strip().startswith('<')
        if not line.strip() and prev_empty:
            continue
        if not line.strip():
            prev_empty = True
        else:
            prev_empty = False

        if not is_html_tag and line.strip():
            html.append(f'<p>{line}</p>')
        else:
            html.append(line)

    body = '\n'.join(html)
    # 修复表格（在 thead 后、tbody 前不需要 p 标签）
    body = re.sub(r'</thead>\s*<p><tr>', '</thead><tr>', body)
    body = re.sub(r'</tr></p>\s*<p><tbody>', '</tr><tbody>', body)

    if not title:
        m = re.search(r'<h1>(.+?)</h1>', body)
        title = m.group(1) if m else "CetCryptoToolkit 文档"

    result = HTML_TEMPLATE
    result = result.replace('__TITLE__', title)
    result = result.replace('__BODY__', body)
    return result


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs_dir = os.path.join(base_dir, "docs")
    html_dir = os.path.join(docs_dir, "html")
    os.makedirs(html_dir, exist_ok=True)

    # MD 文件在 docs/ 目录
    md_files = [
        "CetCryptoToolkit_架构设计.md",
        "CetCryptoToolkit_API参考.md",
        "CetCryptoToolkit_构建与运行指南.md",
        "CetCryptoToolkit_维护者指南.md",
    ]

    for md_file in md_files:
        md_path = os.path.join(docs_dir, md_file)
        if not os.path.exists(md_path):
            print("SKIP: " + md_path + " not found")
            continue

        with open(md_path, 'r', encoding='utf-8') as f:
            md_text = f.read()

        html = convert_md_to_html(md_text)

        html_file = md_file.replace('.md', '.html')
        html_path = os.path.join(html_dir, html_file)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print("OK: " + html_path)

    # README 和 CHANGELOG 在项目根目录
    root_md_files = [
        ("README.md", "README.html"),
        ("CHANGELOG.md", "CHANGELOG.html"),
    ]

    for md_file, html_file in root_md_files:
        md_path = os.path.join(base_dir, md_file)
        if not os.path.exists(md_path):
            print("SKIP: " + md_path + " not found")
            continue

        with open(md_path, 'r', encoding='utf-8') as f:
            md_text = f.read()

        html = convert_md_to_html(md_text)

        html_path = os.path.join(html_dir, html_file)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print("OK: " + html_path)


if __name__ == '__main__':
    main()
