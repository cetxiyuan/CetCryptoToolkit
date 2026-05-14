"""
Markdown → HTML 批量转换脚本
依赖：markdown, pygments
输出：docs/html/
"""
import sys
import io
import os
import re
import shutil

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)          # CetCryptoToolkit/
OUT_DIR = os.path.join(SCRIPT_DIR, 'html')
ASSETS_DIR = os.path.join(OUT_DIR, 'assets')

MD_FILES = [
    os.path.join(ROOT_DIR, 'README.md'),
    os.path.join(ROOT_DIR, 'CHANGELOG.md'),
    os.path.join(SCRIPT_DIR, '软件架构和功能模块说明.md'),
    os.path.join(SCRIPT_DIR, '开发环境搭建指南.md'),
    os.path.join(SCRIPT_DIR, '国密算法使用说明.md'),
    os.path.join(SCRIPT_DIR, '证书管理操作手册.md'),
    os.path.join(SCRIPT_DIR, 'API参考手册.md'),
]

os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
/* ===== 页面主体 ===== */
*, *::before, *::after {{ box-sizing: border-box; }}
body {{
  margin: 0;
  padding: 24px 16px 60px;
  background: #fafafa;
  color: #1e2a3e;
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  font-size: 15px;
  line-height: 1.75;
}}
#doc-wrap {{
  max-width: 1000px;
  margin: 0 auto;
  background: #ffffff;
  border-radius: 8px;
  padding: 40px 48px 48px;
  box-shadow: 0 2px 12px rgba(0,0,0,.06);
  position: relative;
}}
/* ===== 标题 ===== */
h1,h2,h3,h4,h5,h6 {{
  color: #1e2a3e;
  margin-top: 1.6em;
  margin-bottom: .5em;
  line-height: 1.3;
}}
h1 {{ font-size: 2em; border-bottom: 2px solid #e2e8f0; padding-bottom: .3em; }}
h2 {{ font-size: 1.5em; border-bottom: 1px solid #e2e8f0; padding-bottom: .2em; }}
h3 {{ font-size: 1.2em; }}
/* ===== 段落 / 链接 ===== */
p {{ margin: .6em 0 .9em; }}
a {{ color: #2563eb; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
/* ===== 引用块 ===== */
blockquote {{
  margin: 1em 0;
  padding: 10px 20px;
  background: #f6f8fa;
  border-left: 4px solid #94a3b8;
  color: #475569;
  border-radius: 0 4px 4px 0;
}}
blockquote p {{ margin: 0; }}
/* ===== 表格 ===== */
table {{
  width: 100%;
  border-collapse: collapse;
  margin: 1em 0;
  font-size: .93em;
}}
th,td {{
  border: 1px solid #e2e8f0;
  padding: 8px 14px;
  text-align: left;
}}
th {{
  background: #f6f8fa;
  font-weight: 600;
  color: #1e2a3e;
}}
tr:nth-child(even) td {{ background: #fafafa; }}
/* ===== 列表 ===== */
ul,ol {{ padding-left: 1.6em; margin: .5em 0 .9em; }}
li {{ margin: .3em 0; }}
/* ===== 行内代码 ===== */
#doc-content code:not(pre code) {{
  background: #f0f4f8 !important;
  color: #c7254e !important;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: .88em;
  font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
}}
/* ===== 代码块容器 ===== */
#doc-content pre {{
  position: relative;
  margin: 1em 0;
  border-radius: 6px;
  overflow-x: auto;
}}
#doc-content pre code {{
  display: block;
  padding: 16px 18px;
  font-size: .88em;
  font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
  line-height: 1.6;
  background: #1e1e1e !important;
  color: #abb2bf;  /* 默认浅灰，pygments 着色后会覆盖 */
  border-radius: 6px;
}}
/* ===== Pygments 语法高亮（one-dark 风格） ===== */
.codehilite {{ margin: 0; }}
.codehilite pre {{ margin: 0; }}
.hll {{ background-color: #49483e }}
.c  {{ color: #75715e }} /* 注释 */
.err{{ color: #960050; background-color: #1e0010 }}
.k  {{ color: #66d9ef }} /* 关键字 */
.l  {{ color: #ae81ff }}
.n  {{ color: #f8f8f2 }}
.o  {{ color: #f92672 }} /* 运算符 */
.p  {{ color: #f8f8f2 }}
.cm {{ color: #75715e }}
.cp {{ color: #75715e }}
.c1 {{ color: #75715e }}
.cs {{ color: #75715e }}
.ge {{ font-style: italic }}
.gs {{ font-weight: bold }}
.kc {{ color: #66d9ef }}
.kd {{ color: #66d9ef }}
.kn {{ color: #f92672 }}
.kp {{ color: #66d9ef }}
.kr {{ color: #66d9ef }}
.kt {{ color: #66d9ef }}
.ld {{ color: #e6db74 }}
.m  {{ color: #ae81ff }} /* 数字 */
.s  {{ color: #e6db74 }} /* 字符串 */
.na {{ color: #a6e22e }}
.nb {{ color: #f8f8f2 }}
.nc {{ color: #a6e22e }}
.no {{ color: #66d9ef }}
.nd {{ color: #a6e22e }}
.ni {{ color: #f8f8f2 }}
.ne {{ color: #a6e22e }}
.nf {{ color: #a6e22e }} /* 函数名 */
.nl {{ color: #f8f8f2 }}
.nn {{ color: #f8f8f2 }}
.nx {{ color: #a6e22e }}
.py {{ color: #f8f8f2 }}
.nt {{ color: #f92672 }}
.nv {{ color: #f8f8f2 }}
.ow {{ color: #f92672 }}
.w  {{ color: #f8f8f2 }}
.mf {{ color: #ae81ff }}
.mh {{ color: #ae81ff }}
.mi {{ color: #ae81ff }}
.mo {{ color: #ae81ff }}
.sb {{ color: #e6db74 }}
.sc {{ color: #e6db74 }}
.sd {{ color: #e6db74 }}
.s2 {{ color: #e6db74 }}
.se {{ color: #ae81ff }}
.sh {{ color: #e6db74 }}
.si {{ color: #e6db74 }}
.sx {{ color: #e6db74 }}
.sr {{ color: #e6db74 }}
.s1 {{ color: #e6db74 }}
.ss {{ color: #e6db74 }}
.bp {{ color: #f8f8f2 }}
.vc {{ color: #f8f8f2 }}
.vg {{ color: #f8f8f2 }}
.vi {{ color: #f8f8f2 }}
.il {{ color: #ae81ff }}

/* ===== 复制按钮（代码块） ===== */
.copy-code-btn {{
  position: absolute;
  top: 8px;
  right: 10px;
  background: rgba(255,255,255,.12);
  color: #cdd6f4;
  border: 1px solid rgba(255,255,255,.2);
  border-radius: 4px;
  padding: 2px 8px;
  font-size: .78em;
  cursor: pointer;
  opacity: 0;
  transition: opacity .2s, background .2s;
  z-index: 10;
  user-select: none;
}}
#doc-content pre:hover .copy-code-btn {{ opacity: 1; }}
.copy-code-btn:hover {{ background: rgba(255,255,255,.25); }}

/* ===== 全文复制按钮 ===== */
#copy-all-btn {{
  position: fixed;
  top: 20px;
  right: 28px;
  background: #2563eb;
  color: #fff;
  border: none;
  border-radius: 6px;
  padding: 7px 16px;
  font-size: .88em;
  cursor: pointer;
  box-shadow: 0 2px 8px rgba(37,99,235,.35);
  transition: background .2s;
  z-index: 100;
}}
#copy-all-btn:hover {{ background: #1d4ed8; }}

/* ===== 复制提示浮层 ===== */
#copy-toast {{
  position: fixed;
  bottom: 36px;
  left: 50%;
  transform: translateX(-50%);
  background: #1e2a3e;
  color: #e2e8f0;
  padding: 10px 24px;
  border-radius: 24px;
  font-size: .9em;
  opacity: 0;
  pointer-events: none;
  transition: opacity .3s;
  z-index: 200;
}}
#copy-toast.show {{ opacity: 1; }}

/* ===== 页脚 ===== */
#doc-footer {{
  text-align: center;
  margin-top: 48px;
  color: #94a3b8;
  font-size: .85em;
  border-top: 1px solid #e2e8f0;
  padding-top: 20px;
}}

/* ===== 响应式 ===== */
@media (max-width: 720px) {{
  #doc-wrap {{ padding: 24px 18px 36px; }}
  #copy-all-btn {{ top: 10px; right: 12px; padding: 5px 10px; font-size: .8em; }}
}}
</style>
</head>
<body>

<button id="copy-all-btn" onclick="copyAll()">Copy</button>
<div id="copy-toast"></div>

<div id="doc-wrap">
  <div id="doc-content">
{body}
  </div>
  <div id="doc-footer">📄 文档转换 · 笔名 CetXiyuan</div>
</div>

<script>
// ---- 全文复制 ----
function copyAll() {{
  const el = document.getElementById('doc-content');
  // 递归提取文本，保留换行结构
  function extractText(node) {{
    if (node.nodeType === Node.TEXT_NODE) return node.textContent;
    const tag = node.tagName ? node.tagName.toLowerCase() : '';
    if (tag === 'button') return '';
    let text = '';
    for (const child of node.childNodes) text += extractText(child);
    if (['p','h1','h2','h3','h4','h5','h6','li','tr','pre','blockquote','div'].includes(tag))
      text = text.trimEnd() + '\\n';
    if (['h1','h2','h3'].includes(tag)) text += '\\n';
    return text;
  }}
  const raw = extractText(el).replace(/\\n{{3,}}/g, '\\n\\n').trim();
  navigator.clipboard.writeText(raw).then(() => toast('✅ 已复制全文'));
}}

// ---- 代码块复制 ----
document.querySelectorAll('#doc-content pre').forEach(pre => {{
  const btn = document.createElement('button');
  btn.className = 'copy-code-btn';
  btn.textContent = '📋 复制';
  btn.onclick = () => {{
    const code = pre.querySelector('code');
    navigator.clipboard.writeText(code ? code.innerText : pre.innerText)
      .then(() => toast('✅ 已复制代码'));
  }};
  pre.style.position = 'relative';
  pre.appendChild(btn);
}});

// ---- 提示浮层 ----
function toast(msg) {{
  const el = document.getElementById('copy-toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2000);
}}
</script>
</body>
</html>
"""


def strip_frontmatter(text):
    """去除 YAML Frontmatter，返回 (title, body)"""
    title = ''
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
    if m:
        fm = m.group(1)
        tm = re.search(r'^title\s*:\s*(.+)$', fm, re.MULTILINE)
        if tm:
            title = tm.group(1).strip().strip('"\'')
        text = text[m.end():]
    return title, text


def fix_markdown(text):
    """修复常见 Markdown 格式问题，跳过代码块内容"""
    lines = text.split('\n')
    result = []
    in_fence = False
    fence_marker = ''
    for line in lines:
        # 检测代码块开始/结束（``` 或 ~~~）
        m = re.match(r'^(`{3,}|~{3,})', line)
        if m:
            marker = m.group(1)[0] * 3  # 统一取前3字符类型
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif line.strip().startswith(fence_marker):
                in_fence = False
                fence_marker = ''
            result.append(line)
            continue
        if in_fence:
            result.append(line)
            continue
        # 仅对非代码块行做修复
        # #标题 → # 标题（1~6个#后无空格，且下一字符不是#，排除 #include 等7+字符序列）
        line = re.sub(r'^(#{1,6})([^\s#])', r'\1 \2', line)
        # -条目 → - 条目
        line = re.sub(r'^(-|\*)([^\s\-\*])', r'\1 \2', line)
        result.append(line)
    return '\n'.join(result)


def copy_images(md_text, md_file, out_html):
    """将 MD 中本地图片复制到 assets，并更新路径"""
    md_dir = os.path.dirname(md_file)

    def replace_img(m):
        alt, path = m.group(1), m.group(2)
        if path.startswith('http://') or path.startswith('https://'):
            return m.group(0)
        abs_img = os.path.normpath(os.path.join(md_dir, path))
        if os.path.isfile(abs_img):
            rel = os.path.relpath(abs_img, md_dir)
            dst_name = rel.replace(os.sep, '_')
            dst = os.path.join(ASSETS_DIR, dst_name)
            shutil.copy2(abs_img, dst)
            # 相对于 html 输出目录
            new_path = os.path.relpath(dst, OUT_DIR).replace(os.sep, '/')
            return f'![{alt}]({new_path})'
        return m.group(0)

    return re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', replace_img, md_text)


def md_to_html(md_file):
    with open(md_file, encoding='utf-8') as f:
        raw = f.read()

    fm_title, body = strip_frontmatter(raw)
    body = fix_markdown(body)
    body = copy_images(body, md_file, OUT_DIR)

    # 从第一个 # 标题提取 title（若 frontmatter 没有）
    if not fm_title:
        m = re.search(r'^#\s+(.+)$', body, re.MULTILINE)
        fm_title = m.group(1).strip() if m else os.path.splitext(os.path.basename(md_file))[0]

    html_body = markdown.markdown(
        body,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, guess_lang=True, noclasses=False),
            TableExtension(),
            TocExtension(baselevel=1),
            'nl2br',
            'sane_lists',
        ]
    )

    page = HTML_TEMPLATE.format(title=fm_title, body=html_body)

    out_name = os.path.splitext(os.path.basename(md_file))[0] + '.html'
    out_path = os.path.join(OUT_DIR, out_name)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(page)
    print(f'  → {out_path}')
    return out_path


print(f'输出目录: {OUT_DIR}')
for md in MD_FILES:
    if os.path.isfile(md):
        print(f'转换: {os.path.basename(md)}')
        md_to_html(md)
    else:
        print(f'跳过（不存在）: {md}')

print('\n全部完成。')
