#!/usr/bin/env python
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "renders" / "dashboard-refined.html"
TEMPLATE = ROOT / "tools" / "dashboard-template.html"

if not HTML.exists(): sys.exit(f"missing {HTML}")
html = HTML.read_text(encoding="utf-8")

# milestone rows → placeholder
first_phase = html.find('<div class="phase">')
section_close = html.find('</section>', first_phase)
if first_phase > 0 and section_close > first_phase:
    html = html[:first_phase] + '{{MILESTONE_ROWS}}\n    ' + html[section_close:]

# work bar label (no id)
html = re.sub(r'(<div class="bar-val">)[\d.]+%', r'\g<1>{{WORK_PCT}}%', html, count=1)
# JS WORK_PCT
html = re.sub(r'var WORK_PCT = [\d.]+;', 'var WORK_PCT = {{WORK_PCT}};', html)
# target display
html = re.sub(r'(<div class="target-date">)[0-9A-Z-]+</div>', r'\g<1>{{TARGET_DISPLAY}}</div>', html, count=1)
# header timestamp
html = re.sub(r'(<div class="timestamp">)[0-9A-Z-]+ [\d:]+</div>', r'\g<1>{{CREATED_DISPLAY}}</div>', html, count=1)
# JS CREATION / TARGET
html = re.sub(r"var CREATION = Date\.UTC\([^)]+\);", "var CREATION = Date.parse('{{CREATION_ISO}}Z');", html)
html = re.sub(r"var TARGET\s*=\s*Date\.UTC\([^)]+\);", "var TARGET = Date.parse('{{TARGET_ISO}}Z');", html)

TEMPLATE.write_text(html, encoding="utf-8")
print(f"wrote {TEMPLATE} ({len(html)} chars)")
for ph in sorted(set(re.findall(r'\{\{[A-Z_]+\}\}', html))):
    print(f"  placeholder: {ph}")