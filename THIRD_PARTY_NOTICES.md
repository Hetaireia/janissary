# Third-Party Notices

JANISSARY's credential-detection rule set in `src/janissary/credentials/rules.py`
derives from two MIT-licensed projects. Their licence texts are reproduced below,
as MIT requires.

What derives from where:

- **gitleaks** -> `GITLEAKS_RULES` (32 rules). Several regexes are transcribed
  verbatim from gitleaks' default configuration, along with their entropy floors
  and allowlists. The rule identifiers are gitleaks' identifiers.
- **keyhunter** -> `KEYHUNTER_PATTERNS` (9 rules). The unique-segment technique
  (matching a provider-specific substring that only occurs inside a real key,
  e.g. `T3BlbkFJ`, rather than a prefix that appears throughout documentation)
  is keyhunter's.
- The Shannon-entropy fallback in `scanner.py` is ordinary entropy maths and
  carries no separate attribution.

Neither project is vendored. Nothing here is a fork; both are upstream sources
this project's rule data was written from.

---

## gitleaks

https://github.com/gitleaks/gitleaks

MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## keyhunter

https://github.com/fadidevv/keyhunter

MIT License

Copyright (c) 2026 fadidevv

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
