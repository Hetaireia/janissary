# Why I built a differential DAST scanner instead of using Nuclei or Burp

When I started building JANISSARY, I didn't want to build another directory fuzzer or a script that blindly throws payloads at a wall. I wanted to build something that respects the operator's time.

Most automated DAST tools fall into two camps: they either generate massive amounts of noise (high false positives), or they get instantly IP-banned by WAFs the moment they start scanning.

Here is why I took a different architectural approach.

### 1. Differential Detection (Precision = 1.000)
Nuclei is fantastic for CVE signature matching, but blind payload fuzzing drowns you in false positives. JANISSARY uses differential detection. Every finding is gated by a baseline comparison. If a single response changes, it doesn't emit a finding. It only fires when multiple oracles (status changes, length anomalies, error signatures) agree.

On the OWASP Benchmark DAST-applicable corpus (2,258 cases), this architecture scored an F1 of 0.920 with a **Precision of 1.000**. Zero false positives.

### 2. WAF-Aware Pacing
If you are scanning an authorized target, getting blocked mid-scan wastes your time. I ran JANISSARY against OWASP Juice Shop sitting behind a ModSecurity CRS WAF. The scanner detected the WAF, started hitting block signals, and dynamically backed off. It ramped the delay up to 30 seconds, recovered on a clean streak, and still successfully found the SQL injection without aborting the scan.

### 3. Burp-Native Output
I don't want to fight with proprietary dashboards. JANISSARY outputs findings as JSONL with raw HTTP/1.1 requests and responses (CRLF line endings). You can pipe it straight into jq or paste the raw requests directly into Burp Suite Repeater to validate the finding manually.

### The Reality Check
I recently ran JANISSARY against DVWA (Damn Vulnerable Web Application). It successfully grouped 8 distinct signals into a single CRITICAL SQL injection finding.

It’s not perfect. I document the known limitations openly in the repo—like how SPAs can cause admin-panel false positives, or how 401s abort the scan. But it is honest, it is measured, and it is fast.

You can try it out via Docker or PyPI:
```bash
docker run --rm oraclemode337/janissary scan -u "http://target.example" -p q
```

Repo: https://github.com/Hetaireia/janissary
