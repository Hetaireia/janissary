import pathlib

p = pathlib.Path("src/janissary/cli.py")
src = p.read_text(encoding="utf-8")
target = """            \"totalRequests\": summary.total_requests,
            \"findingCount\": len(findings),"""
replacement = """            \"totalRequests\": summary.total_requests,
            \"approximateRequests\": summary.approximate_requests,
            \"findingCount\": len(findings),"""
count = src.count(target)
if count != 1:
    raise SystemExit(f"Expected exactly 1 match, found {count}. Aborting.")
p.write_text(src.replace(target, replacement, 1), encoding="utf-8", newline="\n")
print("Patched cli.py: added approximateRequests to scan-path invocation.properties")
