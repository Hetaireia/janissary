import sys
from prance import ResolvingParser

METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

for path in sys.argv[1:]:
    parser = ResolvingParser(path, backend="openapi-spec-validator", recursion_limit=5)
    spec = parser.specification
    paths = spec.get("paths", {})
    ops = sum(1 for item in paths.values() for m in item if str(m).lower() in METHODS)
    print("VALID " + path + " paths=" + str(len(paths)) + " ops=" + str(ops))
