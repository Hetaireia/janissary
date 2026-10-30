import json, sys
from pathlib import Path
import jsonschema
schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
doc    = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
try:
    jsonschema.validate(doc, schema)
    print("VALID"); sys.exit(0)
except jsonschema.ValidationError as e:
    print(f"INVALID: {e.message}"); sys.exit(1)
