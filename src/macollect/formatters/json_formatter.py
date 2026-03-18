import json

def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)