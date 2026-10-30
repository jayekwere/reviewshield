import json


def parse_document(text: str) -> object:
    return json.loads(text)
