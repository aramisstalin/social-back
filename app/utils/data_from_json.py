import os
import json
from pathlib import Path

def get_data_filename(filename):
    data_path = Path(os.path.dirname(__file__)).parent.absolute()
    return os.path.join(data_path, f"db/data/{filename}")

def get_data_from_json(filename: str):
    file_path = get_data_filename(filename)
    with open(file_path, 'r', encoding='UTF-8') as file:
        result = json.load(file)
    return result
