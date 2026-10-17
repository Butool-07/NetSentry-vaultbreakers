
import json
from pathlib import Path

# Find the main NetSentry project folder
PROJECT_FOLDER = Path(__file__).resolve().parent.parent

# Find the external settings file
CONFIG_FILE = PROJECT_FOLDER / "config" / "settings.json"


def load_config():
    """Load NetSentry settings from settings.json."""
    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


if __name__ == "__main__":
    settings = load_config()

    print("NetSentry configuration loaded successfully!")
    print("Trusted servers:", settings["trusted_servers"])
    print("Approved scanners:", settings["approved_scanners"])
    print("Patch servers:", settings["patch_servers"])
    print("Detection thresholds:", settings["detection_thresholds"])
