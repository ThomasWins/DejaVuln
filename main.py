import sys
import json
import subprocess
from pathlib import Path

from PySide6.QtWidgets import QApplication
from gui import MainWindow

CONFIG = Path("config.json")


def cleanup_history():
    if not CONFIG.exists():
        return

    with open(CONFIG, "r") as f:
        config = json.load(f)

    days = config.get("history_retention_days", 365)

    subprocess.run([
        sys.executable,
        "-m",
        "scripts.clean_data",
        "--days",
        str(days)
    ])


def main():
    cleanup_history()

    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()