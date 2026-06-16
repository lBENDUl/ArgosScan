"""
ArgosScan - JSON Reporter
"""

import json
from pathlib import Path
from typing import Dict


class JSONReporter:
    """Export scan results as a machine-readable JSON file."""

    def __init__(self, results: Dict):
        self._results = results

    def generate(self, output_file: str) -> None:
        """
        Write results to *output_file* as pretty-printed JSON.

        Args:
            output_file: Destination path (e.g. 'results.json').
        """
        content = json.dumps(self._results, indent=2, default=str, ensure_ascii=False)
        Path(output_file).write_text(content, encoding="utf-8")
