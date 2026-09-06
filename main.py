import sys
import json
from config import DEFAULT_CONFIG
from analyzers.yaml_analyzer import YamlAnalyzer


def analyze_workflow(file_path: str, config=DEFAULT_CONFIG):
    analyzer = YamlAnalyzer(config)
    return analyzer.analyze(file_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <workflow.yml>")
        sys.exit(1)

    results = analyze_workflow(sys.argv[1])
    print(json.dumps(results, indent=2))