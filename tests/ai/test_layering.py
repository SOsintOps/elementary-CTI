# "The balance of probability." — Sherlock Holmes, Elementary
import ast
from pathlib import Path

AI_ROOT = Path(__file__).parents[2] / "src" / "pestilentia" / "ai"
FORBIDDEN = {"pestilentia.web", "pestilentia.pipeline"}


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
    return found


def test_ai_does_not_import_web_or_pipeline():
    violations = []
    for py in AI_ROOT.rglob("*.py"):
        for imp in _imports(py):
            if any(imp == f or imp.startswith(f + ".") for f in FORBIDDEN):
                violations.append(f"{py}: {imp}")
    assert not violations, "Layering violation(s):\n" + "\n".join(violations)
