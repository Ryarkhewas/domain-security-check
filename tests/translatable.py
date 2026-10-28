"""Find the texts of the report that need a translation (used by test_i18n.py).

Reads the source code: texts given to M(), to the finding helpers (_f, Finding),
to the report translators (t, L), the `title` of each check, the labels of the
report and the category names.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "domaincheck"
MODULES = ["web_checks", "tls_checks", "email_checks", "dns_checks", "audit", "scoring", "report", "pdf_report",
           "models", "collector", "cli", "sources", "hosting", "summary", "software", "nis2", "trackers", "alerts",
           "netguard"]
# positions of title, detail and recommendation in each helper
TEXT_ARGS = {"Finding": (1, 3, 4), "M": (0,), "t": (0,), "L": (0,), "tr": (0,), "say": (0,)}
F_ARGS = {"web_checks": (0, 2, 3), "email_checks": (0, 2, 3), "dns_checks": (0, 2, 3)}
NIS2_TEXTS = {"HEADING", "INTRO", "NOT_VISIBLE", "NO_PROBLEM"}
LABEL_DICTS = {"AREA_LABELS", "LABELS", "CATEGORY_LABELS", "CATEGORY_METHOD", "GRADE_SUMMARY", "RISKS", "EFFORT_LABELS",
               "IMPACT_LABELS", "NIS2_MEASURES"}


def _text(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip() else None


def translatable_texts() -> dict[str, set[str]]:
    """{text: {module, ...}}"""
    found: dict[str, set[str]] = {}

    def add(node, module):
        text = _text(node)
        if text:
            found.setdefault(text, set()).add(module)

    for module in MODULES:
        tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                positions = F_ARGS.get(module, ()) if name == "_f" else TEXT_ARGS.get(name or "", ())
                if name == "_isolation" and len(node.args) > 2:
                    positions = (2,)
                for i in positions:
                    if i < len(node.args):
                        add(node.args[i], module)
            elif isinstance(node, ast.Assign):
                targets = node.targets[0]
                names = [targets] if isinstance(targets, ast.Name) else getattr(targets, "elts", [])
                values = [node.value] if isinstance(targets, ast.Name) else getattr(node.value, "elts", [])
                for target, value in zip(names, values, strict=False):
                    name = getattr(target, "id", "")
                    if name == "title" or name.endswith(("_title", "_TEXT")) or name in NIS2_TEXTS:
                        add(value, module)
                if getattr(targets, "id", "") in LABEL_DICTS and isinstance(node.value, ast.Dict):
                    for value in node.value.values:
                        add(value, module)
                if getattr(targets, "id", "") in ("REMINDER", "SOURCES", "GUIDES"):
                    values_ = [node.value] if not isinstance(node.value, ast.Dict) else node.value.values
                    for value in values_:
                        add(value.elts[0] if isinstance(value, ast.Tuple) else value, module)
            elif isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") in ("SOURCES", "GUIDES"):
                for value in getattr(node.value, "values", []):
                    add(value.elts[0] if isinstance(value, ast.Tuple) else value, module)
            elif isinstance(node, ast.ClassDef) and node.name == "Category":
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        add(item.value, module)
    return found


if __name__ == "__main__":
    for text, modules in sorted(translatable_texts().items(), key=lambda kv: (sorted(kv[1]), kv[0])):
        print(f"{','.join(sorted(modules))}\t{text}")
