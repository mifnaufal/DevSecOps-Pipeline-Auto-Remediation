"""
Tree-sitter codemod: Replace insecure hash algorithms (MD5/SHA1) with SHA-256.

Patterns detected:
- hashlib.md5() -> hashlib.sha256()
- hashlib.sha1() -> hashlib.sha256()
- md5.new() -> hashlib.sha256() (legacy)

Usage:
    python codemods/python/insecure_crypto.py <target_dir>
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    PY_LANGUAGE = Language(tspython.language())
except ImportError:
    # Fallback: regex-based mode if tree-sitter isn't available
    PY_LANGUAGE = None
    # Stub Node type for type hints
    class Node:
        pass


class InsecureCryptoCodemod:
    """Replaces MD5/SHA1 usage with SHA-256 in Python source files."""

    # Regex patterns used as fallback when tree-sitter isn't available
    PATTERNS = {
        "hashlib.md5": re.compile(r'hashlib\.md5\s*\('),
        "hashlib.sha1": re.compile(r'hashlib\.sha1\s*\('),
        "md5.new": re.compile(r'md5\.new\s*\('),
    }

    REPLACEMENTS = {
        "hashlib.md5": ("hashlib.sha256", "Replaced hashlib.md5() with hashlib.sha256()"),
        "hashlib.sha1": ("hashlib.sha256", "Replaced hashlib.sha1() with hashlib.sha256()"),
        "md5.new": ("hashlib.sha256", "Replaced md5.new() with hashlib.sha256()"),
    }

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.changes: List[Dict[str, Any]] = []
        self.files_modified = 0
        self.files_scanned = 0

        if PY_LANGUAGE is not None:
            self.parser = Parser(PY_LANGUAGE)
        else:
            self.parser = None

    def run(self, target_dir: str) -> List[Dict[str, Any]]:
        """Scan and fix all .py files in target_dir."""
        target_path = Path(target_dir)
        py_files = list(target_path.rglob("*.py"))

        for py_file in py_files:
            # Skip test files and vendored code
            if self._should_skip(py_file):
                continue

            self.files_scanned += 1
            content = py_file.read_text(encoding="utf-8", errors="replace")
            original_content = content

            if self.parser is not None:
                content = self._fix_with_ast(content, str(py_file))
            else:
                content = self._fix_with_regex(content, str(py_file))

            if content != original_content:
                self.files_modified += 1
                if not self.dry_run:
                    py_file.write_text(content, encoding="utf-8")

        return self.changes

    def _should_skip(self, filepath: Path) -> bool:
        """Skip test files, migrations, vendored code."""
        skip_patterns = [
            "test_",
            "_test.py",
            "tests/",
            "conftest.py",
            "migrations/",
            "venv/",
            ".venv/",
            "node_modules/",
            "__pycache__",
        ]
        path_str = str(filepath)
        return any(pattern in path_str for pattern in skip_patterns)

    def _fix_with_ast(self, content: str, filepath: str) -> str:
        """Use Tree-sitter AST to find and replace insecure crypto calls."""
        try:
            tree = self.parser.parse(bytes(content, "utf8"))
            root_node = tree.root_node
            nodes_to_replace = self._find_crypto_calls(root_node, content)

            # Apply replacements in reverse order to preserve offsets
            for node_info in sorted(nodes_to_replace, key=lambda x: x["start_byte"], reverse=True):
                old_text = content[node_info["start_byte"]:node_info["end_byte"]]
                new_text = node_info["replacement"]
                content = content[:node_info["start_byte"]] + new_text + content[node_info["end_byte"]:]

                self.changes.append({
                    "file": filepath,
                    "line": node_info["start_line"],
                    "original": old_text,
                    "fixed": new_text,
                    "rule": "insecure-crypto",
                    "cwe": ["CWE-327", "CWE-328"],
                    "description": node_info["description"],
                })

        except Exception as e:
            # Fall back to regex if AST parsing fails
            print(f"AST parsing failed for {filepath}: {e}, using regex fallback", file=sys.stderr)
            content = self._fix_with_regex(content, filepath)

        return content

    def _find_crypto_calls(self, node: Node, content: str) -> List[Dict[str, Any]]:
        """Traverse AST and find hashlib.md5/sha1 calls."""
        results = []

        for child in node.children:
            # Look for attribute access patterns: hashlib.md5, hashlib.sha1
            if child.type == "call":
                func_node = child.child_by_field_name("function")
                if func_node:
                    func_text = func_node.text.decode("utf8")
                    if "hashlib.md5" in func_text or "hashlib.sha1" in func_text:
                        replacement = func_text.replace(".md5(", ".sha256(").replace(".sha1(", ".sha256(")
                        algo = "md5" if "md5" in func_text else "sha1"
                        results.append({
                            "start_byte": child.start_byte,
                            "end_byte": child.end_byte,
                            "replacement": replacement,
                            "start_line": child.start_point[0] + 1,
                            "description": f"Replaced hashlib.{algo}() with hashlib.sha256()",
                        })

            results.extend(self._find_crypto_calls(child, content))

        return results

    def _fix_with_regex(self, content: str, filepath: str) -> str:
        """Fallback: use regex patterns to find and replace."""
        for pattern_name, pattern in self.PATTERNS.items():
            replacement_text, description = self.REPLACEMENTS[pattern_name]

            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                old_text = match.group()
                # Replace the algorithm name but keep the parentheses and args
                new_text = old_text.replace(".md5(", ".sha256(").replace(".sha1(", ".sha256(")
                content = content[:match.start()] + new_text + content[match.end():]

                self.changes.append({
                    "file": filepath,
                    "line": line_num,
                    "original": old_text,
                    "fixed": new_text,
                    "rule": "insecure-crypto",
                    "cwe": ["CWE-327", "CWE-328"],
                    "description": description,
                })

        return content


def main():
    parser = argparse.ArgumentParser(description="Replace insecure MD5/SHA1 with SHA-256 in Python files")
    parser.add_argument("target_dir", help="Directory containing Python files to scan")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without modifying files")
    parser.add_argument("--output", "-o", default=None, help="Output JSON report of changes")

    args = parser.parse_args()

    codemod = InsecureCryptoCodemod(dry_run=args.dry_run)
    changes = codemod.run(args.target_dir)

    report = {
        "codemod": "insecure_crypto_python",
        "files_scanned": codemod.files_scanned,
        "files_modified": codemod.files_modified,
        "changes": changes,
        "dry_run": args.dry_run,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2))

    print(f"\nScanned: {codemod.files_scanned} files, Modified: {codemod.files_modified} files, Changes: {len(changes)}", file=sys.stderr)

    # Exit 0 even if no changes found (not an error)
    sys.exit(0)


if __name__ == "__main__":
    main()
