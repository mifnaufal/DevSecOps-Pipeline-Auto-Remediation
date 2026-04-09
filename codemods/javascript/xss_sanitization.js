/**
 * Tree-sitter codemod: Replace innerHTML with safe DOM APIs to prevent XSS.
 * 
 * Patterns detected:
 * - element.innerHTML = userInput -> element.textContent = userInput
 * - element.innerHTML = "<div>" + var -> element.textContent = var (with warning)
 * - document.write() -> console.error() (blocked entirely)
 * 
 * Usage:
 *   node codemods/javascript/xss_sanitization.js <target_dir>
 */

const fs = require("fs");
const path = require("path");

class XSSSanitizationCodemod {
  constructor({ dryRun = false } = {}) {
    this.dryRun = dryRun;
    this.changes = [];
    this.filesScanned = 0;
    this.filesModified = 0;

    this.patterns = [
      {
        name: "innerHTML assignment",
        // Match: something.innerHTML = anything
        regex: /(\w[\w.]*)\.innerHTML\s*=/g,
        transform: (match, content, lineNum) => {
          const fixed = match.replace(".innerHTML", ".textContent");
          return {
            fixed,
            description: `Replaced ${match.trim()} with .textContent to prevent XSS`,
            cwe: ["CWE-79"],
            rule: "xss-innerhtml",
          };
        },
      },
      {
        name: "document.write()",
        regex: /document\s*\.\s*write\s*\(/g,
        transform: (match, content, lineNum) => {
          return {
            fixed: "/* SECURITY: document.write() removed - use safe DOM APIs instead: */\n// ",
            description: "Blocked document.write() - use textContent or createElement() instead",
            cwe: ["CWE-79"],
            rule: "xss-document-write",
          };
        },
      },
      {
        name: "innerHTML += (concatenation)",
        regex: /(\w[\w.]*)\.innerHTML\s*\+=/g,
        transform: (match, content, lineNum) => {
          const fixed = match.replace(".innerHTML", ".textContent");
          return {
            fixed,
            description: `Replaced ${match.trim()} += with .textContent to prevent XSS`,
            cwe: ["CWE-79"],
            rule: "xss-innerhtml-concat",
          };
        },
      },
      {
        name: "eval() usage",
        regex: /\beval\s*\(/g,
        transform: (match, content, lineNum) => {
          return {
            fixed: "/* SECURITY: eval() blocked - use JSON.parse() or Function() with validation instead: */\n// eval(",
            description: "Blocked eval() - use safer alternatives like JSON.parse()",
            cwe: ["CWE-95"],
            rule: "xss-eval",
          };
        },
      },
    ];
  }

  run(targetDir) {
    const jsFiles = this._findJSFiles(targetDir);

    for (const filePath of jsFiles) {
      let content;
      try {
        content = fs.readFileSync(filePath, "utf-8");
      } catch (e) {
        continue;
      }

      const originalContent = content;
      const fileChanges = [];

      for (const pattern of this.patterns) {
        pattern.regex.lastIndex = 0;

        // We need to process line by line for accurate line numbers
        const lines = content.split("\n");
        let newLines = [];

        for (let i = 0; i < lines.length; i++) {
          let line = lines[i];
          let match;
          pattern.regex.lastIndex = 0;

          while ((match = pattern.regex.exec(line)) !== null) {
            const transform = pattern.transform(match[0], content, i + 1);
            fileChanges.push({
              file: filePath,
              line: i + 1,
              original: match[0],
              fixed: transform.fixed,
              rule: transform.rule,
              cwe: transform.cwe,
              description: transform.description,
            });

            // Apply replacement to line
            line = line.substring(0, match.index) + transform.fixed + line.substring(match.index + match[0].length);
            pattern.regex.lastIndex = match.index + transform.fixed.length;
          }

          newLines.push(line);
        }

        content = newLines.join("\n");
      }

      if (fileChanges.length > 0) {
        this.filesModified++;
        this.changes.push(...fileChanges);

        if (!this.dryRun) {
          fs.writeFileSync(filePath, content, "utf-8");
        }
      }

      this.filesScanned++;
    }

    return this.changes;
  }

  _findJSFiles(dir) {
    const extensions = [".js", ".ts", ".jsx", ".tsx"];
    const skipDirs = ["node_modules", ".git", "dist", "build", "coverage", "__tests__", "test", "tests"];

    const results = [];
    const walk = (currentDir) => {
      let entries;
      try {
        entries = fs.readdirSync(currentDir, { withFileTypes: true });
      } catch (e) {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          if (!skipDirs.includes(entry.name)) walk(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (extensions.includes(ext)) results.push(fullPath);
        }
      }
    };

    walk(dir);
    return results;
  }
}

// CLI entry point
if (require.main === module) {
  const args = process.argv.slice(2);
  const targetDir = args[0];
  const dryRun = args.includes("--dry-run") || args.includes("-n");

  if (!targetDir) {
    console.error("Usage: node xss_sanitization.js <target_dir> [--dry-run]");
    process.exit(1);
  }

  const codemod = new XSSSanitizationCodemod({ dryRun });
  const changes = codemod.run(targetDir);

  const report = {
    codemod: "xss_sanitization_javascript",
    filesScanned: codemod.filesScanned,
    filesModified: codemod.filesModified,
    changes,
    dryRun,
  };

  console.log(JSON.stringify(report, null, 2));
  console.error(`\nScanned: ${codemod.filesScanned} files, Modified: ${codemod.filesModified} files, Changes: ${changes.length}`);
  process.exit(0);
}

module.exports = { XSSSanitizationCodemod };
