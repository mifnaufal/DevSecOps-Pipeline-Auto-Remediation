/**
 * Tree-sitter codemod: Replace insecure hash algorithms in JavaScript.
 * 
 * Patterns detected:
 * - crypto.createHash('md5') -> crypto.createHash('sha256')
 * - crypto.createHash('sha1') -> crypto.createHash('sha256')
 * - createHash('md5') -> createHash('sha256')
 * 
 * Usage:
 *   node codemods/javascript/insecure_crypto.js <target_dir>
 */

const fs = require("fs");
const path = require("path");

class InsecureCryptoCodemod {
  constructor({ dryRun = false } = {}) {
    this.dryRun = dryRun;
    this.changes = [];
    this.filesScanned = 0;
    this.filesModified = 0;

    // Regex patterns for insecure crypto detection
    this.patterns = [
      {
        name: "crypto.createHash('md5')",
        regex: /createHash\s*\(\s*['"]md5['"]\s*\)/g,
        replacement: "createHash('sha256')",
        description: "Replaced createHash('md5') with createHash('sha256')",
        cwe: ["CWE-327", "CWE-328"],
      },
      {
        name: "crypto.createHash('sha1')",
        regex: /createHash\s*\(\s*['"]sha1['"]\s*\)/g,
        replacement: "createHash('sha256')",
        description: "Replaced createHash('sha1') with createHash('sha256')",
        cwe: ["CWE-327", "CWE-328"],
      },
      {
        name: "md5() library call",
        regex: /\bmd5\s*\(/g,
        replacement: "sha256(",
        description: "Replaced md5() with sha256() - verify import is correct",
        cwe: ["CWE-327", "CWE-328"],
      },
    ];
  }

  /**
   * Scan and fix all .js/.ts files in targetDir.
   * @param {string} targetDir - Directory to scan
   * @returns {Array} List of changes made
   */
  run(targetDir) {
    const jsFiles = this._findJSFiles(targetDir);

    for (const filePath of jsFiles) {
      let content = fs.readFileSync(filePath, "utf-8");
      const originalContent = content;
      const fileChanges = [];

      for (const pattern of this.patterns) {
        let match;
        // Reset lastIndex for global regex
        pattern.regex.lastIndex = 0;

        // Find all matches with line numbers
        const contentLines = content.split("\n");
        let searchContent = content;
        let lineOffset = 0;

        while ((match = pattern.regex.exec(searchContent)) !== null) {
          const lineNum = lineOffset + contentLines.slice(0).join("\n").indexOf(match[0]) >= 0
            ? content.substring(0, match.index + lineOffset).split("\n").length
            : 1;

          fileChanges.push({
            file: filePath,
            line: lineNum,
            original: match[0],
            fixed: pattern.replacement,
            rule: "insecure-crypto",
            cwe: pattern.cwe,
            description: pattern.description,
          });

          // Apply replacement
          searchContent =
            searchContent.substring(0, match.index) +
            pattern.replacement +
            searchContent.substring(match.index + match[0].length);

          // Adjust for next iteration
          pattern.regex.lastIndex = match.index + pattern.replacement.length;
        }

        content = searchContent;
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

  /**
   * Find all JavaScript/TypeScript files recursively.
   * @private
   */
  _findJSFiles(dir) {
    const extensions = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"];
    const skipDirs = [
      "node_modules",
      ".git",
      "dist",
      "build",
      "coverage",
      "__tests__",
      "test",
      "tests",
      "vendor",
    ];

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
          if (!skipDirs.includes(entry.name)) {
            walk(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (extensions.includes(ext)) {
            results.push(fullPath);
          }
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
  const outputFlag = args.find((a) => a.startsWith("-o=") || a.startsWith("--output="));
  const outputFile = outputFlag ? outputFlag.split("=")[1] : null;

  if (!targetDir) {
    console.error("Usage: node insecure_crypto.js <target_dir> [--dry-run] [-o=output.json]");
    process.exit(1);
  }

  const codemod = new InsecureCryptoCodemod({ dryRun });
  const changes = codemod.run(targetDir);

  const report = {
    codemod: "insecure_crypto_javascript",
    filesScanned: codemod.filesScanned,
    filesModified: codemod.filesModified,
    changes,
    dryRun,
  };

  if (outputFile) {
    fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
  } else {
    console.log(JSON.stringify(report, null, 2));
  }

  console.error(
    `\nScanned: ${codemod.filesScanned} files, Modified: ${codemod.filesModified} files, Changes: ${changes.length}`
  );
  process.exit(0);
}

module.exports = { InsecureCryptoCodemod };
