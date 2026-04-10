/**
 * Tests for the insecure JavaScript crypto codemod.
 */

const { InsecureCryptoCodemod } = require("../insecure_crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

describe("InsecureCryptoCodemod", () => {
  let tempDir;
  let codemod;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "codemod-test-"));
    codemod = new InsecureCryptoCodemod({ dryRun: true });
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writeTestFile(content, filename = "test.js") {
    const filePath = path.join(tempDir, filename);
    fs.writeFileSync(filePath, content, "utf-8");
    return filePath;
  }

  test("replaces createHash('md5') with createHash('sha256')", () => {
    writeTestFile("crypto.createHash('md5').update(data).digest('hex')");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("sha256");
    expect(changes[0].original).toContain("md5");
    expect(changes[0].cwe).toContain("CWE-327");
    expect(changes[0].cwe).toContain("CWE-328");
  });

  test("replaces createHash('sha1') with createHash('sha256')", () => {
    writeTestFile("createHash('sha1').update(data)");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("sha256");
  });

  test("replaces md5() with sha256()", () => {
    writeTestFile("const hash = md5(data)");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("sha256");
  });

  test("does not modify safe code", () => {
    writeTestFile("crypto.createHash('sha256').update(data).digest('hex')");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBe(0);
  });

  test("skips node_modules directory", () => {
    const nodeModulesPath = path.join(tempDir, "node_modules", "some-pkg");
    fs.mkdirSync(nodeModulesPath, { recursive: true });
    writeTestFile("crypto.createHash('md5')", "node_modules/some-pkg/index.js");

    const changes = codemod.run(tempDir);
    expect(changes.length).toBe(0);
  });

  test("skips test directories", () => {
    const testPath = path.join(tempDir, "__tests__");
    fs.mkdirSync(testPath, { recursive: true });
    writeTestFile("crypto.createHash('md5')", "__tests__/crypto.test.js");

    const changes = codemod.run(tempDir);
    expect(changes.length).toBe(0);
  });

  test("dry run does not modify files", () => {
    const content = "crypto.createHash('md5').update(data)";
    const filePath = writeTestFile(content);

    const changes = codemod.run(tempDir);
    const actualContent = fs.readFileSync(filePath, "utf-8");

    expect(actualContent).toBe(content);
    expect(changes.length).toBeGreaterThan(0);
  });

  test("handles multiple files", () => {
    writeTestFile("crypto.createHash('md5')", "file1.js");
    writeTestFile("crypto.createHash('sha1')", "file2.js");
    writeTestFile("const h = md5(x)", "file3.ts");

    const changes = codemod.run(tempDir);
    expect(changes.length).toBe(3);
  });
});

// Run with: npx jest codemods/javascript/tests/test_insecure_crypto.js
