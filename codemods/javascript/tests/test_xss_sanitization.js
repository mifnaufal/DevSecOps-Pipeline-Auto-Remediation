/**
 * Tests for the XSS sanitization JavaScript codemod.
 */

const { XSSSanitizationCodemod } = require("../xss_sanitization");
const fs = require("fs");
const path = require("path");
const os = require("os");

describe("XSSSanitizationCodemod", () => {
  let tempDir;
  let codemod;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "xss-codemod-test-"));
    codemod = new XSSSanitizationCodemod({ dryRun: true });
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writeTestFile(content, filename = "test.js") {
    const filePath = path.join(tempDir, filename);
    fs.writeFileSync(filePath, content, "utf-8");
    return filePath;
  }

  test("replaces innerHTML with textContent", () => {
    writeTestFile("document.getElementById('user').innerHTML = user.name");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("textContent");
    expect(changes[0].cwe).toContain("CWE-79");
  });

  test("blocks document.write()", () => {
    writeTestFile("document.write('<div>' + data + '</div>')");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("SECURITY");
    expect(changes[0].fixed).toContain("document.write");
    expect(changes[0].cwe).toContain("CWE-79");
  });

  test("blocks eval()", () => {
    writeTestFile("eval('(' + jsonStr + ')')");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("SECURITY");
    expect(changes[0].fixed).toContain("eval");
    expect(changes[0].cwe).toContain("CWE-95");
  });

  test("replaces innerHTML += with textContent +=", () => {
    writeTestFile("element.innerHTML += '<li>' + item + '</li>'");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBeGreaterThan(0);
    expect(changes[0].fixed).toContain("textContent");
  });

  test("does not modify safe DOM code", () => {
    writeTestFile("document.getElementById('user').textContent = user.name");
    const changes = codemod.run(tempDir);

    expect(changes.length).toBe(0);
  });

  test("dry run does not modify files", () => {
    const content = "element.innerHTML = userInput";
    const filePath = writeTestFile(content);

    const changes = codemod.run(tempDir);
    const actualContent = fs.readFileSync(filePath, "utf-8");

    expect(actualContent).toBe(content);
    expect(changes.length).toBeGreaterThan(0);
  });
});

// Run with: npx jest codemods/javascript/tests/test_xss_sanitization.js
