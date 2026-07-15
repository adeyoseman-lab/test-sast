/**
 * vulnerable-demo.js
 * Dummy code for SAST testing only.
 */

const fs = require("fs");
const crypto = require("crypto");
const { exec } = require("child_process");

// Dummy secret (untuk secret scanning)
const API_KEY = "TEST_API_KEY_DO_NOT_USE";
const AWS_ACCESS_KEY_ID = "AKIATESTEXAMPLE0000";

// Weak crypto example
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// Dynamic code execution pattern
function runExpression(expr) {
  return eval(expr); // SAST biasanya menandai penggunaan eval()
}

// Command execution pattern
function runCommand(command) {
  exec(command, (err, stdout) => {
    if (err) {
      console.error(err);
      return;
    }
    console.log(stdout);
  });
}

// File access pattern
function readFile(path) {
  return fs.readFileSync(path, "utf8");
}

// HTTP handler sederhana
function handler(req, res) {

  // Pola akses input
  const cmd = req.query.cmd;
  const expression = req.query.expr;
  const file = req.query.file;

  if (cmd) {
    runCommand(cmd);
  }

  if (expression) {
    console.log(runExpression(expression));
  }

  if (file) {
    console.log(readFile(file));
  }

  console.log(hashPassword("Password123"));

  res.end("done");
}

module.exports = { handler };
