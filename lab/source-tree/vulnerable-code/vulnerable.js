// Semgrep: Command injection
const { exec } = require('child_process');
function vulnerable_exec(userInput) {
  exec(`echo ${userInput}`, (error, stdout, stderr) => {});  // VULNERABLE
}

// Semgrep: Hardcoded secrets
const API_SECRET = 'super_secret_key_12345';
const DB_PASS = 'mysql_root_password';

// Semgrep: SQL injection
function vulnerable_query(userId) {
  return `SELECT * FROM users WHERE id = ${userId}`;  // VULNERABLE
}

// Semgrep: Eval usage
function dangerous_eval(code) {
  eval(code);  // VULNERABLE
}

// Semgrep: XXE in XML parsing
const xml2js = require('xml2js');
const parser = new xml2js.Parser({ 
  doctype: true  // VULNERABLE: Allows XXE
});

// Semgrep: No input validation
function process_input(data) {
  return data.toUpperCase();  // No sanitization
}
