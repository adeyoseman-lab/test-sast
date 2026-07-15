/**
 * Vulnerable Node.js Web Application for SAST Testing
 * This file contains various security vulnerabilities intentionally
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const mysql = require('mysql');
const crypto = require('crypto');
const pickle = require('pickle');
const yaml = require('js-yaml');

const app = express();
app.use(express.json());

// ============================================
// 1. SQL INJECTION VULNERABILITY
// ============================================
app.get('/user/:id', (req, res) => {
    // VULNERABLE: Direct concatenation of user input into SQL query
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    // Should use parameterized queries instead
    db.query(query, (err, results) => {
        if (err) res.status(500).send(err);
        res.json(results);
    });
});

// ============================================
// 2. COMMAND INJECTION VULNERABILITY
// ============================================
app.post('/execute', (req, res) => {
    // VULNERABLE: Direct user input passed to system command
    const command = req.body.cmd;
    exec("ls " + command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error);
        }
        res.send(stdout);
    });
});

// ============================================
// 3. PATH TRAVERSAL VULNERABILITY
// ============================================
app.get('/file', (req, res) => {
    // VULNERABLE: No validation of file path
    const filePath = req.query.path;
    
    if (fs.existsSync(filePath)) {
        res.send(fs.readFileSync(filePath, 'utf8'));
    } else {
        res.status(404).send('File not found');
    }
});

// ============================================
// 4. CROSS-SITE SCRIPTING (XSS) VULNERABILITY
// ============================================
app.get('/comment', (req, res) => {
    // VULNERABLE: Direct output of unsanitized user input
    const comment = req.query.text;
    
    // No escaping - XSS vulnerability
    res.send(`<div class="comment"><p>${comment}</p></div>`);
});

// ============================================
// 5. CROSS-SITE REQUEST FORGERY (CSRF)
// ============================================
app.post('/transfer', (req, res) => {
    // VULNERABLE: No CSRF token validation
    const amount = req.body.amount;
    const recipient = req.body.recipient;
    
    // Direct transfer without CSRF protection
    // Transfer money here
    res.send('Transfer successful');
});

// ============================================
// 6. HARDCODED CREDENTIALS
// ============================================
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'SuperSecret123!', // VULNERABLE: Hardcoded credentials
    database: 'production_db'
};

const apiKey = 'sk_live_1234567890abcdef'; // VULNERABLE: Hardcoded API key
const jwtSecret = 'my-super-secret-key'; // VULNERABLE: Hardcoded secret

// ============================================
// 7. INSECURE DESERIALIZATION
// ============================================
app.post('/deserialize', (req, res) => {
    try {
        // VULNERABLE: Deserializing untrusted data
        const userData = JSON.parse(req.body.data);
        
        // Even worse - using eval
        eval(userData.code); // Arbitrary code execution
        
        res.send('Data processed');
    } catch (err) {
        res.status(500).send(err);
    }
});

// ============================================
// 8. WEAK CRYPTOGRAPHY
// ============================================
function hashPassword(password) {
    // VULNERABLE: Using weak MD5 hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

function encryptData(data) {
    // VULNERABLE: Using weak DES encryption with fixed IV
    const cipher = crypto.createCipheriv('des-cbc', 'weak_key_', '12345678');
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// ============================================
// 9. MISSING INPUT VALIDATION
// ============================================
app.post('/age-check', (req, res) => {
    // VULNERABLE: No input validation
    const age = req.body.age;
    
    // Directly using age without validation
    if (age > 18) {
        res.send('Access granted');
    } else {
        res.send('Access denied');
    }
});

// ============================================
// 10. INSECURE RANDOM NUMBER GENERATION
// ============================================
function generateSessionToken() {
    // VULNERABLE: Using weak random number generation
    const token = Math.random().toString(36).substring(2, 15);
    return token;
}

// ============================================
// 11. OPEN REDIRECT
// ============================================
app.get('/redirect', (req, res) => {
    // VULNERABLE: No validation of redirect URL
    const redirectUrl = req.query.url;
    res.redirect(redirectUrl); // Open redirect vulnerability
});

// ============================================
// 12. INSECURE FILE UPLOAD
// ============================================
app.post('/upload', (req, res) => {
    // VULNERABLE: No file type validation
    const file = req.files.upload;
    
    // VULNERABLE: No extension check, directly save uploaded file
    file.mv(__dirname + '/uploads/' + file.name);
    res.send('File uploaded');
});

// ============================================
// 13. PROTOTYPE POLLUTION
// ============================================
app.post('/merge', (req, res) => {
    // VULNERABLE: Unsafe object merge
    const obj = {};
    const input = req.body;
    
    // No sanitization - vulnerable to prototype pollution
    Object.assign(obj, input);
    
    res.send('Merged');
});

// ============================================
// 14. INSECURE YAML/JSON PARSING
// ============================================
app.post('/parse-yaml', (req, res) => {
    try {
        // VULNERABLE: Using yaml.load with untrusted data
        const data = yaml.load(req.body.content);
        res.json(data);
    } catch (err) {
        res.status(400).send(err);
    }
});

// ============================================
// 15. UNCONTROLLED RESOURCE CONSUMPTION
// ============================================
app.post('/process', (req, res) => {
    // VULNERABLE: No limit on data size processing
    const data = req.body.data;
    
    // Processing without size limit - DOS vulnerability
    let result = data.repeat(1000000);
    res.send(result.length);
});

// ============================================
// 16. INSECURE LOGGING
// ============================================
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // VULNERABLE: Logging sensitive information
    console.log(`User login - Username: ${username} Password: ${password}`);
    
    res.send('Login attempt logged');
});

// ============================================
// 17. EXPOSURE OF SYSTEM INFORMATION
// ============================================
app.get('/info', (req, res) => {
    // VULNERABLE: Exposing sensitive system information
    const info = {
        nodeVersion: process.version,
        platform: process.platform,
        cwd: process.cwd(),
        env: process.env // CRITICAL: Exposing all environment variables
    };
    
    res.json(info);
});

// ============================================
// 18. USING EVAL
// ============================================
app.post('/eval', (req, res) => {
    // VULNERABLE: Using eval with user input
    const code = req.body.code;
    
    try {
        eval(code); // Extremely dangerous - arbitrary code execution
        res.send('Code executed');
    } catch (err) {
        res.status(500).send(err);
    }
});

// ============================================
// 19. INSECURE DEPENDENCY VERSION
// ============================================
// Using old versions of vulnerable packages
// package.json should have: express@2.0.0, lodash@2.4.1, etc.

// ============================================
// 20. NO RATE LIMITING
// ============================================
app.get('/api/data', (req, res) => {
    // VULNERABLE: No rate limiting - susceptible to DOS
    res.json({ data: 'unlimited access' });
});

// ============================================
// 21. MISSING SECURITY HEADERS
// ============================================
app.get('/', (req, res) => {
    // VULNERABLE: No security headers
    // Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.
    res.send('Welcome to vulnerable app');
});

// ============================================
// 22. REGEX DOS (ReDoS)
// ============================================
app.post('/validate-email', (req, res) => {
    const email = req.body.email;
    
    // VULNERABLE: Catastrophic backtracking regex (ReDoS)
    const emailRegex = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/;
    
    if (emailRegex.test(email)) {
        res.send('Valid email');
    } else {
        res.send('Invalid email');
    }
});

// ============================================
// DATABASE CONNECTION (INSECURE)
// ============================================
const db = mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    database: dbConfig.database
});

// No error handling for connection
db.connect();

// ============================================
// SERVER START
// ============================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API Key: ${apiKey}`); // VULNERABLE: Exposing secrets in logs
});

module.exports = app;
