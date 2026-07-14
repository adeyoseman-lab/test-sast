<?php
/**
 * Vulnerable PHP Code for SAST Testing
 * This file contains various security vulnerabilities intentionally
 */

// ============================================
// 1. SQL INJECTION VULNERABILITY
// ============================================
function getUserData($userId) {
    // VULNERABLE: Direct concatenation of user input into SQL query
    $dbConnection = new mysqli("localhost", "root", "password", "test_db");
    
    // No parameterized query - SQL Injection vulnerability
    $query = "SELECT * FROM users WHERE id = " . $_GET['user_id'];
    $result = $dbConnection->query($query);
    
    return $result->fetch_assoc();
}

// ============================================
// 2. COMMAND INJECTION VULNERABILITY
// ============================================
function executeCommand($filename) {
    // VULNERABLE: Direct user input passed to system command
    $output = shell_exec("cat " . $_POST['filename']);
    return $output;
}

// ============================================
// 3. PATH TRAVERSAL VULNERABILITY
// ============================================
function readFile() {
    // VULNERABLE: No validation of file path
    $file = $_GET['file'];
    
    if (file_exists($file)) {
        return file_get_contents($file);
    }
    
    return null;
}

// ============================================
// 4. CROSS-SITE SCRIPTING (XSS) VULNERABILITY
// ============================================
function displayUserComment() {
    // VULNERABLE: Direct output of unsanitized user input
    $comment = $_GET['comment'];
    
    echo "<div class='comment'>";
    echo "Comment: " . $comment; // XSS vulnerability - no escaping
    echo "</div>";
}

// ============================================
// 5. CROSS-SITE REQUEST FORGERY (CSRF)
// ============================================
function updateUserProfile() {
    // VULNERABLE: No CSRF token validation
    if ($_POST['action'] === 'update') {
        $userId = $_POST['user_id'];
        $email = $_POST['email'];
        
        // Direct update without CSRF protection
        // UPDATE query here
    }
}

// ============================================
// 6. HARDCODED CREDENTIALS
// ============================================
class DatabaseConnection {
    private $host = "localhost";
    private $username = "admin";
    private $password = "SuperSecret123!"; // VULNERABLE: Hardcoded credentials
    private $database = "production_db";
    
    public function connect() {
        $conn = new mysqli($this->host, $this->username, $this->password, $this->database);
        return $conn;
    }
}

// ============================================
// 7. INSECURE DESERIALIZATION
// ============================================
function deserializeUserData() {
    // VULNERABLE: Unserialize untrusted data
    $userData = $_COOKIE['user_data'];
    $unserialized = unserialize($userData); // Dangerous - can execute arbitrary code
    
    return $unserialized;
}

// ============================================
// 8. WEAK CRYPTOGRAPHY
// ============================================
function hashPassword($password) {
    // VULNERABLE: Using weak MD5 hashing
    return md5($password); // Not secure - should use password_hash()
}

function encryptData($data) {
    // VULNERABLE: Using weak encryption
    $key = "weak_secret_key";
    $iv = "12345678"; // Fixed IV - not random
    
    // Using DES which is deprecated and weak
    return mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_CBC, $iv);
}

// ============================================
// 9. MISSING INPUT VALIDATION
// ============================================
function processUserAge() {
    // VULNERABLE: No input validation
    $age = $_POST['age'];
    
    // Directly using $age without validation
    if ($age > 18) {
        return "Access granted";
    }
    
    return "Access denied";
}

// ============================================
// 10. INSECURE RANDOM NUMBER GENERATION
// ============================================
function generateSessionToken() {
    // VULNERABLE: Using weak random number generation
    $token = rand(1, 100000); // Not cryptographically secure
    
    return $token;
}

// ============================================
// 11. OPEN REDIRECT
// ============================================
function redirectUser() {
    // VULNERABLE: No validation of redirect URL
    $redirect_url = $_GET['redirect'];
    header("Location: " . $redirect_url); // Open redirect vulnerability
    exit;
}

// ============================================
// 12. INSECURE FILE UPLOAD
// ============================================
function handleFileUpload() {
    // VULNERABLE: No file type validation
    if ($_FILES['upload']['size'] > 0) {
        $filename = $_FILES['upload']['name'];
        $tmpname = $_FILES['upload']['tmp_name'];
        
        // VULNERABLE: No extension check, directly move uploaded file
        move_uploaded_file($tmpname, "uploads/" . $filename);
    }
}

// ============================================
// 13. ERROR INFORMATION DISCLOSURE
// ============================================
function connectDatabase() {
    // VULNERABLE: Showing detailed error messages
    $conn = mysqli_connect("localhost", "root", "password", "db");
    
    if (!$conn) {
        // VULNERABLE: Exposing database connection details
        die("Connection failed: " . mysqli_connect_error());
    }
    
    return $conn;
}

// ============================================
// 14. USE OF EVAL
// ============================================
function evaluateCode() {
    // VULNERABLE: Using eval() with user input
    $code = $_GET['code'];
    eval($code); // Extremely dangerous - arbitrary code execution
}

// ============================================
// 15. INSECURE LOGGING
// ============================================
function logUserAction() {
    // VULNERABLE: Logging sensitive information
    $password = $_POST['password'];
    $username = $_POST['username'];
    
    // Writing passwords to log files
    error_log("User login - Username: " . $username . " Password: " . $password);
}

?>
