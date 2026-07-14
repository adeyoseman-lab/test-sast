# SAST Testing Guide

## Overview

This repository contains vulnerable PHP code for testing Static Application Security Testing (SAST) tools in GitHub Actions CI/CD pipelines.

## Vulnerabilities Included

### File: `vulnerable-code.php`

1. **SQL Injection** - Direct user input in SQL queries
2. **Command Injection** - User input passed to shell commands
3. **Path Traversal** - Unvalidated file paths
4. **Cross-Site Scripting (XSS)** - Unsanitized user output
5. **CSRF** - Missing CSRF token validation
6. **Hardcoded Credentials** - Passwords in source code
7. **Insecure Deserialization** - Using unserialize()
8. **Weak Cryptography** - MD5/DES usage
9. **Missing Input Validation** - No type/range checks
10. **Insecure Random Generation** - Using rand()
11. **Open Redirect** - Unvalidated redirect URLs
12. **Insecure File Upload** - No extension validation
13. **Error Disclosure** - Exposing sensitive error details
14. **eval() Usage** - Dynamic code execution
15. **Insecure Logging** - Logging sensitive data

## SAST Tools Configured

### 1. Semgrep
**Workflow:** `.github/workflows/sast-semgrep.yml`
- Pattern-based vulnerability detection
- OWASP Top 10 checks
- CWE Top 25 checks
- Multi-language support

**To run locally:**
```bash
semgrep --config=p/security-audit --config=p/owasp-top-ten .
```

### 2. CodeQL
**Workflow:** `.github/workflows/sast-codeql.yml`
- GitHub's advanced code analysis
- Supports multiple languages
- Generates SARIF reports

**To run locally:**
```bash
codeql database create codeql-db --language=javascript
codeql database analyze codeql-db javascript-code-scanning.qls --format=sarif-latest --output=results.sarif
```

### 3. PHPStan
**Workflow:** `.github/workflows/sast-phpstan.yml`
- PHP-specific static analysis
- Strict level 8 checks
- Type checking

**To run locally:**
```bash
phpstan analyse --configuration=phpstan.neon
```

### 4. Psalm
**Workflow:** `.github/workflows/sast-phpstan.yml`
- PHP static analysis
- Security scanning
- Type inference

**To run locally:**
```bash
psalm
```

### 5. Trivy
**Workflow:** `.github/workflows/sast-trivy.yml`
- Vulnerability scanner
- Dependency scanning
- Fast scanning

**To run locally:**
```bash
trivy fs .
```

### 6. OWASP Dependency-Check
**Workflow:** `.github/workflows/sast-dependency-check.yml`
- Dependency vulnerability scanning
- Comprehensive CVE database
- Multiple output formats

**To run locally:**
```bash
dependency-check.sh --project test-sast --scan .
```

## GitHub Actions Workflows

### Automatic Scanning

All workflows run automatically on:
- **Push to main/develop** - Immediate security feedback
- **Pull Requests** - Pre-merge security checks
- **Scheduled (Daily)** - Regular comprehensive scans

### View Results

1. **Security Tab**
   - Go to repository → Security
   - View all detected vulnerabilities
   - See remediation advice

2. **Actions Tab**
   - View workflow runs
   - Check individual scan logs
   - Download SARIF reports

3. **PR Comments**
   - Vulnerability summaries
   - Action items
   - Security recommendations

## Setup Instructions

### 1. Prerequisites
```bash
# Clone repository
git clone https://github.com/adeyoseman-lab/test-sast.git
cd test-sast
```

### 2. Install Local Tools (Optional)
```bash
# Semgrep
pip install semgrep

# PHPStan
composer require --dev phpstan/phpstan

# Psalm
composer require --dev vimeo/psalm

# Trivy
wget https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_Linux-64bit.tar.gz
tar zxvf trivy_0.50.0_Linux-64bit.tar.gz
```

### 3. Run Scans Locally
```bash
# Semgrep
semgrep --config=p/security-audit .

# Trivy
trivy fs .

# PHPStan
phpstan analyse

# Psalm
psalm
```

## Interpreting Results

### Severity Levels
- **CRITICAL** - Immediate action required
- **HIGH** - Address before deployment
- **MEDIUM** - Plan remediation
- **LOW** - Monitor and improve

### Common Findings

| Vulnerability | CVSS | Action |
|---|---|---|
| SQL Injection | 9.8 | Use parameterized queries |
| XSS | 7.1 | Sanitize/escape output |
| Command Injection | 9.8 | Use safe APIs |
| Path Traversal | 7.5 | Validate file paths |
| Hardcoded Secrets | 9.1 | Use secrets management |

## Remediation Examples

### SQL Injection Fix
```php
// ❌ Vulnerable
$query = "SELECT * FROM users WHERE id = " . $_GET['user_id'];

// ✅ Fixed
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['user_id']);
$stmt->execute();
```

### XSS Fix
```php
// ❌ Vulnerable
echo "Comment: " . $_GET['comment'];

// ✅ Fixed
echo "Comment: " . htmlspecialchars($_GET['comment'], ENT_QUOTES, 'UTF-8');
```

### Command Injection Fix
```php
// ❌ Vulnerable
shell_exec("cat " . $_POST['filename']);

// ✅ Fixed
$filename = realpath($_POST['filename']);
if ($filename && strpos($filename, '/safe/directory') === 0) {
    $output = file_get_contents($filename);
}
```

## CI/CD Pipeline

### Workflow Execution Order
1. Semgrep (2 AM UTC)
2. CodeQL (parallel)
3. PHPStan (on PHP changes)
4. Trivy (3 AM UTC)
5. Dependency-Check (5 AM UTC)

### Failure Handling
- High severity findings create GitHub Issues
- PR comments summarize findings
- Workflow can block merges if configured

## GitHub Secrets Setup

For SonarQube integration:
```bash
# Add these secrets to repository settings
SONAR_TOKEN=<your-token>
SONAR_HOST_URL=https://sonarqube.example.com
```

## Best Practices

1. **Regular Scanning** - Run scans on every push
2. **Baseline Management** - Establish security baseline
3. **Issue Tracking** - Link findings to issues
4. **Remediation** - Fix vulnerabilities promptly
5. **Training** - Educate team on secure coding
6. **Dependency Updates** - Keep dependencies current
7. **Code Review** - Security-focused reviews
8. **Documentation** - Document security decisions

## Troubleshooting

### Workflow Not Running
- Check branch protection rules
- Verify workflow file syntax
- Check Actions permissions

### False Positives
- Review findings in Security tab
- Add .semgrep.yml rules
- Create suppression rules if needed

### Performance Issues
- Exclude large directories
- Adjust scan frequency
- Use caching

## Resources

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [PHPStan Documentation](https://phpstan.org/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

## Questions & Support

For questions or issues, open a GitHub Issue or contact the security team.
