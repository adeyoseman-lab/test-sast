import json

INPUT = "semgrep.sarif"
OUTPUT = "semgrep-remapped.sarif"

RULES = {

    "javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression": {
        "title": "Code Injection via eval()",
        "cvss": 9.8,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-95",
        "description": "User-controlled data reaches eval(), allowing arbitrary JavaScript execution.",
        "impact": """An attacker may execute arbitrary JavaScript code, leading to:
• Remote Code Execution
• Complete application compromise
• Data theft
• Authentication bypass""",
        "fix": """Avoid eval().
Use JSON.parse(), switch statements, or predefined function maps instead.""",
        "reference": "https://owasp.org/Top10/A03_2021-Injection/"
    },

    "javascript.lang.security.detect-child-process.detect-child-process": {
        "title": "Command Injection",
        "cvss": 9.8,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-78",
        "description": "Unsanitized user input reaches child_process.exec().",
        "impact": """Attackers can execute arbitrary operating system commands.""",
        "fix": """Use execFile() or spawn() with argument arrays.
Validate and whitelist user input.""",
        "reference": "https://cwe.mitre.org/data/definitions/78.html"
    },

    "javascript.lang.security.audit.sql-injection": {
        "title": "SQL Injection",
        "cvss": 9.8,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-89",
        "description": "Application concatenates user input into SQL query.",
        "impact": """• Database disclosure
• Authentication bypass
• Data modification
• Remote Code Execution (DB dependent)""",
        "fix": """Use prepared statements / parameterized queries.""",
        "reference": "https://cwe.mitre.org/data/definitions/89.html"
    },

    "javascript.lang.security.audit.xss": {
        "title": "Cross Site Scripting (XSS)",
        "cvss": 6.5,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-79",
        "description": "Untrusted data is rendered in HTML without proper escaping.",
        "impact": """Attackers may steal cookies, hijack sessions, and execute arbitrary JavaScript.""",
        "fix": """Escape output and use a templating engine with auto-escaping.""",
        "reference": "https://cwe.mitre.org/data/definitions/79.html"
    },

    "php.lang.security.eval-use.eval-use": {
        "title": "PHP eval() Code Injection",
        "cvss": 9.8,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-95",
        "description": "PHP eval() executes attacker-controlled code.",
        "impact": """Remote Code Execution.""",
        "fix": """Remove eval(). Use safer alternatives.""",
        "reference": "https://cwe.mitre.org/data/definitions/95.html"
    },

    "php.lang.security.exec-use.exec-use": {
        "title": "PHP Command Injection",
        "cvss": 9.8,
        "owasp": "OWASP A03:2021 - Injection",
        "cwe": "CWE-78",
        "description": "Unsanitized input reaches exec().",
        "impact": """Attackers may execute arbitrary OS commands.""",
        "fix": """Use escapeshellarg() and validate user input.""",
        "reference": "https://cwe.mitre.org/data/definitions/78.html"
    },

}

with open(INPUT, encoding="utf8") as f:
    sarif = json.load(f)

driver = sarif["runs"][0]["tool"]["driver"]

rules_lookup = {}
for r in driver.get("rules", []):
    rules_lookup[r["id"]] = r

for result in sarif["runs"][0]["results"]:

    rid = result["ruleId"]

    if rid not in RULES:
        continue

    info = RULES[rid]

    cvss = info["cvss"]

    if cvss >= 9.0:
        level = "error"
    elif cvss >= 7.0:
        level = "error"
    elif cvss >= 4.0:
        level = "warning"
    elif cvss > 0:
        level = "note"
    else:
        level = "none"

    result["level"] = level

    props = result.setdefault("properties", {})
    props["security-severity"] = str(cvss)

    if rid in rules_lookup:

        rule = rules_lookup[rid]

        rule["shortDescription"] = {
            "text": info["title"]
        }

        rule["fullDescription"] = {
            "text": info["description"]
        }

        rule["help"] = {
            "text": f"""
Impact
------

{info['impact']}

How to Fix
----------

{info['fix']}

OWASP
------

{info['owasp']}

CWE
---

{info['cwe']}

CVSS
----

{info['cvss']}

Reference
---------

{info['reference']}
"""
        }

        rule["helpUri"] = info["reference"]

with open(OUTPUT, "w", encoding="utf8") as f:
    json.dump(sarif, f, indent=2)

print("Generated", OUTPUT)
