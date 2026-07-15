import json

INPUT="semgrep.sarif"
OUTPUT="semgrep-remapped.sarif"

# Mapping rule -> (CVSS, OWASP, CWE)
RULES={

"php.lang.security.eval-use.eval-use":
(9.8,"A03:2021 Injection","CWE-95"),

"php.lang.security.exec-use.exec-use":
(9.8,"A03:2021 Injection","CWE-78"),

"javascript.lang.security.detect-child-process.detect-child-process":
(9.8,"A03:2021 Injection","CWE-78"),

"javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression":
(9.8,"A03:2021 Injection","CWE-95"),

"javascript.lang.security.audit.code-string-concat.code-string-concat":
(8.2,"A03:2021 Injection","CWE-89"),

"php.lang.security.injection.echoed-request.echoed-request":
(6.4,"A03:2021 Injection","CWE-79"),

"php.lang.security.mcrypt-use.mcrypt-use":
(5.5,"A02:2021 Cryptographic Failures","CWE-327"),

"php.lang.security.md5.md5":
(5.9,"A02:2021 Cryptographic Failures","CWE-327"),

"php.lang.security.sha1.sha1":
(5.9,"A02:2021 Cryptographic Failures","CWE-327"),

"php.lang.security.file-upload.file-upload":
(8.8,"A05:2021 Security Misconfiguration","CWE-434"),

"php.lang.security.xxe":
(8.5,"A05:2021","CWE-611"),

"php.lang.security.ssrf":
(8.8,"A10:2021 SSRF","CWE-918"),

"php.lang.security.path-traversal":
(8.1,"A01:2021","CWE-22"),

"php.lang.security.open-redirect":
(3.8,"A10:2021","CWE-601"),

"generic.secrets":
(9.8,"A02:2021","CWE-798"),
}

with open(INPUT) as f:
    sarif=json.load(f)

for run in sarif["runs"]:

    for r in run["results"]:

        rid=r["ruleId"]

        cvss=5.0
        owasp="Unknown"
        cwe="Unknown"

        if rid in RULES:
            cvss,owasp,cwe=RULES[rid]

        if cvss>=9:
            level="error"
        elif cvss>=7:
            level="error"
        elif cvss>=4:
            level="warning"
        elif cvss>0:
            level="note"
        else:
            level="none"

        r["level"]=level

        props=r.setdefault("properties",{})
        props["security-severity"]=str(cvss)
        props["owasp"]=owasp
        props["cwe"]=cwe

with open(OUTPUT,"w") as f:
    json.dump(sarif,f,indent=2)

print("Done.")
