# Demo Vulnerable Apps

Intentionally vulnerable applications for SAST/DAST scan testing. Upload any of these to the scanning system.

## Structure

```
demo_app_files/
├── python/              # 10 Flask vulnerable apps + FIXED safe version
│   ├── vulnerable_app.py  # 34 findings (Critical)
│   ├── safe_app.py        # 0 findings (Low) - FIXED demo
│   └── requirements.txt
├── javascript/          # 6 Node.js vulnerable apps
│   ├── vulnerable_app_js.js
│   └── package.json
└── java/                # Spring Boot vulnerable app (6 endpoints)
    └── vulnapp/
        ├── pom.xml
        └── src/main/...
```

## Vulnerability Classes Covered

| Class              | Python | JavaScript | Java |
|--------------------|--------|------------|------|
| SQL Injection      | ✅     | ✅          | ✅   |
| Path Traversal     | ✅     | ✅          | ✅   |
| Command Injection  | ✅     | ✅          | ✅   |
| XSS                | ✅     | ✅          | ✅   |
| SSRF               | ✅     | ✅          | ✅   |
| Open Redirect      | ✅     | ✅          | ✅   |
| SSTI               | ✅     |            |      |
| Deserialization    | ✅     |            |      |
| XXE                | ✅     |            |      |
| Prototype Pollution| ✅     |            |      |

## Demo: Vulnerable vs Safe

Upload to `/training/upload` (Upload tab) to see full tabular SAST+DAST report:

| File | Findings | Risk | Demo |
|------|----------|------|------|
| `vulnerable_app.py` | 34 | Critical | Click row → expand SAST/DAST logs + code context + fix |
| `safe_app.py` | 0 | Low | Shows 0 findings — ideal for side-by-side demo |

**How to demo:**
1. Upload `vulnerable_app.py` → see Executive Summary (Risk 100/Critical), By-Class table (SQLi 6, PathTraversal 5...), Full Tabular Summary — click any row to expand SAST log + code context + DAST payload/log + fix.
2. Upload `safe_app.py` → see 0 findings, Risk Low — proves fix works.
3. Upload both together → compare per-file counts.

## Run Instructions

### Python (Flask)
```bash
cd demo_app_files/python
pip install -r requirements.txt
# Run vulnerable (34 findings):
python vulnerable_app.py --class SQLi --port 5000
# Run safe (0 findings) — same API, fixed code:
python safe_app.py --class SQLi --port 5001
# Available classes: SQLi, PathTraversal, CommandInjection, XSS, SSTI, SSRF, OpenRedirect, Deserialization, XXE, PrototypePollution
```

### JavaScript (Node.js)
```bash
cd demo_app_files/javascript
# Run all endpoints:
node vulnerable_app_js.js --all --port 3000
# Run specific class:
node vulnerable_app_js.js --class SQLi --port 3000
# Available classes: SQLi, PathTraversal, CommandInjection, XSS, SSRF, OpenRedirect
```

### Java (Spring Boot)
```bash
cd demo_app_files/java/vulnapp
mvn spring-boot:run
# Or build jar first:
mvn package -DskipTests
java -jar target/vulnapp-1.0.0.jar
# Default port: 8080
```
