# Demo Vulnerable Apps

Intentionally vulnerable applications for DAST scan testing. Upload any of these to the scanning system.

## Structure

```
demo_app_files/
├── python/              # 10 Flask vulnerable apps
│   ├── vulnerable_app.py
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

## Run Instructions

### Python (Flask)
```bash
cd demo_app_files/python
pip install -r requirements.txt
# Run specific class:
python vulnerable_app.py --class SQLi --port 5000
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
