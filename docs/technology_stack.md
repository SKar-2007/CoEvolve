# Technology Stack: CoEvolve Sandbox

## Technology Decisions and Justification

---

## 1. Core Technology Choices

### 1.1 Language & Runtime

| Component | Technology | Version | Justification |
|-----------|-----------|---------|---------------|
| Core Language | Python | 3.11+ | Rich ML/AI ecosystem, async support, rapid development |
| API Framework | FastAPI | 0.100+ | High performance, automatic OpenAPI docs, async support |
| Container Runtime | Docker | 24.0+ | Industry standard, rich security features, wide support |
| Primary Database | PostgreSQL | 15+ | ACID compliance, JSON support, proven reliability |
| Cache/Queue | Redis | 7.0+ | In-memory performance, pub/sub, queue primitives |
| Metrics | Prometheus | 2.45+ | Time-series excellence, PromQL, ecosystem |
| Dashboards | Grafana | 10.0+ | Rich visualization, alerting, plugin ecosystem |

### 1.2 Why Python?

```python
# Strengths for CoEvolve Sandbox:
1. ML/AI Ecosystem: transformers, langchain, sentence-transformers
2. Docker SDK: docker-py for container orchestration
3. Async Support: asyncio for concurrent agent execution
4. Rapid Prototyping: FastAPI + Pydantic for API development
5. Rich Testing: pytest, hypothesis, coverage
6. Community: Largest AI/ML community support
```

---

## 2. LLM Integration

### 2.1 Provider Selection

| Provider | Model | Use Case | Pricing (Input/Output) |
|----------|-------|----------|----------------------|
| Anthropic | Claude 3.5 Sonnet | Attacker, Developer | $3/M / $15/M |
| Anthropic | Claude 3.5 Haiku | Distiller, Regression | $0.25/M / $1.25/M |
| OpenAI | GPT-4o | Alternative Attacker/Developer | $2.50/M / $10/M |
| OpenAI | GPT-4o-mini | Alternative Distiller | $0.15/M / $0.60/M |
| Local | Qwen2.5-72B-Instruct | Self-hosted alternative | Compute cost only |
| Local | Qwen2.5-7B-Instruct | Self-hosted distiller | Compute cost only |

### 2.2 LLM Client Architecture

```python
# LLM Client Abstraction Layer
class LLMClient:
    """Unified interface for multiple LLM providers."""
    
    def __init__(self, provider: str, model: str, api_key: str):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.client = self._init_client()
    
    async def generate(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stop_sequences: List[str] = None
    ) -> LLMResponse:
        """Generate response from LLM."""
        pass
    
    async def generate_streaming(
        self,
        system_prompt: str,
        user_message: str,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream response tokens."""
        pass
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text."""
        pass
```

### 2.3 Provider Priority

```
Primary:    Anthropic Claude (best reasoning, code generation)
Secondary:  OpenAI GPT-4o (fallback, strong performance)
Tertiary:   Open-source models (cost optimization, data privacy)
```

### 2.4 Model Configuration

| Agent | Model | Temperature | Max Tokens | Top-p | Rationale |
|-------|-------|-------------|------------|-------|-----------|
| Attacker | Claude 3.5 Sonnet | 0.85 | 4096 | 0.95 | High creativity for task generation |
| Developer | Claude 3.5 Sonnet | 0.1 | 8192 | 0.95 | Deterministic code generation |
| Distiller | Claude 3.5 Haiku | 0.3 | 1024 | 0.9 | Fast, accurate summarization |
| Regression | Claude 3.5 Haiku | 0.0 | 2048 | 0.9 | Deterministic evaluation |

---

## 3. Container & Sandbox

### 3.1 Docker Configuration

```dockerfile
# Base Image
FROM python:3.11-slim AS base

# Security Hardening
RUN groupadd -r agent && useradd -r -g agent -d /workspace agent
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Working Directory
WORKDIR /workspace
RUN chown agent:agent /workspace

# Copy Agent Code
COPY --chown=agent:agent ./packages/agents /app/agents
COPY --chown=agent:agent ./packages/sandbox /app/sandbox

# Switch to Non-Root User
USER agent

# Health Check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Entrypoint
ENTRYPOINT ["python", "-m", "sandbox.executor"]
```

### 3.2 Container Runtime Options

| Runtime | Isolation Level | Performance | Use Case |
|---------|----------------|-------------|----------|
| Docker (default) | Container | Native | Development, single-tenant |
| gVisor (runsc) | User-space kernel | ~70% native | Multi-tenant, untrusted code |
| Firecracker | microVM | ~90% native | Maximum isolation |
| Kata Containers | VM-based | ~85% native | Kubernetes integration |

**Recommendation:** Start with Docker for development, migrate to gVisor/Firecracker for production.

### 3.3 Seccomp Profile

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "accept", "access", "arch_prctl", "bind", "brk",
        "clone", "close", "connect", "dup", "dup2",
        "epoll_create", "epoll_wait", "execve", "exit",
        "exit_group", "fcntl", "fstat", "futex", "getcwd",
        "getdents64", "getpid", "getppid", "getsockname",
        "getsockopt", "ioctl", "kill", "listen", "lseek",
        "mmap", "mprotect", "munmap", "nanosleep", "newfstatat",
        "openat", "pipe", "poll", "prlimit64", "read",
        "readlink", "recvfrom", "rt_sigaction", "rt_sigprocmask",
        "sendto", "set_robust_list", "set_tid_address",
        "setsockopt", "shutdown", "sigaltstack", "socket",
        "stat", "statfs", "tgkill", "uname", "unistd",
        "wait4", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Blocked syscalls:** ptrace, mount, kexec_load, init_module, delete_module, bpf, userfaultfd

---

## 4. Static Analysis (SAST)

### 4.1 Semgrep Integration

```python
# Semgrep Configuration
SEMGREP_CONFIG = {
    "rules": [
        # Python
        "p/python.django.security.audit.sql-injection",
        "p/python.lang.security.audit.path-traversal",
        "p/python.requests.security.ssrf",
        "p/python.lang.security.audit.dangerous-system-call",
        "p/python.lang.security.audit.insecure-deserialization",
        "p/python.jinja2.security.template-injection",
        "p/python.flask.security.xss",
        
        # JavaScript/TypeScript
        "p/javascript.express.security.audit.xss",
        "p/javascript.lang.security.audit.path-traversal",
        "p/javascript.lang.security.audit.command-injection",
        "p/javascript.lang.security.audit prototype-pollution",
        
        # Java
        "p/java.lang.security.audit.sql-injection",
        "p/java.lang.security.audit.dangerous-deserialization",
        "p/java.lang.security.audit.xxe",
        
        # Go
        "p/go.lang.security.audit.dangerous-exec-cmd",
        "p/go.lang.security.audit.dangerous-file-path",
        
        # Ruby
        "p/ruby.lang.security.audit.sql-injection",
        "p/ruby.lang.security.audit.command-injection",
    ],
    "severity": ["ERROR", "WARNING"],
    "confidence": ["HIGH", "MEDIUM"],
    "max_target_bytes": 1000000,
    "timeout": 30
}
```

### 4.2 Custom Semgrep Rules

```yaml
# Custom rule for parameterized query detection
rules:
  - id: unparameterized-sql-query
    pattern: |
      $CURSOR.execute("..." + $INPUT)
    message: >
      Unparameterized SQL query detected. Use parameterized queries
      via ORM bindings or ? placeholders.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
```

---

## 5. Dynamic Analysis (DAST)

### 5.1 Exploit Payload Library

```python
# Exploit Payloads by Vulnerability Class
EXPLOIT_PAYLOADS = {
    "SQLi": [
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "' UNION SELECT * FROM users--",
        "admin'--",
        "1' AND SLEEP(5)--",
    ],
    "PathTraversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/",
        "http://[::1]:80/",
        "http://0x7f000001/",
    ],
    "Deserialization": [
        "runcos.system('id')",  # pickle
        "!!python/object/apply:os.system ['id']",  # YAML
        '{"__proto__":{"isAdmin":true}}',  # JSON
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "CommandInjection": [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],
    "OpenRedirect": [
        "//evil.com/phish",
        "/\\evil.com/phish",
        "http://evil.com%23 legitimate.com",
    ],
    "LogInjection": [
        "admin\r\nINFO: User admin logged in",
        "test\n2026-01-01 INFO: Password reset",
    ],
}
```

### 5.2 Exploit Success Detection

```python
# Success Indicators by Vulnerability Class
SUCCESS_INDICATORS = {
    "SQLi": {
        "stdout_patterns": [
            r"root:x:0:0",
            r"admin.*password",
            r"All \d+ records",
        ],
        "file_changes": [],
        "exit_code": 0,
    },
    "PathTraversal": {
        "stdout_patterns": [
            r"root:x:0:0",
            r"/bin/bash",
            r"daemon:x:",
        ],
        "file_changes": [],
        "exit_code": 0,
    },
    "SSRF": {
        "stdout_patterns": [
            r"instance-id",
            r"ami-id",
            r"iam/security-credentials",
        ],
        "file_changes": [],
        "exit_code": 0,
    },
    "CommandInjection": {
        "stdout_patterns": [
            r"root:x:0:0",
            r"/bin/bash",
            r"uid=\d+",
        ],
        "file_changes": [],
        "exit_code": 0,
    },
}
```

---

## 6. Database Schema

### 6.1 Core Tables

```sql
-- Episodes Table
CREATE TABLE episodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    k INTEGER NOT NULL,  -- Episode number
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attacker_rating_before FLOAT,
    developer_rating_before FLOAT,
    attacker_rating_after FLOAT,
    developer_rating_after FLOAT,
    outcome INTEGER,  -- 0=secure, 1=vulnerable
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Tasks Table
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    episode_id UUID REFERENCES episodes(id),
    task_description TEXT NOT NULL,
    vulnerability_class VARCHAR(50) NOT NULL,
    difficulty_tier INTEGER NOT NULL,
    context_files JSONB,
    expected_exploit TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Patches Table
CREATE TABLE patches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    episode_id UUID REFERENCES episodes(id),
    task_id UUID REFERENCES tasks(id),
    code_diff TEXT NOT NULL,
    files_modified JSONB,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Judge Results Table
CREATE TABLE judge_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    episode_id UUID REFERENCES episodes(id),
    patch_id UUID REFERENCES patches(id),
    J INTEGER NOT NULL,  -- 0 or 1
    sast_result JSONB,
    dast_result JSONB,
    exploit_payload TEXT,
    exploit_success BOOLEAN,
    evaluation_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Rules Table
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    episode_id UUID REFERENCES episodes(id),
    rule_text TEXT NOT NULL,
    vulnerability_class VARCHAR(50) NOT NULL,
    source_pattern TEXT,
    recommended_fix TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    regression_checked BOOLEAN DEFAULT FALSE,
    regression_passed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Prompt Versions Table
CREATE TABLE prompt_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version INTEGER NOT NULL,
    parent_version_id UUID REFERENCES prompt_versions(id),
    base_prompt TEXT NOT NULL,
    rules JSONB NOT NULL DEFAULT '[]',
    full_prompt TEXT NOT NULL,
    commit_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(version)
);

-- Elo Ratings Table
CREATE TABLE elo_ratings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_type VARCHAR(20) NOT NULL,  -- 'attacker' or 'developer'
    rating FLOAT NOT NULL DEFAULT 1500,
    episode_id UUID REFERENCES episodes(id),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

---

## 7. API Specification

### 7.1 OpenAPI 3.0 Definition

```yaml
openapi: 3.0.3
info:
  title: CoEvolve Sandbox API
  version: 1.0.0
  description: Automated Adversarial-Training-as-a-Service API

servers:
  - url: http://localhost:8000/api/v1
    description: Development

paths:
  /episodes:
    post:
      summary: Start new training episode
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                vulnerability_classes:
                  type: array
                  items:
                    type: string
                max_duration_minutes:
                  type: integer
      responses:
        '201':
          description: Episode started
          
  /episodes/{episode_id}:
    get:
      summary: Get episode status
      parameters:
        - name: episode_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Episode details
          
  /prompts/current:
    get:
      summary: Get current system prompt
      responses:
        '200':
          description: Current prompt with all rules
          
  /prompts/history:
    get:
      summary: Get prompt version history
      responses:
        '200':
          description: List of prompt versions
          
  /elo:
    get:
      summary: Get current Elo ratings
      responses:
        '200':
          description: Current attacker and developer ratings
          
  /rules:
    get:
      summary: List all distilled rules
      parameters:
        - name: vulnerability_class
          in: query
          schema:
            type: string
      responses:
        '200':
          description: List of rules
```

---

## 8. Testing Strategy

### 8.1 Test Pyramid

```
                    ┌─────────┐
                    │   E2E   │  5%
                    │  Tests  │
                ┌───┴─────────┴───┐
                │  Integration    │  15%
                │     Tests       │
            ┌───┴─────────────────┴───┐
            │      Unit Tests         │  80%
            │    (pytest + mocks)     │
        └─────────────────────────────┘
```

### 8.2 Test Configuration

```python
# pytest configuration
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "unit: Unit tests",
    "integration: Integration tests",
    "e2e: End-to-end tests",
    "slow: Slow tests (>30s)",
]
addopts = "-v --cov=packages --cov-report=html"

# Coverage configuration
[tool.coverage.run]
source = ["packages"]
omit = ["tests/*", "*/migrations/*"]

[tool.coverage.report]
fail_under = 80
show_missing = true
```

### 8.3 Test Categories

| Category | Count Target | Execution Time | Tools |
|----------|-------------|----------------|-------|
| Unit Tests | 500+ | <30s total | pytest, pytest-mock |
| Integration Tests | 100+ | <5min total | pytest, docker |
| E2E Tests | 20+ | <30min total | pytest, docker-compose |
| Performance Tests | 10+ | <10min total | locust, prometheus |

---

## 9. Deployment

### 9.1 Docker Compose (Development)

```yaml
version: '3.8'

services:
  api:
    build: ./packages/api
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/coevolve
      - REDIS_URL=redis://redis:6379
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      - db
      - redis
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - coevolve

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=coevolve
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - coevolve

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - coevolve

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./packages/telemetry/prometheus/config.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - coevolve

  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./packages/telemetry/grafana/dashboards:/var/lib/grafana/dashboards
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - coevolve

volumes:
  postgres_data:

networks:
  coevolve:
    driver: bridge
```

### 9.2 Kubernetes (Production)

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coevolve-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: coevolve-api
  template:
    metadata:
      labels:
        app: coevolve-api
    spec:
      containers:
        - name: api
          image: coevolve-sandbox/api:latest
          ports:
            - containerPort: 8000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: coevolve-secrets
                  key: database-url
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
```

---

## 10. Cost Estimation

### 10.1 Per-Episode Cost Breakdown

| Component | Calls | Tokens (Est.) | Cost (Claude 3.5 Sonnet) |
|-----------|-------|---------------|-------------------------|
| Attacker Generation | 1 | 2000 in / 1000 out | $0.021 |
| Developer Execution | 3-5 | 5000 in / 3000 out | $0.060 |
| Distillation | 0-1 | 1000 in / 500 out | $0.004 |
| Regression Check | 0-1 | 2000 in / 1000 out | $0.008 |
| **Total** | | | **~$0.09** |

### 10.2 Scaling Cost Projections

| Episodes | Cost/Episode | Total Cost | Duration |
|----------|--------------|------------|----------|
| 100 | $0.09 | $9 | 1 hour |
| 1,000 | $0.09 | $90 | 10 hours |
| 10,000 | $0.08 (bulk) | $800 | 4 days |
| 100,000 | $0.07 (enterprise) | $7,000 | 40 days |

### 10.3 Cost Optimization Strategies

1. **Use Haiku for Distiller/Regression**: 10x cheaper than Sonnet
2. **Batch Regression Checks**: Run multiple tasks in single API call
3. **Cache Embeddings**: Reuse sentence-transformer embeddings
4. **Local Models**: Use Qwen2.5 for cost-sensitive deployments
5. **Prompt Caching**: Cache common system prompts

---

## 11. Security Considerations

### 11.1 API Security

```python
# Security middleware
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()
security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token."""
    token = credentials.credentials
    if not verify_jwt(token):
        raise HTTPException(status_code=401, detail="Invalid token")
    return decode_jwt(token)

@app.post("/api/v1/episodes")
async def create_episode(
    episode: EpisodeCreate,
    user = Depends(verify_token)
):
    """Create new episode (authenticated)."""
    pass
```

### 11.2 Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://host:6379
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# Optional
GRAFANA_ADMIN_PASSWORD=admin
SENTRY_DSN=https://...@sentry.io/...
LOG_LEVEL=INFO
```

### 11.3 Secrets Management

- Never commit secrets to Git
- Use environment variables or secret managers
- Rotate API keys regularly
- Use vault solutions (HashiCorp Vault, AWS Secrets Manager) for production

---

## 12. Summary

| Category | Primary Choice | Alternative | Justification |
|----------|---------------|-------------|---------------|
| Language | Python 3.11+ | - | ML ecosystem, rapid development |
| API | FastAPI | Flask | Async, performance, auto-docs |
| Database | PostgreSQL | - | ACID, JSON, reliability |
| Cache | Redis | - | In-memory, pub/sub |
| LLM (Primary) | Claude 3.5 Sonnet | GPT-4o | Best reasoning, code generation |
| LLM (Fast) | Claude 3.5 Haiku | GPT-4o-mini | Cost-effective distillation |
| Container | Docker | gVisor | Industry standard, security features |
| SAST | Semgrep | Bandit | Extensible, multi-language |
| Metrics | Prometheus | - | Time-series, PromQL |
| Dashboards | Grafana | - | Rich visualization, alerting |
| Testing | pytest | - | Rich ecosystem, async support |
