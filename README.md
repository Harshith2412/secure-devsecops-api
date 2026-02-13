# Secure DevSecOps API Platform

A production-grade Zero-Trust Secure API Platform built with FastAPI, demonstrating enterprise-level DevSecOps practices, comprehensive security controls, and automated security testing pipelines.


This project showcases a **security-first approach** to API development, implementing industry best practices for authentication, authorization, and data protection. Built as a portfolio demonstration of DevSecOps expertise, it features comprehensive security controls, automated testing, and a complete CI/CD security pipeline.

### Purpose
- Demonstrate enterprise-grade security engineering practices
- Showcase DevSecOps pipeline implementation
- Illustrate secure-by-design architecture
- Provide reference implementation for secure API development

## Key Features

### Security Features

#### Authentication & Authorization
- **JWT-based Authentication** with short-lived access tokens (15 min)
- **Refresh Token Rotation** with automatic revocation on reuse
- **Token Reuse Detection** - Security breach response mechanism
- **Argon2id Password Hashing** - Industry-standard cryptographic hashing
- **Role-Based Access Control (RBAC)** - User and Admin roles
- **Session Management** - Secure token lifecycle management

#### Protection Mechanisms
- **Rate Limiting** - Prevents brute force attacks (5 login attempts/min)
- **SQL Injection Prevention** - SQLAlchemy ORM with parameterized queries
- **Input Validation** - Pydantic strict mode with comprehensive validation
- **Security Headers** - OWASP recommended headers (CSP, X-Frame-Options, etc.)
- **IDOR Prevention** - User context validation on all operations
- **XSS Protection** - Input sanitization and output encoding

#### Audit & Monitoring
- **Comprehensive Audit Logging** - All security events tracked
- **Event Types Logged**: 
  - Authentication (success/failure)
  - Token operations (refresh, revoke, reuse detection)
  - Authorization violations
  - Rate limit breaches
  - Admin actions

### DevSecOps Pipeline

- **SAST** - Static Analysis Security Testing with Bandit
- **Dependency Scanning** - Vulnerability detection with pip-audit
- **Container Scanning** - Image security with Trivy
- **Secrets Detection** - Credential leak prevention with Gitleaks
- **SBOM Generation** - Software Bill of Materials with Syft
- **Automated Testing** - 19 unit tests with 100% pass rate
- **Linting** - Code quality enforcement with Ruff


### Security Layers

1. **Transport Security** - HTTPS with HSTS headers
2. **Request Filtering** - Rate limiting and input validation
3. **Authentication** - JWT token validation
4. **Authorization** - RBAC enforcement
5. **Data Access** - ORM with parameterized queries
6. **Audit Trail** - Comprehensive security event logging
7. **Error Handling** - Generic error messages (no info disclosure)
8. **Response Security** - Security headers on all responses

## Security Controls

### Threat Mitigation Matrix

| Threat | Control | Test Coverage |
|--------|---------|---------------|
| Brute Force | Rate Limiting (5 attempts/min) 
| SQL Injection | ORM + Parameterized Queries 
| Token Theft | Refresh Token Rotation 
| Token Replay | Reuse Detection & Revocation 
| IDOR | User Context Validation |
| Privilege Escalation | Server-side RBAC 
| XSS | Input Validation & Sanitization 
| JWT Tampering | Signature Verification 
| Weak Passwords | Policy Enforcement (12+ chars) 
| Session Hijacking | Short-lived tokens + Rotation 

### Password Policy
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Argon2id hashing with automatic salt generation



### Security Testing Breakdown
| Domain | Tests | Status |
|--------|-------|--------|
| Password Security | 4 | 100% |
| JWT Authentication | 5 | 100% |
| RBAC Authorization | 2 | 100% |
| Input Validation | 6 | 100% |
| Rate Limiting | 1 | 100% |
| Configuration | 1 | 100% |



### Performance
- **API Response Time**: < 100ms (average)
- **Token Generation**: < 50ms
- **Password Hashing**: ~200ms (intentionally slow - security)
- **Database Queries**: Indexed and optimized


## DevSecOps Pipeline

The GitHub Actions CI/CD pipeline automatically runs on every push:

### Pipeline Stages

1. **Linting** - Code quality with Ruff
2. **Unit Tests** - 19 security-focused tests
3. **SAST** - Bandit static analysis
4. **Dependency Scan** - pip-audit for vulnerabilities
5. **Secrets Scan** - Gitleaks credential detection
6. **Container Scan** - Trivy image security
7. **SBOM Generation** - Syft software bill of materials

### Security Gate Policy

Pipeline fails if:
- Any test fails
- HIGH or CRITICAL severity vulnerabilities found
- Secrets detected in code
- Linting errors present



## Security Considerations

### Production Deployment Checklist

- [ ] Change `SECRET_KEY` to a cryptographically secure random value (32+ characters)
- [ ] Enable HTTPS and uncomment HSTS headers in `headers.py`
- [ ] Set `DEBUG=False` in production environment
- [ ] Use environment-specific database credentials
- [ ] Enable database connection encryption (SSL/TLS)
- [ ] Set up log aggregation (ELK, Splunk, CloudWatch)
- [ ] Configure alerting for security events
- [ ] Implement backup and disaster recovery
- [ ] Set up rate limiting at infrastructure level (CloudFlare, AWS WAF)
- [ ] Enable database audit logging
- [ ] Review and adjust token expiration times for your use case
- [ ] Implement IP whitelisting for admin endpoints
- [ ] Set up monitoring and health checks
- [ ] Configure CORS policies appropriately
- [ ] Review security headers for your specific requirements


## Technologies Used

### Core Framework
- **FastAPI 0.109.0** - Modern, fast web framework
- **Uvicorn** - ASGI server
- **Python 3.11** - Programming language

### Security
- **python-jose** - JWT implementation
- **PyJWT** - JSON Web Tokens
- **argon2-cffi** - Password hashing
- **Pydantic** - Data validation

### Database
- **SQLAlchemy 2.0** - ORM
- **PyMySQL** - MySQL driver
- **MySQL 8.0** - Database

### DevSecOps Tools
- **Pytest** - Testing framework
- **Bandit** - SAST scanner
- **Ruff** - Linter
- **pip-audit** - Dependency scanner
- **Trivy** - Container scanner
- **Gitleaks** - Secrets detector
- **Syft** - SBOM generator

### Infrastructure
- **Docker** - Containerization
- **Docker Compose** - Multi-container management
- **GitHub Actions** - CI/CD


## License

This project is created for educational and portfolio purposes.



## Acknowledgments

- OWASP for security best practices
- FastAPI community for excellent documentation
- Automotive cybersecurity research community
