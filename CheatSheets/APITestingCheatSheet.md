# OSCP API Testing Cheat Sheet
Focused on discovering insecure API behavior, including endpoints that evaluate user input and may allow code execution (Hetemit-style patterns).

---

## 1. API Recon & Mapping

### Identify API Surface
Look for common API paths:
- `/api`
- `/v1`, `/v2`
- `/internal`
- `/admin`
- `/debug`
- `/graphql`
- `/swagger`, `/openapi`, `/api-docs`, `/docs`

Check response headers:
- `Server`
- `X-Powered-By`
- Framework error messages or stack traces

---

### Endpoint Discovery

#### Passive
- Proxy browser traffic through Burp
- Watch `fetch` / `XHR` requests
- Review JS files for hidden endpoints
- Check `robots.txt`, `sitemap.xml`

#### Active
- Directory brute forcing against API roots:
  - `/api/`
  - `/internal/`
  - `/admin/`

---

### Per-Endpoint Notes
For every endpoint, record:
- HTTP methods allowed
- Authentication required?
- Input locations:
  - URL path
  - Query string
  - JSON body
  - Headers
- Content-Types accepted

---

## 2. Burp Suite Workflow (OSCP Practical)

1. Intercept API requests
2. Send to Repeater
3. Modify:
   - IDs
   - JSON fields
   - Headers
4. Use Comparer to detect subtle response differences
5. Use Intruder sparingly (IDs, roles, rate limits)

---

## 3. Authentication Testing

### Token Checks
- No token
- Empty token
- Expired token
- Token reuse between users

### JWT Issues
- `alg=none`
- Weak signature validation
- Token accepted via query string
- Token accepted from another tenant/user

### API Keys
- Hardcoded in JS?
- Shared across users?
- Environment reuse (dev/prod)?

---

## 4. Authorization Testing

### BOLA / IDOR (Object-Level)
Test IDs in:
- `/api/users/123`
- `?userId=123`
- `{ "userId": 123 }`

Procedure:
1. Capture request for your object
2. Change ID
3. Look for:
   - Unauthorized data
   - Same status code with different data
   - Missing authorization errors

---

### Function-Level Authorization
Attempt restricted functions as low-priv user:
- `/admin/*`
- `/internal/*`
- `/debug/*`
- `/config`
- `/users/delete`

---

## 5. Input Handling & Injection

### Injection Locations
- JSON fields
- Nested JSON objects
- Arrays
- Headers (`X-Forwarded-For`, `Host`)
- File uploads

### Vulnerability Types
- SQL Injection
- Command Injection
- SSRF
- XXE
- Insecure Deserialization

---

## 6. Dangerous Pattern: Input Evaluation / Code Execution

### High-Risk Endpoint Names
- `/verify`
- `/execute`
- `/eval`
- `/run`
- `/compile`
- `/generate`
- `/render`
- `/calculate`

### Suspicious Parameters
- `code`
- `expr`
- `expression`
- `template`
- `script`
- `query`
- `payload`

---

### Common Backend Evaluation Functions

#### Python
- `eval()`
- `exec()`
- `compile()`
- Unsafe Jinja2 template rendering

#### Node / JavaScript
- `eval()`
- `Function()`
- `vm.runInNewContext()`
- `child_process.exec()`

#### PHP
- `eval()`
- `system()`
- `exec()`
- `shell_exec()`
- `passthru()`

#### Java
- `Runtime.getRuntime().exec()`
- `ProcessBuilder`
- Script engines (JSR-223)

#### Ruby
- `eval`
- Backticks
- `system()`

---

## 7. Safe Evaluation Detection (Non-Destructive)

### Math Canary
```
2*3
```
If response is `6`, evaluation is likely occurring.

### Error Probing
```
doesNotExist123
```
Interpreter-style errors indicate code execution paths.

### Time-Based Testing
- Try benign delays (only in lab environments)
- Look for response timing changes

---

## 8. If Evaluation Is Confirmed

- Pivot from expression execution to system interaction
- Start with minimal, controlled proof
- Avoid destructive payloads
- Focus on:
  - Environment access
  - Command execution paths
  - File read/write capabilities

---

## 9. API Fuzzing Tips

### Parameter Discovery
Try adding fields:
- `role`
- `isAdmin`
- `admin`
- `debug`
- `cmd`
- `execute`

### Data Type Confusion
- `1` vs `"1"`
- Arrays instead of scalars
- Nested objects

### Content-Type Confusion
If JSON fails, try:
- `application/x-www-form-urlencoded`
- `multipart/form-data`

---

## 10. OSCP API Testing Checklist

- [ ] Enumerate endpoints
- [ ] Identify authentication mechanism
- [ ] Test unauthenticated access
- [ ] BOLA / IDOR everywhere
- [ ] Function-level authorization
- [ ] Mass assignment
- [ ] Rate limiting
- [ ] Injection testing
- [ ] File upload abuse
- [ ] Input evaluation / code execution patterns

---

## Notes
APIs often fail quietly. Small differences in responses, timing, or error handling are frequently the key signal. Focus on behavior, not just errors.

