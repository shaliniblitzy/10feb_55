# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification


### 0.1.1 Core Security Objective

Based on the security concern described, the Blitzy platform understands that the security vulnerability to resolve is a **comprehensive remediation of 172 vulnerability entries** spanning three distinct categories — dependency CVEs, SAST source-code flaws, and hardcoded secret exposures — across the six Java microservice modules of the GAE-GNP Facultativo reinsurance platform (project identifier `10feb_55`).

- **Vulnerability Category:** Multiple vulnerabilities (Dependency vulnerability + Code vulnerability + Configuration weakness)
- **Severity Level:** Critical — The vulnerability portfolio includes 11 Critical-severity findings (including all 4 hardcoded Apigee tokens and the highest-CVSS Tomcat CVEs), 79 High-severity findings, and 82 Medium-severity findings
- **Security Requirements with Enhanced Clarity:**
  - **F-001 — Dependency Vulnerability Remediation:** Upgrade 16 open-source libraries to patched versions that resolve 23 unique CVEs across all 6 modules, eliminating known attack vectors including Remote Code Execution (Logback, Tomcat), path traversal (Tomcat, Spring MVC), authorization bypass (Spring Security), HTTP/2 DDoS (Netty), request smuggling (Netty), and Denial of Service (Commons FileUpload, Commons Lang3)
  - **F-002 — SAST Remediation (CWE-117 Log Injection):** Apply `Encode.forJava()` wrappers from the OWASP Java Encoder library to 27 specific log statement locations across 8 Java service files in Modules 1, 2, 3, and 4, eliminating log injection vulnerabilities that could allow attackers to forge audit entries or exploit downstream log analysis tools
  - **F-003 — Secret Detection Remediation:** Externalize 4 hardcoded Apigee API Gateway tokens (`l7xxc883ea7da3d047e0ba28114ec` pattern) from `application.yml` and `application-test.yml` configuration files in Modules 1, 3, and 5, replacing them with references to GCP Secret Manager or environment variables
- **Implicit Security Needs:**
  - Backward compatibility must be preserved — all patched versions must be drop-in replacements for existing functionality
  - Zero downtime — the remediation changes must not alter runtime behavior, service topology, or deployment configuration beyond secret management
  - Compliance alignment — the 172-entry remediation represents a mandatory security posture improvement before GCP deployment acceptance, governed by the three-scanner convergence model (Dependency Scanner, SAST Scanner, Secret Detection Scanner) all returning zero findings simultaneously

### 0.1.2 Special Instructions and Constraints

- **CRITICAL Directive — Minimal Change Discipline:** Only changes necessary to remediate the 172 identified vulnerabilities are permitted (Constraint C-001). No new features, capabilities, refactoring, or code quality improvements beyond security fixes are allowed (Constraints C-002 through C-004)
- **Governing Constraints:**
  - C-001: Only vulnerability remediation changes permitted
  - C-002: No new features or capabilities
  - C-003: No architectural modifications
  - C-004: No performance optimization or refactoring
  - C-005: Newly discovered vulnerabilities beyond the 172 entries are noted but not fixed unless explicitly specified
  - C-006: No database modifications
  - C-007: No infrastructure changes beyond secret management
  - C-008: Every security change must include clear inline comments explaining the specific threat addressed
- **Documentation Requirement:** All version changes in `build.gradle` must include inline comments referencing the specific CVEs being resolved. All `Encode.forJava()` usages must be accompanied by inline comments explaining CWE-117 and the specific threat of log injection
- **Change Scope Preference:** Minimal — Apply the smallest possible change that completely addresses each vulnerability
- **Key Assumptions:**
  - A-001: All 16 target library versions are available in Maven Central or internal artifact repositories
  - A-002: The OWASP Java Encoder library is approved within GNP's technology governance framework
  - A-003: An externalized secret management mechanism (GCP Secret Manager or environment variables) is available in the deployment environment
  - A-004: Existing unit test suites provide sufficient coverage to detect functional regressions
  - A-005: The 172 vulnerability entries represent the complete and authoritative set of findings

### 0.1.3 Technical Interpretation

This security vulnerability portfolio translates to the following technical fix strategy:

- To resolve **F-001** (Dependency Vulnerabilities), we will **update version declarations** in the `build.gradle` (Groovy DSL) file of each affected module, upgrading 16 packages from their current vulnerable versions to the minimum patched versions specified in the security advisory matrix. This includes coordinated upgrades across the Spring ecosystem (spring-core, spring-web, spring-webmvc, spring-security-core), the embedded Tomcat container (tomcat-embed-core), the gRPC/Netty communication layer, logging frameworks (Logback, Log4j), Apache Commons utilities, and the AssertJ test framework
- To resolve **F-002** (SAST Findings), we will **wrap user-controlled input variables** in 27 specific log statements across 8 Java service files with `Encode.forJava()` from the OWASP Java Encoder library. This requires adding the OWASP Encoder dependency to `build.gradle` for Modules 1, 2, 3, and 4, and adding the corresponding import statement to each affected Java file
- To resolve **F-003** (Secret Exposure), we will **replace hardcoded Apigee token strings** in 4 YAML configuration files across Modules 1, 3, and 5 with externalized references (e.g., `${APIGEE_TOKEN}` environment variable placeholders or GCP Secret Manager lookups)
- **User's Understanding Level:** Explicit CVE/vulnerability — The user (via the PRD) has provided a comprehensive vulnerability report with specific CVE numbers, CWE identifiers, affected package names and versions, exact file paths and line numbers, and severity classifications


## 0.2 Vulnerability Research and Analysis


### 0.2.1 Initial Assessment

All security-related information extracted from the project's authoritative PRD and Technical Specification:

- **CVE Numbers Mentioned:** CVE-2024-47554, CVE-2024-22243, CVE-2024-22259, CVE-2024-22262, CVE-2024-38819, CVE-2024-38820, CVE-2025-24813, CVE-2025-24814, CVE-2024-21634, CVE-2024-7254, CVE-2024-34155, CVE-2024-34156, CVE-2024-34158, CVE-2024-56337, CVE-2025-22223, CVE-2025-24228, CVE-2025-41248, CVE-2025-41249, CVE-2025-21549, CVE-2024-25710, CVE-2024-26308, CVE-2026-24400, plus 1 additional Tomcat CVE (7 total Tomcat CVEs resolved by upgrading to ≥ 10.1.47)
- **Vulnerability Names:** Log Injection (CWE-117), Path Traversal (Tomcat, Spring MVC), Authorization Bypass (Spring Security), Remote Code Execution (Logback, Tomcat), HTTP/2 DDoS (Netty), Request Smuggling (Netty), Denial of Service (Commons FileUpload, Commons Lang3), XXE (AssertJ), Secret Exposure (Apigee Tokens)
- **Affected Packages:** tomcat-embed-core, spring-core, spring-web, spring-webmvc, spring-security-core, grpc-netty-shaded, netty-codec-http2, netty-codec-http, netty-codec, logback-classic, logback-core, log4j-to-slf4j, commons-io, commons-fileupload2-jakarta-servlet6, commons-lang3, assertj-core
- **Symptoms Described:** 172 total vulnerability entries distributed as 23 unique CVEs across 16 packages (dependency), 27 CWE-117 findings across 8 Java files (SAST), and 4 hardcoded Apigee tokens across 3 modules (secrets)
- **Security Advisories Referenced:** OWASP CWE-117 guidelines, Apache Tomcat Security advisories, Spring Security advisories, Netty/gRPC security bulletins

### 0.2.2 Required Web Research — Findings

Research was conducted across official CVE databases, security advisories from package maintainers, OWASP documentation, and GitHub security advisories. Key findings are documented below.

**Apache Tomcat (tomcat-embed-core 10.1.41 → ≥ 10.1.47):**

Research reveals that the current version 10.1.41 is affected by multiple CVEs including CVE-2025-24813 and CVE-2025-55752 (directory traversal leading to RCE) and CVE-2025-55754 (ANSI escape sequence injection in logs). <cite index="7-3,7-4">CVE-2025-55754 affects Tomcat 10.1.0-M1 to 10.1.46 and involves Tomcat not escaping ANSI escape sequences in log messages, which on Windows systems with ANSI-supporting consoles could allow an attacker to inject escape sequences to manipulate the console and clipboard.</cite> <cite index="4-2">CVE-2025-55752 affects Apache Tomcat from 10.1.0-M1 through 10.1.44.</cite> <cite index="4-5">Users are recommended to upgrade to version 10.1.45 or later, which fixes the issue.</cite> The Tech Spec mandates ≥ 10.1.47 to resolve all seven Tomcat CVEs simultaneously.

**Spring Security (spring-security-core 6.5.0 → ≥ 6.5.4):**

<cite index="11-3,11-4,11-5">CVE-2025-41248 is rated MEDIUM severity (September 2025). The Spring Security annotation detection mechanism may not correctly resolve annotations on methods within type hierarchies with a parameterized super type with unbounded generics, resulting in an authorization bypass when using @PreAuthorize and other method security annotations.</cite> <cite index="13-4">The Spring Security 6.4.11 and 6.5.5 open source releases address CVE-2025-41248.</cite> <cite index="12-5">Both issues were rated CVSS 4.4 (Medium severity), though these vulnerabilities pose meaningful risks for applications relying on method-level security annotations such as @PreAuthorize.</cite>

**Spring Framework (spring-core 6.2.7 → ≥ 6.2.11):**

<cite index="13-5">The Spring Framework 6.2.11 open source release addresses CVE-2025-41249.</cite> <cite index="20-9">CVE-2025-41249 is a closely related flaw in the Spring Framework itself, impacting versions 6.2.0 through 6.2.10.</cite>

**CWE-117 Log Injection (OWASP Java Encoder):**

<cite index="21-17,21-18,21-19">CWE 117: Improper Output Sanitization for Logs is a logging-specific example of CRLF Injection. It occurs when a user maliciously or accidentally inserts line-ending characters into data that will be written into a log. Because a line break is a record-separator for log events, unexpected line breaks can cause issues with parsing logs, or can be used by attackers to forge log entries.</cite> <cite index="22-31,22-32,22-33">The OWASP Java Encoder library is the recommended remediation approach. Adding the OWASP Java Encoder dependency using Maven groupId `org.owasp.encoder`, artifactId `encoder`, and then encoding the output before logging eliminates the vulnerability.</cite>

### 0.2.3 Vulnerability Classification

| Classification Dimension | F-001 (Dependencies) | F-002 (SAST) | F-003 (Secrets) |
|---|---|---|---|
| Vulnerability Type | Multiple: Path Traversal, RCE, Authorization Bypass, DoS, HTTP/2 DDoS, Request Smuggling, XXE | CWE-117: Log Injection (CRLF Injection) | Hardcoded Credentials (Secret Exposure) |
| Attack Vector | Network | Network (indirect via log manipulation) | Network / Repository Access |
| Exploitability | High (known CVEs with public advisories) | Medium (requires user-controlled input reaching log statements) | High (tokens visible in source control) |
| Impact | Confidentiality, Integrity, Availability | Integrity (audit trail forgery), Availability (log analysis disruption) | Confidentiality (unauthorized API gateway access) |
| Root Cause | Outdated library versions with known security patches available | Unsanitized user input written directly to log files | API credentials hardcoded in YAML configuration files committed to source control |

### 0.2.4 Web Search Research Conducted

- **Official Security Advisories Reviewed:**
  - Apache Tomcat Security Pages: `tomcat.apache.org/security-10.html`, `tomcat.apache.org/security-11.html`
  - Spring Security CVE Page: `spring.io/security/cve-2025-41248`
  - Spring Framework Blog: `spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes`
  - NVD: `nvd.nist.gov/vuln/detail/CVE-2025-55754`
  - OWASP Java Encoder Project: `owasp.org/www-project-java-encoder`
  - MITRE CWE-117: `cwe.mitre.org/data/definitions/117.html`
  - SEI CERT: `wiki.sei.cmu.edu/confluence/display/java/IDS03-J`
- **Recommended Mitigation Strategies:**
  - Dependency upgrades to patched versions (primary)
  - `Encode.forJava()` wrapping for CWE-117 (OWASP recommended)
  - Environment variable externalization for secrets (GCP-native)
- **Alternative Solutions Considered and Rejected:**
  - ESAPI Logger replacement (rejected: too invasive, violates C-001 minimal change constraint)
  - Structured JSON logging to prevent CWE-117 (rejected: architectural change, violates C-003)
  - HashiCorp Vault for secrets (rejected: infrastructure change, violates C-007)


## 0.3 Security Scope Analysis


### 0.3.1 Affected Component Discovery

A comprehensive search of the Technical Specification and vulnerability reports reveals the following scope of impact. The vulnerability affects **approximately 30+ files across 6 module directories**, spanning build configurations, Java source files, and YAML configuration files.

**Affected File Categories:**

- **Dependency Manifests:** 6 × `build.gradle` (one per module) — all require version updates for F-001
- **Java Source Files (SAST):** 8 Java service files across 4 modules require `Encode.forJava()` wrapping for F-002
- **YAML Configuration Files (Secrets):** 4 YAML files across 3 modules require token externalization for F-003
- **Total Vulnerability Distribution by Module:**

| Module | Name | F-001 Entries | F-002 Findings | F-003 Findings | Total |
|---|---|---|---|---|---|
| Module 1 | administrador | 21 | 4 | 1 | 26 |
| Module 2 | catalogos | 21 | 1 | 0 | 22 |
| Module 3 | procesos | 21 | 20 | 1 | 42 |
| Module 4 | reportes | 22 | 2 | 0 | 24 |
| Module 5 | sincronizador-archivos | 19 | 0 | 2 | 21 |
| Module 6 | tarifas | 37 | 0 | 0 | 37 |
| **Total** | | **141** | **27** | **4** | **172** |

### 0.3.2 Root Cause Identification

**F-001 — Dependency Vulnerabilities:**
The identified vulnerabilities exist in the `build.gradle` dependency declarations of all 6 modules due to **outdated library versions** that were current at the time of initial development but have since had security patches released. The root cause is the natural lifecycle of open-source dependencies where new CVEs are discovered and patched over time. The current versions predate the security advisories for the 23 CVEs identified.

- **Direct usage locations:** All 6 `build.gradle` files
- **Indirect dependencies:** Transitive dependency chains (e.g., `grpc-netty-shaded` pulls in Netty components; Spring Boot starter pulls in Tomcat)
- **Configuration enablers:** Gradle dependency resolution settings that resolve to specific vulnerable versions

**F-002 — SAST (CWE-117) Vulnerabilities:**
Investigation reveals the vulnerability stems from **8 Java service classes** where user-controlled input (request parameters, entity identifiers, business object fields) is passed directly to SLF4J/Logback log statements without sanitization. The root cause is the absence of output encoding before log writes — a common pattern in enterprise Java applications.

- **Direct usage locations:**
  - `LoginService.java` (Module 1) — 1 finding
  - `RolService.java` (Module 1) — 1 finding
  - `UsuarioService.java` (Module 1) — 2 findings
  - `ReaseguradoraService.java` (Module 2) — 1 finding
  - `OfertaService.java` (Module 3) — 4 findings
  - `MantenimientoMaestroService.java` (Module 3) — 3 findings
  - `PolizaService.java` (Module 3) — 13 findings (lines 86–360)
  - `ArchivosUsuarioService.java` (Module 4) — 2 findings

**F-003 — Secret Exposure:**
The vulnerability stems from **hardcoded Apigee API Gateway tokens** embedded directly in Spring YAML configuration files. The token pattern `l7xxc883ea7da3d047e0ba28114ec` is present at specific line numbers in configuration files that are committed to source control.

- **Direct usage locations:**
  - Module 1 `application.yml` (line 64)
  - Module 3 `application.yml` (line 64)
  - Module 5 `application.yml` (line 63)
  - Module 5 `application-test.yml` (line 52)

### 0.3.3 Current State Assessment

| Category | Current State | Exposure |
|---|---|---|
| Vulnerable `tomcat-embed-core` | 10.1.41 | Public-facing via embedded servlet container; 7 CVEs including RCE path |
| Vulnerable `spring-security-core` | 6.5.0 | API endpoints; authorization bypass for `@PreAuthorize` methods |
| Vulnerable `spring-core` | 6.2.7 | All modules; annotation detection flaw enables security check bypass |
| Vulnerable `grpc-netty-shaded` | 1.70.0 | Inter-service gRPC; HTTP/2 DDoS and request smuggling |
| Vulnerable `logback-classic/core` | 1.5.18 | All modules; Remote Code Execution vector |
| CWE-117 log injection | 27 unsanitized log statements | Internal — log forging in authentication, business logic, and file management services |
| Hardcoded Apigee tokens | 4 YAML entries across 3 modules | Repository access exposes API gateway credentials; Critical severity |
| Scope of exposure | Combination of public-facing (Tomcat, Apigee), internal (gRPC, logging), and source-control (secrets) | Enterprise reinsurance platform handling sensitive financial data |


## 0.4 Version Compatibility Research


### 0.4.1 Secure Version Identification

For each vulnerable dependency, the following table identifies the current version, the minimum patched version, and the rationale sourced from official security advisories.

| Package | Current Version | First Patched Version | Recommended / Target Version | Breaking Changes | Advisory Source |
|---|---|---|---|---|---|
| tomcat-embed-core | 10.1.41 | 10.1.45 (CVE-2025-55752/55754) | ≥ 10.1.47 (resolves all 7 CVEs) | None (drop-in) | Apache Tomcat Security |
| spring-core | 6.2.7 | 6.2.11 (CVE-2025-41249) | ≥ 6.2.11 | None (patch release) | spring.io/security |
| spring-web | 6.2.7 | 6.2.8 | ≥ 6.2.8 | None (patch release) | Spring Security Advisories |
| spring-webmvc | 6.2.7 | 6.2.10 | ≥ 6.2.10 | None (patch release) | Spring Security Advisories |
| spring-security-core | 6.5.0 | 6.5.4 (CVE-2025-41248) | ≥ 6.5.4 | None (patch release) | spring.io/security/cve-2025-41248 |
| grpc-netty-shaded | 1.70.0 | 1.75.0 | ≥ 1.75.0 | Verify gRPC API compatibility | gRPC GitHub Releases |
| netty-codec-http2 | 4.1.121.Final | 4.1.129.Final | ≥ 4.1.129.Final | None (patch release) | Netty Security Advisories |
| netty-codec-http | 4.1.121.Final | 4.1.125.Final | ≥ 4.1.125.Final | None (patch release) | Netty Security Advisories |
| netty-codec | 4.1.121.Final | 4.1.124.Final | ≥ 4.1.124.Final | None (patch release) | Netty Security Advisories |
| logback-classic | 1.5.18 | 1.5.19 | ≥ 1.5.19 | None (patch release) | Logback Changelog |
| logback-core | 1.5.18 | 1.5.19 | ≥ 1.5.19 | None (patch release) | Logback Changelog |
| log4j-to-slf4j | 2.24.3 | 2.24.4 | ≥ 2.24.4 | None (patch release) | Apache Log4j2 Security |
| commons-io | 2.11.0 | 2.18.0 | ≥ 2.18.0 | Minor API additions only | Apache Commons IO |
| commons-fileupload2-jakarta-servlet6 | 2.0.0-M2 | 2.0.0-M3 | ≥ 2.0.0-M3 | None (milestone update) | Apache Commons FileUpload |
| commons-lang3 | 3.17.0 | 3.18.0 | ≥ 3.18.0 | None (minor release) | Apache Commons Lang |
| assertj-core | 3.27.3 | 3.27.7 | ≥ 3.27.7 | None (patch release) | AssertJ GitHub |

### 0.4.2 Compatibility Verification

**Spring Ecosystem Coordination:**
The four Spring packages must be upgraded in coordination to prevent version misalignment:
- `spring-core` ≥ 6.2.11 requires `spring-web` ≥ 6.2.8 and `spring-webmvc` ≥ 6.2.10 (same framework release train)
- `spring-security-core` ≥ 6.5.4 is designed to work with Spring Framework 6.2.x (verified via Spring's compatibility matrix)
- All four Spring upgrades are within the same major.minor train, ensuring binary compatibility

**Tomcat Compatibility:**
- `tomcat-embed-core` ≥ 10.1.47 remains within the 10.1.x line, fully compatible with Spring Framework 6.2.x and Spring Boot 3.x
- No servlet API version change; stays on Jakarta Servlet 6.0

**gRPC/Netty Compatibility:**
- `grpc-netty-shaded` ≥ 1.75.0 bundles its own Netty internally (shaded), avoiding classpath conflicts with direct Netty in Module 4
- Module 4's direct Netty libraries (`netty-codec-http2` ≥ 4.1.129.Final, `netty-codec-http` ≥ 4.1.125.Final, `netty-codec` ≥ 4.1.124.Final) are all within the 4.1.x series and are backward compatible

**Module 4 Divergence — Special Consideration:**
Module 4 (`reportes`) uses direct Netty artifacts instead of `grpc-netty-shaded`, requiring three independent upgrade paths. The three Netty packages have different minimum target versions (4.1.124, 4.1.125, 4.1.129) because they address different CVEs. The highest minimum (4.1.129.Final for `netty-codec-http2`) satisfies all three, but each must be explicitly declared at its own minimum to maintain traceability to specific CVEs.

**OWASP Java Encoder (New Dependency for F-002):**
- `org.owasp.encoder:encoder` is a lightweight, zero-transitive-dependency library
- Compatible with Java 8+ and all Spring Framework versions
- No conflicts with existing dependencies
- Requires governance approval per Assumption A-002

**No Package Replacements Required:**
All vulnerable packages have patched versions available. No package needs to be replaced with an alternative library.


## 0.5 Security Fix Design


### 0.5.1 Minimal Fix Strategy

**PRINCIPLE:** Apply the smallest possible change that completely addresses each vulnerability. Every modification must trace directly to one of the 172 documented vulnerability entries. No refactoring, no feature additions, no code quality improvements.

**Fix Approach:** Combination of Dependency Updates (F-001), Code Patches (F-002), and Configuration Changes (F-003).

**F-001 — Dependency Vulnerability Remediation (Dependency Update):**

For each of the 16 vulnerable packages, upgrade the version declaration in the module's `build.gradle` file to the minimum patched version. The fix is a one-line-per-package change in each affected module's build configuration.

- "Upgrade `tomcat-embed-core` from 10.1.41 to ≥ 10.1.47 in all 6 modules"
  - Justification: Resolves 7 Tomcat CVEs including CVE-2025-24813 (RCE), CVE-2025-55752 (path traversal), CVE-2025-55754 (log escape injection)
  - Side effects: None expected — patch-level upgrade within 10.1.x line
- "Upgrade `spring-security-core` from 6.5.0 to ≥ 6.5.4 in all 6 modules"
  - Justification: Resolves CVE-2025-41248 (authorization bypass) and CVE-2025-22223
  - Side effects: None expected — coordinated with spring-core ≥ 6.2.11
- "Upgrade `grpc-netty-shaded` from 1.70.0 to ≥ 1.75.0 in Modules 1, 2, 3, 5, 6"
  - Justification: Resolves HTTP/2 DDoS and request smuggling CVEs
  - Side effects: None expected — shaded bundle avoids classpath conflicts
- "Upgrade `netty-codec-http2` from 4.1.121.Final to ≥ 4.1.129.Final in Module 4 only"
  - Justification: Module 4 uses direct Netty; highest minimum version across three Netty CVEs
  - Side effects: None expected — within 4.1.x patch series

**F-002 — SAST Remediation (Code Patch):**

Apply a targeted fix to each of the 27 log statement locations by wrapping user-controlled input parameters with `Encode.forJava()` from the OWASP Java Encoder library.

- "Add OWASP Java Encoder dependency to `build.gradle` for Modules 1, 2, 3, 4"
- "Add `import org.owasp.encoder.Encode;` to each of the 8 affected Java files"
- "Wrap each user-controlled variable in log statements with `Encode.forJava(variable)`"
- Rationale: OWASP-recommended approach for CWE-117 remediation. <cite index="30-8,30-9">The recommended mitigation is to sanitize untrusted data using a safe logging mechanism such as the OWASP ESAPI Logger, or alternatively, some of the XSS escaping functions from the OWASP Java Encoder project will also sanitize CRLF sequences.</cite>

Example transformation pattern:
```java
// Before: CWE-117 vulnerable
log.info("Processing offer: {}", offerId);
// After: CWE-117 remediated
log.info("Processing offer: {}", Encode.forJava(offerId));
```

**F-003 — Secret Externalization (Configuration Change):**

Replace each hardcoded Apigee token in YAML configuration files with an environment variable reference or GCP Secret Manager lookup.

- "Update Module 1 `application.yml` line 64: replace hardcoded token with `${APIGEE_TOKEN}`"
- "Update Module 3 `application.yml` line 64: replace hardcoded token with `${APIGEE_TOKEN}`"
- "Update Module 5 `application.yml` line 63: replace hardcoded token with `${APIGEE_TOKEN}`"
- "Update Module 5 `application-test.yml` line 52: replace hardcoded token with `${APIGEE_TOKEN_TEST}` or `${APIGEE_TOKEN}`"
- Security improvement: Eliminates credential exposure in source control, build artifacts, and configuration backups

### 0.5.2 Dependency Replacement Analysis

**No dependency replacements are required.** All 16 vulnerable packages have patched versions available from their respective maintainers. The OWASP Java Encoder is the only **new** dependency being added (for F-002 remediation), and it is an addition rather than a replacement.

### 0.5.3 Security Improvement Validation

**How each fix eliminates the vulnerability:**

| Feature | Vulnerability | Fix Mechanism | Why It Works |
|---|---|---|---|
| F-001 | 23 CVEs in outdated libraries | Version upgrade to patched releases | Patched versions contain specific code fixes for each CVE, verified by the upstream maintainer's security team |
| F-002 | 27 CWE-117 log injection findings | `Encode.forJava()` output encoding | Encodes CR/LF characters and other control sequences before they reach the log writer, preventing log entry forgery |
| F-003 | 4 hardcoded Apigee tokens | Environment variable externalization | Removes the secret from source-controlled files entirely; runtime resolution from environment or secret manager |

**Verification Methods:**
- F-001: Dependency scanner re-scan must return 0 CVEs across all 23 identifiers
- F-002: SAST scanner re-scan must return 0 CWE-117 findings across all 8 files
- F-003: Secret detection scanner re-scan must return 0 findings across all configuration files
- All: `./gradlew test` must achieve 100% pass rate across all 6 modules

**Rollback Plan:**
- Revert `build.gradle` version changes to restore original dependency versions
- Remove `Encode.forJava()` wrappers and OWASP Encoder import/dependency
- Restore original hardcoded token values in YAML files
- All changes are isolated and independently reversible per feature


## 0.6 File Transformation Mapping


### 0.6.1 File-by-File Security Fix Plan

Every file to be created, updated, or deleted is exhaustively mapped below. No files remain as "pending" or "to be discovered."

**Build Configuration Files (F-001 + F-002 Dependency):**

| Target File | Transformation | Source / Reference | Security Changes |
|---|---|---|---|
| gae-gnp-facultativo-administrador/build.gradle | UPDATE | Same file | Upgrade 16 package versions to patched releases; add OWASP Encoder dependency; inline CVE comments (C-008) |
| gae-gnp-facultativo-catalogos/build.gradle | UPDATE | Same file | Upgrade 16 package versions to patched releases; add OWASP Encoder dependency; inline CVE comments (C-008) |
| gae-gnp-facultativo-procesos/build.gradle | UPDATE | Same file | Upgrade 16 package versions to patched releases; add OWASP Encoder dependency; inline CVE comments (C-008) |
| gae-gnp-facultativo-reportes/build.gradle | UPDATE | Same file | Upgrade 16 package versions (including 3 direct Netty libs instead of grpc-netty-shaded); add OWASP Encoder dependency; inline CVE comments (C-008) |
| gae-gnp-facultativo-sincronizador-archivos/build.gradle | UPDATE | Same file | Upgrade applicable package versions (no commons-io in this module); no OWASP Encoder (no SAST findings); inline CVE comments (C-008) |
| gae-gnp-facultativo-tarifas/build.gradle | UPDATE | Same file | Upgrade applicable package versions; no OWASP Encoder (no SAST findings); inline CVE comments (C-008) |

**Java Source Files (F-002 SAST Remediation):**

| Target File | Transformation | Source / Reference | Security Changes |
|---|---|---|---|
| gae-gnp-facultativo-administrador/.../services/LoginService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 1 log parameter with `Encode.forJava()`; add CWE-117 inline comment |
| gae-gnp-facultativo-administrador/.../services/RolService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 1 log parameter with `Encode.forJava()`; add CWE-117 inline comment |
| gae-gnp-facultativo-administrador/.../services/UsuarioService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 2 log parameters with `Encode.forJava()`; add CWE-117 inline comments |
| gae-gnp-facultativo-catalogos/.../services/ReaseguradoraService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 1 log parameter with `Encode.forJava()`; add CWE-117 inline comment |
| gae-gnp-facultativo-procesos/.../services/OfertaService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 4 log parameters with `Encode.forJava()`; add CWE-117 inline comments |
| gae-gnp-facultativo-procesos/.../services/MantenimientoMaestroService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 3 log parameters with `Encode.forJava()`; add CWE-117 inline comments |
| gae-gnp-facultativo-procesos/.../services/PolizaService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 13 log parameters (lines 86–360) with `Encode.forJava()`; add CWE-117 inline comments |
| gae-gnp-facultativo-reportes/.../service/ArchivosUsuarioService.java | UPDATE | Same file | Add `import org.owasp.encoder.Encode;`; wrap 2 log parameters with `Encode.forJava()`; add CWE-117 inline comment |

**Note on Module 4 Package Namespace:** Module 4 (`reportes`) uses the `.service` (singular) package namespace rather than `.services` (plural) used by Modules 1, 2, and 3. This must be reflected in the import path.

**YAML Configuration Files (F-003 Secret Externalization):**

| Target File | Transformation | Source / Reference | Security Changes |
|---|---|---|---|
| gae-gnp-facultativo-administrador/src/main/resources/application.yml | UPDATE | Same file | Line 64: Replace hardcoded Apigee token `l7xxc883ea7da3d047e0ba28114ec` with `${APIGEE_TOKEN}` |
| gae-gnp-facultativo-procesos/src/main/resources/application.yml | UPDATE | Same file | Line 64: Replace hardcoded Apigee token `l7xxc883ea7da3d047e0ba28114ec` with `${APIGEE_TOKEN}` |
| gae-gnp-facultativo-sincronizador-archivos/src/main/resources/application.yml | UPDATE | Same file | Line 63: Replace hardcoded Apigee token `l7xxc883ea7da3d047e0ba28114ec` with `${APIGEE_TOKEN}` |
| gae-gnp-facultativo-sincronizador-archivos/src/test/resources/application-test.yml | UPDATE | Same file | Line 52: Replace hardcoded Apigee token with `${APIGEE_TOKEN}` or test-specific placeholder |

**Complete File Count Summary:**

| Category | Files | Modules Affected |
|---|---|---|
| build.gradle (F-001 + F-002) | 6 | All 6 |
| Java Source (F-002) | 8 | Modules 1, 2, 3, 4 |
| YAML Config (F-003) | 4 | Modules 1, 3, 5 |
| **Total Unique Files** | **18** | **All 6 modules** |

### 0.6.2 Code Change Specifications

**F-002 Java Source File Changes — Per-File Detail:**

| File | Module | Lines Affected | Before State | After State | Findings Fixed |
|---|---|---|---|---|---|
| LoginService.java | 1 (administrador) | ~1 log statement | User input logged without encoding | Input wrapped with `Encode.forJava()` | 1 |
| RolService.java | 1 (administrador) | ~1 log statement | User input logged without encoding | Input wrapped with `Encode.forJava()` | 1 |
| UsuarioService.java | 1 (administrador) | ~2 log statements | User input logged without encoding | Inputs wrapped with `Encode.forJava()` | 2 |
| ReaseguradoraService.java | 2 (catalogos) | ~1 log statement | User input logged without encoding | Input wrapped with `Encode.forJava()` | 1 |
| OfertaService.java | 3 (procesos) | ~4 log statements | User input logged without encoding | Inputs wrapped with `Encode.forJava()` | 4 |
| MantenimientoMaestroService.java | 3 (procesos) | ~3 log statements | User input logged without encoding | Inputs wrapped with `Encode.forJava()` | 3 |
| PolizaService.java | 3 (procesos) | Lines 86–360 (~13 log statements) | User input logged without encoding — highest density SAST hotspot | All 13 inputs wrapped with `Encode.forJava()` | 13 |
| ArchivosUsuarioService.java | 4 (reportes) | ~2 log statements | User input logged without encoding | Inputs wrapped with `Encode.forJava()` | 2 |

### 0.6.3 Configuration Change Specifications

**F-003 YAML Configuration Changes — Per-File Detail:**

| File | Module | Setting | Current Value | New Value | Security Rationale |
|---|---|---|---|---|---|
| application.yml (line 64) | 1 (administrador) | Apigee token property | `l7xxc883ea7da3d047e0ba28114ec` (hardcoded) | `${APIGEE_TOKEN}` | Eliminates credential exposure in source control; runtime resolution from environment |
| application.yml (line 64) | 3 (procesos) | Apigee token property | `l7xxc883ea7da3d047e0ba28114ec` (hardcoded) | `${APIGEE_TOKEN}` | Eliminates credential exposure in source control; runtime resolution from environment |
| application.yml (line 63) | 5 (sincronizador-archivos) | Apigee token property | `l7xxc883ea7da3d047e0ba28114ec` (hardcoded) | `${APIGEE_TOKEN}` | Eliminates credential exposure in source control; runtime resolution from environment |
| application-test.yml (line 52) | 5 (sincronizador-archivos) | Apigee token property | `l7xxc883ea7da3d047e0ba28114ec` (hardcoded) | `${APIGEE_TOKEN}` | Eliminates credential exposure in test configuration; prevents secret scanner false pass |


## 0.7 Dependency Inventory


### 0.7.1 Security Patches and Updates

All security-critical package updates with exact names, versions, and advisory references:

| Registry | Package Name | Current | Patched To | CVE/Advisory | Severity |
|---|---|---|---|---|---|
| Maven Central | tomcat-embed-core | 10.1.41 | ≥ 10.1.47 | CVE-2025-24813, CVE-2024-56337, CVE-2025-24814, CVE-2025-55752, CVE-2025-55754, +2 more (7 total) | Critical/High |
| Maven Central | spring-core | 6.2.7 | ≥ 6.2.11 | CVE-2025-41249 | Medium |
| Maven Central | spring-web | 6.2.7 | ≥ 6.2.8 | CVE-2024-22243, CVE-2024-22259, CVE-2024-22262 | High |
| Maven Central | spring-webmvc | 6.2.7 | ≥ 6.2.10 | CVE-2024-38819, CVE-2024-38820 | High |
| Maven Central | spring-security-core | 6.5.0 | ≥ 6.5.4 | CVE-2025-41248, CVE-2025-22223 | Medium/High |
| Maven Central | grpc-netty-shaded | 1.70.0 | ≥ 1.75.0 | CVE-2024-21634, CVE-2024-7254, CVE-2024-34155, CVE-2024-34156, CVE-2024-34158 | High |
| Maven Central | netty-codec-http2 | 4.1.121.Final | ≥ 4.1.129.Final | HTTP/2 DDoS vulnerability | High |
| Maven Central | netty-codec-http | 4.1.121.Final | ≥ 4.1.125.Final | Request smuggling vulnerability | High |
| Maven Central | netty-codec | 4.1.121.Final | ≥ 4.1.124.Final | Codec processing vulnerability | Medium |
| Maven Central | logback-classic | 1.5.18 | ≥ 1.5.19 | CVE-2025-24228 (RCE) | Critical |
| Maven Central | logback-core | 1.5.18 | ≥ 1.5.19 | CVE-2025-24228 (RCE) | Critical |
| Maven Central | log4j-to-slf4j | 2.24.3 | ≥ 2.24.4 | CVE-2025-21549 | Medium |
| Maven Central | commons-io | 2.11.0 | ≥ 2.18.0 | CVE-2024-47554 (DoS) | Medium |
| Maven Central | commons-fileupload2-jakarta-servlet6 | 2.0.0-M2 | ≥ 2.0.0-M3 | CVE-2024-25710, CVE-2024-26308 | High |
| Maven Central | commons-lang3 | 3.17.0 | ≥ 3.18.0 | DoS vulnerability | Medium |
| Maven Central | assertj-core | 3.27.3 | ≥ 3.27.7 | CVE-2026-24400 (XXE) | High |

**New Dependency (F-002):**

| Registry | Package Name | Version | Purpose | Modules |
|---|---|---|---|---|
| Maven Central | org.owasp.encoder:encoder | Latest stable (1.2.3+) | CWE-117 remediation via `Encode.forJava()` | Modules 1, 2, 3, 4 |

### 0.7.2 Dependency Chain Analysis

- **Direct dependencies requiring updates:** All 16 packages listed above are direct dependencies declared in `build.gradle` files
- **Transitive dependencies affected:**
  - `grpc-netty-shaded` internally bundles Netty classes (shaded) — upgrading to 1.75.0 resolves the transitive Netty vulnerabilities for Modules 1, 2, 3, 5, 6
  - `tomcat-embed-core` may pull transitive Tomcat components — the embed-core upgrade covers the primary CVE surface
  - `spring-core` is a transitive dependency of `spring-web`, `spring-webmvc`, and `spring-security-core` — all four must be upgraded in coordination
- **Peer dependencies to verify:**
  - Spring Boot parent BOM (if used) — verify it does not override the explicitly declared Spring versions
  - Gradle dependency resolution strategy — confirm that `force` or `strictly` is not pinning any vulnerable versions
- **Development dependencies with vulnerabilities:**
  - `assertj-core` 3.27.3 → ≥ 3.27.7 (CVE-2026-24400 XXE in `isXmlEqualTo`) — test-scoped but must be fixed to prevent CI/CD exploitation

### 0.7.3 Import and Reference Updates

**Source files requiring import additions (F-002):**

All 8 Java service files in Modules 1–4 require a new import statement:

```java
import org.owasp.encoder.Encode;
```

- `gae-gnp-facultativo-administrador/**/services/LoginService.java`
- `gae-gnp-facultativo-administrador/**/services/RolService.java`
- `gae-gnp-facultativo-administrador/**/services/UsuarioService.java`
- `gae-gnp-facultativo-catalogos/**/services/ReaseguradoraService.java`
- `gae-gnp-facultativo-procesos/**/services/OfertaService.java`
- `gae-gnp-facultativo-procesos/**/services/MantenimientoMaestroService.java`
- `gae-gnp-facultativo-procesos/**/services/PolizaService.java`
- `gae-gnp-facultativo-reportes/**/service/ArchivosUsuarioService.java`

**Import transformation rule:**
```java
// Add to imports section of each file:
import org.owasp.encoder.Encode;
```

**Configuration reference updates (F-003):**
- All 4 YAML files replace the hardcoded token string with `${APIGEE_TOKEN}` (Spring property placeholder syntax)
- Deployment environment must define the `APIGEE_TOKEN` environment variable
- No import or code reference changes needed for F-003 — the Spring `@Value` / property resolution handles it transparently


## 0.8 Impact Analysis and Testing Strategy


### 0.8.1 Security Testing Requirements

**Vulnerability Regression Tests:**

The remediation must be verified through the three-scanner convergence model. Each vulnerability category must return zero findings after the fix is applied.

- **Test that vulnerability is no longer exploitable:**
  - F-001: Dependency scanner confirms 0 CVEs across all 23 identifiers in all 6 modules
  - F-002: SAST scanner confirms 0 CWE-117 findings across all 8 scanned Java files
  - F-003: Secret detection scanner confirms 0 findings across all YAML configuration files

- **Specific attack scenarios validated by the fix:**
  - Path traversal via Tomcat rewrite rules (CVE-2025-55752) — eliminated by tomcat-embed-core ≥ 10.1.47
  - Authorization bypass via `@PreAuthorize` on parameterized types (CVE-2025-41248) — eliminated by spring-security-core ≥ 6.5.4
  - Log entry forgery via CRLF injection in log statements (CWE-117) — eliminated by `Encode.forJava()` encoding
  - API gateway credential theft via hardcoded token in source control (Apigee tokens) — eliminated by environment variable externalization

- **Existing tests to verify (no new tests created per Constraint C-002):**
  - `./gradlew test` — full unit test suite execution per module
  - 100% pass rate required across all 6 modules
  - Assumption A-004 must be verified: existing unit tests provide sufficient regression coverage

### 0.8.2 Verification Methods

**Automated Security Scanning:**

| Tool Category | Command / Invocation | Expected Result |
|---|---|---|
| Dependency Scanner | Project-specific scanner invocation | 0 CVEs across all 23 identifiers |
| SAST Scanner | Project-specific SAST tool | 0 CWE-117 findings across 8 files |
| Secret Detection | Project-specific secret scanner | 0 findings across all YAML configs |
| Unit Tests | `./gradlew test` (per module) | 100% pass rate, all 6 modules |

**Manual Verification Steps:**
- Review each `build.gradle` to confirm all 16 package versions are at or above the minimum patched version
- Review each of the 8 Java files to confirm all 27 log statement parameters are wrapped with `Encode.forJava()`
- Review each of the 4 YAML files to confirm no hardcoded Apigee token strings remain
- Verify inline comments are present on every change per Constraint C-008
- Verify Module 4 uses direct Netty libraries (not `grpc-netty-shaded`) at correct target versions
- Verify Module 5 has both `application.yml` and `application-test.yml` remediated

**Post-Deployment Verification:**
- F-003: Verify Apigee API Gateway connectivity for Modules 1, 3, and 5 after token externalization (requirement F-003-RQ-006)
- Monitor service response times to confirm no degradation post-upgrade

### 0.8.3 Impact Assessment

**Direct Security Improvements Achieved:**
- 23 unique CVEs eliminated across dependency stack
- 27 CWE-117 log injection vulnerabilities eliminated across 8 service files
- 4 hardcoded credential exposures eliminated across 3 modules
- Total: 172 vulnerability entries → 0 vulnerability entries (100% remediation)

**Minimal Side Effects on Existing Functionality:**
- No breaking changes to public APIs — all dependency upgrades are within patch/minor release trains
- No changes to service topology, module boundaries, or deployment architecture
- Internal changes limited to: version numbers in build configs, `Encode.forJava()` wrappers in log statements, environment variable references in YAML configs
- `Encode.forJava()` adds negligible per-log-statement overhead (no measurable performance delta)
- Secret retrieval from environment variables adds no perceptible startup or runtime latency

**Potential Impacts and Mitigations:**

| Potential Impact | Likelihood | Mitigation |
|---|---|---|
| Spring version mismatch across 4 packages | Low | Coordinate all 4 Spring upgrades together in single `build.gradle` update |
| gRPC-Netty transitive classpath clash | Low | `grpc-netty-shaded` bundles Netty internally; Module 4 uses direct Netty independently |
| `Encode.forJava()` changes log output format for encoded characters | Medium | Expected behavior — encoded characters are intentional security improvement; verify test expectations |
| Module 5 `application-test.yml` missed | Medium | Explicitly track dual-environment scope; secret scanner validates both files |
| OWASP Encoder governance rejection (A-002) | Low | Fallback: manual CRLF stripping via `String.replace('\n', '_').replace('\r', '_')` |
| Maven Central artifact unavailability (A-001) | Low | Fallback to internal artifact repository |


## 0.9 Scope Boundaries


### 0.9.1 Exhaustively In Scope

**Vulnerable Dependency Manifests (F-001):**
- `gae-gnp-facultativo-administrador/build.gradle`
- `gae-gnp-facultativo-catalogos/build.gradle`
- `gae-gnp-facultativo-procesos/build.gradle`
- `gae-gnp-facultativo-reportes/build.gradle`
- `gae-gnp-facultativo-sincronizador-archivos/build.gradle`
- `gae-gnp-facultativo-tarifas/build.gradle`

**Source Files with Vulnerable Code (F-002 — CWE-117 SAST):**
- `gae-gnp-facultativo-administrador/**/services/LoginService.java` (1 finding)
- `gae-gnp-facultativo-administrador/**/services/RolService.java` (1 finding)
- `gae-gnp-facultativo-administrador/**/services/UsuarioService.java` (2 findings)
- `gae-gnp-facultativo-catalogos/**/services/ReaseguradoraService.java` (1 finding)
- `gae-gnp-facultativo-procesos/**/services/OfertaService.java` (4 findings)
- `gae-gnp-facultativo-procesos/**/services/MantenimientoMaestroService.java` (3 findings)
- `gae-gnp-facultativo-procesos/**/services/PolizaService.java` (13 findings)
- `gae-gnp-facultativo-reportes/**/service/ArchivosUsuarioService.java` (2 findings)

**Configuration Files Requiring Security Updates (F-003 — Secret Externalization):**
- `gae-gnp-facultativo-administrador/src/main/resources/application.yml` (line 64)
- `gae-gnp-facultativo-procesos/src/main/resources/application.yml` (line 64)
- `gae-gnp-facultativo-sincronizador-archivos/src/main/resources/application.yml` (line 63)
- `gae-gnp-facultativo-sincronizador-archivos/src/test/resources/application-test.yml` (line 52)

**Infrastructure and Deployment (F-003 Secret Management Only):**
- GCP deployment environment: `APIGEE_TOKEN` environment variable provisioning for Modules 1, 3, 5
- GCP Secret Manager integration (if environment variables are insufficient)
- Deployment runbook updates for secret provisioning steps

**Security Validation Artifacts:**
- Dependency scanner reports (all 6 modules)
- SAST scanner reports (Modules 1, 2, 3, 4)
- Secret detection scanner reports (Modules 1, 3, 5)
- `./gradlew test` execution results (all 6 modules)

**Documentation Updates:**
- Inline comments on every security change per Constraint C-008
- CVE references in `build.gradle` version change comments
- CWE-117 threat explanation in `Encode.forJava()` usage comments

### 0.9.2 Explicitly Out of Scope

- Feature additions unrelated to security (Constraint C-002)
- Performance optimizations not required for security (Constraint C-004)
- Code refactoring beyond security fix requirements (Constraint C-004)
- Non-vulnerable dependencies — only the 16 identified packages are upgraded
- Style or formatting changes beyond the security fixes
- Test files unrelated to security validation — no new test cases, utilities, or helpers (Constraint C-002)
- Database modifications, schema changes, or data migrations (Constraint C-006)
- Infrastructure changes beyond secret management (Constraint C-007)
- Architectural modifications to module boundaries or deployment topology (Constraint C-003)
- Newly discovered vulnerabilities beyond the 172 documented entries (Constraint C-005)
- Modules 2, 4, 5, 6 SAST source changes (no CWE-117 findings in Modules 5 and 6; Modules 2 and 4 have findings and are in scope)
- Modules 2, 4, 6 secret externalization (no Apigee tokens in these modules)
- CI/CD pipeline modifications — no new scanning tools, coverage servers, or reporting dashboards
- Test infrastructure provisioning — no new test frameworks, test runners, or coverage tools
- Cross-browser, E2E, or UI testing — backend microservices only, no UI components
- Performance benchmarking or load testing (Constraint C-004)
- User input: The user's original request mentioned "Node.js" and "Express.js" features, which do not apply to this Java microservices security remediation project. The Technical Specification (authoritative source) defines the project as GAE-GNP Facultativo — a Java/Spring security hardening initiative


## 0.10 Execution Parameters


### 0.10.1 Security Verification Commands

| Verification Step | Command | Expected Output |
|---|---|---|
| Unit test execution (per module) | `cd gae-gnp-facultativo-{module} && ./gradlew test` | BUILD SUCCESSFUL, 100% pass rate |
| Full build validation (per module) | `cd gae-gnp-facultativo-{module} && ./gradlew build` | BUILD SUCCESSFUL, all dependencies resolved |
| Dependency vulnerability scan | Project-specific dependency scanner CLI | 0 CVEs across all 23 identifiers |
| SAST scan | Project-specific SAST tool CLI | 0 CWE-117 findings across 8 files |
| Secret detection scan | Project-specific secret detection CLI | 0 findings across all YAML configurations |
| Gradle dependency resolution check | `./gradlew dependencies --configuration compileClasspath` | No version conflicts; all patched versions resolved |

### 0.10.2 Research Documentation

**Security Advisories Consulted:**
- Apache Tomcat Security (10.x): `https://tomcat.apache.org/security-10.html` — CVE-2025-24813, CVE-2025-55752, CVE-2025-55754
- Spring Security CVE-2025-41248: `https://spring.io/security/cve-2025-41248` — Authorization bypass in method security annotations
- Spring Framework CVE-2025-41249: `https://spring.io/security/cve-2025-41249` — Annotation detection vulnerability
- Spring Blog (September 2025): `https://spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes` — Coordinated fix announcement
- NVD (NIST): `https://nvd.nist.gov/vuln/detail/CVE-2025-55754` — Official government vulnerability database
- OWASP Java Encoder: `https://owasp.org/www-project-java-encoder` — Contextual output encoding library
- MITRE CWE-117: `https://cwe.mitre.org/data/definitions/117.html` — Improper Output Neutralization for Logs
- SEI CERT IDS03-J: `https://wiki.sei.cmu.edu/confluence/display/java/IDS03-J` — Do not log unsanitized user input
- GitHub Advisory GHSA-8v5q-rhf3-jphm: `https://github.com/advisories/GHSA-8v5q-rhf3-jphm` — Spring Security advisory

**CVE Numbers Referenced:**
- Tomcat: CVE-2025-24813, CVE-2024-56337, CVE-2025-24814, CVE-2025-55752, CVE-2025-55754
- Spring: CVE-2025-41248, CVE-2025-41249, CVE-2025-22223, CVE-2024-22243, CVE-2024-22259, CVE-2024-22262, CVE-2024-38819, CVE-2024-38820
- Netty/gRPC: CVE-2024-21634, CVE-2024-7254, CVE-2024-34155, CVE-2024-34156, CVE-2024-34158
- Logback: CVE-2025-24228
- Log4j Bridge: CVE-2025-21549
- Commons: CVE-2024-47554, CVE-2024-25710, CVE-2024-26308
- AssertJ: CVE-2026-24400

**Security Best Practices Followed:**
- OWASP Output Encoding — Contextual encoding of user input before logging (CWE-117 remediation)
- OWASP Dependency Management — Keep all libraries updated to patched versions
- Secret Externalization — Never store credentials in source-controlled configuration files
- Principle of Least Privilege — Environment variable access scoped to deployment environment only
- Defense in Depth — Three independent scanner categories validate three different vulnerability classes

### 0.10.3 Implementation Constraints

- **Priority:** Security fix first, minimal disruption second — all changes serve the singular goal of reducing 172 vulnerability entries to zero
- **Backward Compatibility:** Must maintain — all upgrades are within patch/minor release trains; no major version bumps; no API changes
- **Deployment Considerations:** Requires coordination — `APIGEE_TOKEN` environment variable must be provisioned in GCP deployment environment before Module 1, 3, 5 deployment; otherwise API gateway connectivity will fail
- **Execution Order Recommendation:**
  - Phase 1: Apply F-001 dependency upgrades to all 6 `build.gradle` files; run `./gradlew test` per module
  - Phase 2: Apply F-002 SAST fixes to 8 Java files in Modules 1–4; add OWASP Encoder dependency; run `./gradlew test`
  - Phase 3: Apply F-003 secret externalization to 4 YAML files in Modules 1, 3, 5; provision environment variables; run `./gradlew test`
  - Phase 4: Execute all three security scanners across all modules; verify convergence at zero findings


## 0.11 Special Instructions for Security Fixes


### 0.11.1 Security-Specific Requirements Explicitly Emphasized

The following directives are drawn directly from the project's governance framework (Constraints C-001 through C-008) and the minimal-change discipline:

- **Change Scope:** "ONLY make changes necessary for security fix" — Every modification must trace to one of the 172 documented vulnerability entries. No opportunistic improvements, no clean-up of adjacent code, no modernization of patterns
- **No Refactoring:** "Do not refactor unrelated code" — Even if adjacent code could benefit from improvement, only the specific log statements identified in the SAST report may be modified (F-002). Only the specific dependency versions identified in the dependency scan may be changed (F-001). Only the specific YAML lines identified in the secret scan may be updated (F-003)
- **No Non-Vulnerable Dependency Updates:** "Do not update non-vulnerable dependencies" — The 16 packages listed in the dependency inventory are the complete and exclusive set of dependencies to upgrade. No other packages may be updated, even if newer versions are available
- **Preserve Existing Functionality:** "Preserve all existing functionality except where it enables the vulnerability" — The `Encode.forJava()` wrappers intentionally modify log output format for encoded characters; this is the expected security improvement, not a regression
- **Principle of Least Privilege:** "Follow principle of least privilege in all changes" — Environment variables for Apigee tokens are scoped to the GCP deployment environment; no broad credential distribution
- **Audit Trail:** "Maintain audit trail for all security changes" — Every change must include an inline comment explaining the specific threat addressed (Constraint C-008). Version changes reference CVE numbers; encoding changes reference CWE-117; token removals reference secret detection findings
- **Documentation Alongside Code:** "Update security documentation alongside code changes" — Inline comments are the primary documentation mechanism; no separate documentation files are created (per Constraint C-002, no new capabilities)

### 0.11.2 Secrets Management Directive

- The Apigee token externalization (F-003) requires provisioning the `APIGEE_TOKEN` environment variable in the GCP deployment environment
- If the deployment environment supports GCP Secret Manager, the preferred approach is `sm://projects/{project}/secrets/apigee-token/versions/latest` syntax in Spring Cloud GCP
- If GCP Secret Manager is not available, standard environment variable resolution (`${APIGEE_TOKEN}`) is the minimum viable approach
- The same token value must be provisioned for Modules 1, 3, and 5 to maintain API gateway connectivity
- Module 5's test environment (`application-test.yml`) may use a separate test token or the same production token, depending on the Apigee gateway configuration for test environments

### 0.11.3 Scope Discipline for Newly Discovered Vulnerabilities

Per Constraint C-005: If the dependency scanner, SAST scanner, or secret detection scanner discovers vulnerabilities **beyond** the 172 documented entries during the remediation process, these new findings are:
- **Noted** in the remediation report
- **Not fixed** unless explicitly authorized
- **Escalated** to the Security & Compliance team for triage
- The exception: if upgrading a package to its minimum patched version inadvertently resolves additional CVEs in that same package, this is an acceptable side effect and does not violate C-005

### 0.11.4 Module 4 Special Handling

Module 4 (`reportes`) requires special attention due to its architectural divergence:
- Uses `.service` (singular) package namespace instead of `.services` (plural)
- Uses direct Netty libraries instead of `grpc-netty-shaded`
- `commons-io` is absent — CVE-2024-47554 upgrade does not apply
- Three independent Netty upgrade paths with different minimum versions (4.1.124, 4.1.125, 4.1.129)
- Each Netty package version must be individually verified against its specific CVE

### 0.11.5 Module 5 Dual-Environment Scope

Module 5 (`sincronizador-archivos`) is the only module requiring remediation in both production and test configuration environments:
- `application.yml` (line 63) — production configuration
- `application-test.yml` (line 52) — test configuration
- Both files must be independently remediated; missing the test configuration would leave the test environment with an exposed secret
- Failure to remediate `application-test.yml` would cause the secret detection scanner to fail on Module 5, blocking project completion


