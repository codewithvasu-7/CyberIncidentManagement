# Cybersecurity Incident Reporting & Management System (CIRMS)

An enterprise-grade **Computer Security Incident Response Team (CSIRT) & Security Operations Center (SOC)** web application built in **Java (Jakarta EE Servlets, JSP, JDBC)** with a **MySQL** backend.

---

## 🏛️ System Architecture

```
                  ┌───────────────┐
                  │    Browser    │
                  └───────┬───────┘
                          │
                    JSP / HTML / CSS / JS
                          │
                          ▼
                  ┌───────────────┐
                  │   Controller  │
                  │ Servlets      │
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │     Model     │
                  │ Java Classes  │
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │      DAO      │
                  │ JDBC          │
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │     MySQL     │
                  └───────────────┘
```

---

## 📂 Project Directory Structure

```text
CyberIncidentManagement/
│
├── src/main/java/
│   └── com/cyberincident/
│       ├── controller/
│       │   ├── LoginServlet.java          # Authentication & role-based routing
│       │   ├── RegisterServlet.java       # User onboarding & password hashing
│       │   ├── LogoutServlet.java         # Session invalidation & audit logging
│       │   ├── IncidentServlet.java       # Incident triage, lifecycle & updates
│       │   ├── AdminServlet.java          # User administration & role changes
│       │   └── ReportServlet.java         # CSV exports & analytics reports
│       │
│       ├── model/
│       │   ├── User.java                  # Identity entity (USER, ANALYST, ADMIN)
│       │   ├── Incident.java              # Security incident entity & badges
│       │   ├── IncidentUpdate.java        # Chronology, comments & timeline
│       │   └── AuditLog.java              # Immutable security audit entry
│       │
│       ├── dao/
│       │   ├── DBConnection.java          # JDBC connection manager & fallback
│       │   ├── UserDAO.java               # User CRUD & authentication
│       │   ├── IncidentDAO.java           # Incident queries & filtering
│       │   ├── AdminDAO.java              # KPI counters & metrics aggregation
│       │   └── AuditLogDAO.java           # Security event auditing
│       │
│       ├── security/
│       │   ├── PasswordUtil.java          # SHA-256 + 16-byte cryptographic salt
│       │   ├── RiskAnalyzer.java          # Threat category, asset & scope weights
│       │   ├── RiskCalculator.java        # Quantitative formula (0-100 risk score)
│       │   └── ResponseEngine.java        # NIST SP 800-61 automated playbooks
│       │
│       └── filter/
│           └── AuthFilter.java            # RBAC enforcement & cache prevention
│
├── src/main/webapp/
│   ├── index.jsp                          # Public landing & architecture overview
│   ├── login.jsp                          # Cyber login portal with 1-click autofill
│   ├── register.jsp                       # Employee registration with strength meter
│   │
│   ├── css/
│   │   └── style.css                      # Cyber SOC dark theme (Cyan/Emerald/Rose)
│   │
│   ├── js/
│   │   └── script.js                      # Live risk predictor, table filter, clipboard
│   │
│   ├── user/
│   │   ├── dashboard.jsp                  # Employee overview & quick report
│   │   ├── report.jsp                     # Incident submission & live calculator
│   │   ├── incidents.jsp                  # Employee reported incidents list
│   │   └── details.jsp                    # Full incident timeline & playbooks
│   │
│   ├── analyst/
│   │   ├── dashboard.jsp                  # SOC triage workbench & priority queue
│   │   └── investigation.jsp              # Forensics, IOCs, status transitions
│   │
│   ├── admin/
│   │   ├── dashboard.jsp                  # Executive command center & charts
│   │   ├── users.jsp                      # Identity directory & RBAC toggling
│   │   ├── incidents.jsp                  # Master incident archive & purge
│   │   └── reports.jsp                    # Compliance audit & CSV export
│   │
│   └── WEB-INF/
│       └── web.xml                        # Servlet deployment descriptor
│
├── database/
│   └── database.sql                       # Complete schema & realistic seed data
│
├── README.md                              # Technical guide & viva preparation
└── pom.xml                                # Maven build descriptor
```

---

## 🔑 Default User Accounts (Seed Data)

The database comes pre-loaded with accounts for testing:

| Role | Username | Password | Purpose |
|---|---|---|---|
| **ADMIN (CISO)** | `admin` | `Admin@123` | Master control, user role management, system metrics |
| **ANALYST (SOC Tier-2)** | `analyst_raj` | `Analyst@123` | Incident investigation, forensics, playbook execution |
| **ANALYST (Responder)** | `analyst_priya` | `Analyst@123` | Containment actions & IOC extraction |
| **USER (Employee)** | `john_doe` | `User@123` | Report security anomalies, monitor status |
| **USER (Employee)** | `alice_smith` | `User@123` | Report security anomalies |

*(On the login screen, click the **Evaluator Quick Login** buttons for 1-click instant login).*

---

## 🧮 Security Engine & Algorithms

### 1. Cryptographic Password Hashing (`PasswordUtil.java`)
- Passwords are **never stored in plain text**.
- Generates a **16-byte random cryptographic salt** via `SecureRandom`.
- Hashes input using `SHA-256(password + salt)`.
- Compares hashes in **constant time** via `MessageDigest.isEqual()` to prevent timing attacks.

### 2. Multi-Factor Quantitative Risk Equation (`RiskCalculator.java`)
Risk scores range from `0` to `100`:
$$\text{Risk Score} = \left(\text{Threat Weight} \times 0.35 + \text{Asset Criticality} \times 0.25 + \text{Impact Scope} \times 0.20 + \text{Data Sensitivity} \times 0.20\right) \times 100$$

- **Threat Weight (35%)**: Ransomware (1.0), Data Breach (0.95), Insider Threat (0.85), DDoS (0.80), Malware (0.75), Phishing (0.70), Unauthorized Access (0.65).
- **Asset Criticality (25%)**: Core Database / Active Directory / NAS (1.0), Payment / API Gateway (0.80), Employee Workstations / Mailbox (0.60), Dev / Test (0.35).
- **Impact Scope (20%)**: Organization-Wide (1.0), External/Client (0.85), Department (0.60), Individual (0.30).
- **Data Sensitivity (20%)**: Highly Sensitive / PII / Financial (1.0), Confidential (0.80), Internal (0.50), Public (0.20).

**Score Triage Ranges:**
- `85 - 100`: **CRITICAL** (Emergency P1 / War Room)
- `65 - 84`: **HIGH** (Priority containment within 1 hour)
- `40 - 64`: **MEDIUM** (Standard SOC queue triage)
- `0 - 39`: **LOW** (Minor anomaly / informational)

### 3. NIST SP 800-61 Automated Response Engine (`ResponseEngine.java`)
Generates actionable playbooks for SOC Responders:
- **Phishing**: Purge malicious emails across tenant, block sender domain, reset OAuth tokens.
- **Ransomware**: Physical VLAN severance, SMB/RPC block, offline shadow-copy verification.
- **Data Breach**: IAM credential rotation, SIEM egress analysis, evidence preservation.
- **DDoS**: BGP scrubbing center routing, SYN cookie enforcement, WAF rate limiting.

---

## 🚀 Setup & Execution Guide

### Step 1: Database Setup (MySQL)
1. Open **MySQL Workbench**, **phpMyAdmin**, or the MySQL command line client:
   ```bash
   mysql -u root -p
   ```
2. Import the schema and seed data:
   ```sql
   source d:/download_browser/javaproject/CyberIncidentManagement/database/database.sql;
   ```
3. Verify that the `cyber_incident_db` database is created with tables: `users`, `incidents`, `incident_updates`, `audit_logs`.

### Step 2: Database Credentials Configuration
In `com.cyberincident.dao.DBConnection.java`:
- Default host: `localhost:3306`
- Default DB: `cyber_incident_db`
- Default user: `root`
- Default password: `root` (automatically falls back to blank `""` if password-less).
- You can configure custom credentials in `src/main/resources/db.properties` or JVM argument `-Ddb.password=yourpass`.

### Step 3: Run / Deploy on Apache Tomcat
#### Option A: Using Eclipse / IntelliJ IDEA
1. Open Eclipse or IntelliJ IDEA.
2. Import `CyberIncidentManagement` as an **Existing Maven Project** or **Dynamic Web Project**.
3. Add **Apache Tomcat 10.x or 10.1.x** (or Tomcat 9 with Jakarta/Java EE servlet bridge) to Server Runtime.
4. Right-click the project &rarr; **Run As &rarr; Run on Server**.
5. Access via: `http://localhost:8080/CyberIncidentManagement/`

#### Option B: Deploying WAR File directly to Tomcat
1. Run `mvn clean package` or the included `package.bat` script.
2. Copy `target/CyberIncidentManagement.war` into your Tomcat `webapps/` folder.
3. Start Tomcat (`bin/startup.bat`).
4. Access: `http://localhost:8080/CyberIncidentManagement/`

---

## 🎓 Major Project Viva / Oral Exam Guide

1. **Why MVC Architecture?**
   - **Model**: Encapsulates business data entities (`Incident`, `User`, `AuditLog`).
   - **View**: Renders responsive UI via JSP and CSS (`dashboard.jsp`, `investigation.jsp`).
   - **Controller**: Manages request flow, validates input, interacts with DAO, and directs navigation (`IncidentServlet`, `LoginServlet`).
   - Prevents mixing of presentation and database logic.

2. **How is Role-Based Access Control (RBAC) enforced?**
   - Implemented via `AuthFilter.java` using Java Servlet Filter API.
   - Every request is intercepted before hitting a servlet or JSP.
   - If an unauthorized user tries to access `/admin/*` or `/analyst/*`, they are redirected with an access denied alert.

3. **How does the Incident Response Workflow follow NIST standards?**
   - Follows the 4 NIST SP 800-61 phases:
     1. **Preparation**: Pre-defined triage rules & cryptographic audit logging.
     2. **Detection & Analysis**: Real-time multi-factor risk calculator & IOC extraction.
     3. **Containment, Eradication & Recovery**: Automated playbooks, VLAN isolation instructions, status lifecycle transitions.
     4. **Post-Incident Activity**: Root cause analysis recording, MTTR calculation, and CSV report export.

4. **Why SHA-256 with Cryptographic Salt?**
   - A simple SHA-256 hash without salt is vulnerable to pre-computed **Rainbow Table attacks**.
   - A unique 16-byte random salt per user ensures identical passwords generate completely different hashes.
