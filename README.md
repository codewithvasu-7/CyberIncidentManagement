# Cybersecurity Incident Reporting & Management System (CIRMS)

### A Java-based web platform for reporting, triaging, investigating, and managing cybersecurity incidents.

------------------------------------------------------------------------

## Project Overview

The **Cybersecurity Incident Reporting & Management System (CIRMS)** is
a web-based application designed to organize cybersecurity incident
reporting and response workflows. It provides separate interfaces for
employees, SOC analysts, and administrators, allowing incidents to be
reported, prioritized, investigated, tracked, and reviewed through a
centralized system.

The project uses Java, Jakarta Servlets, JSP, JDBC, MySQL, and a
role-based application architecture. It also includes risk scoring,
security audit records, incident-response guidance, dashboards, and
reporting features. The project is intended for academic demonstration
and controlled evaluation; automated recommendations support analyst
decision-making and do not replace professional incident-response
procedures.

> **Repository:**
> https://github.com/codewithvasu-7/CyberIncidentManagement\
> **Recorded live deployment:**
> https://cyberincidentmanagement-1.onrender.com\
> **Project duration:** 12-week development plan\
> **Project guide:** Add/confirm the guide's name before final academic
> submission.

------------------------------------------------------------------------

## Week-wise Project Timeline (Week 1 to Week 12)

The project work is organized chronologically below. Each week has a dedicated section later in this README with its details, activities, and relevant deliverables.

| Week | Main Focus | Expected Output |
|---|---|---|
| **Week 1** | Team formation and problem definition | Project problem statement, objectives, team responsibilities |
| **Week 2** | Abstract, scope, and requirements | Abstract, project scope, limitations, initial requirements |
| **Week 3** | User roles and detailed requirements | Role definitions, functional and non-functional requirements |
| **Week 4** | System architecture and core modules | MVC-style architecture, module breakdown, request/data flow |
| **Week 5** | Technology stack and database design | Technology selection, database entities, persistence plan |
| **Week 6** | Authentication and access control | Login/session workflow, role checks, security controls |
| **Week 7** | Incident lifecycle and risk scoring | Incident status workflow, risk score and triage bands |
| **Week 8** | Response playbooks and investigation | Recommended response steps, investigation notes and chronology |
| **Week 9** | Dashboards, audit logs, and reports | Metrics, traceability, CSV/reporting features |
| **Week 10** | Cloud database and deployment preparation | Environment configuration, Docker and hosting setup |
| **Week 11** | Testing and integration review | Test checklist, bug fixes, integration verification |
| **Week 12** | Final deployment and evaluation | Deployment verification, demonstration, final documentation |

> **Academic accuracy note:** This is a week-wise project plan/summary. Update each week's activities to reflect the work actually completed, and attach evidence such as commits, screenshots, test results, or meeting notes where required. Do not mark planned work as completed unless it has been verified.

------------------------------------------------------------------------

## Week 1: Team Formation and Problem Definition

### Project Administration

-   **Project Name:** Cybersecurity Incident Reporting & Management
    System (CIRMS)
-   **Project Type:** Cybersecurity / Web Application
-   **Institution:** Arya College of Engineering & IT, Jaipur
-   **Department:** Computer Science and Engineering
-   **Development Approach:** Iterative development with weekly
    milestones
-   **Repository:** `codewithvasu-7/CyberIncidentManagement`

### Team Members and Responsibilities

  -----------------------------------------------------------------------
  Team Member             GitHub Username         Primary Responsibility
  ----------------------- ----------------------- -----------------------
  Vasudev                 `codewithvasu-7`        Team coordination,
                                                  application
                                                  architecture, cloud
                                                  database integration,
                                                  Docker and deployment

  Shailja                 `shailja2007`           Authentication
                                                  security, salted
                                                  password hashing, login
                                                  rate limiting and CSRF
                                                  protection

  Tanishka                `Tanishkasharma01`      URL and QR-code threat
                                                  scanning, forensic
                                                  analysis workflow and
                                                  threat mapping

  Sonu                    `yes-its-SONU-9845`     Frontend styling,
                                                  responsive pages,
                                                  reusable UI components
                                                  and navigation

  
  Shilpi                  `ShilpiJha2210`         Dashboard metrics,
                                                  audit logs, MTTR
                                                  calculations and report
                                                  generation

  -----------------------------------------------------------------------

This table describes the planned/recorded module distribution. Git
history and pull requests should be used to verify individual
contributions.

### Problem Statement

Cybersecurity incidents such as phishing, malware, unauthorized access,
data exposure, and denial-of-service attacks need to be reported and
tracked consistently. When reports are scattered across messages or
spreadsheets, organizations may struggle to prioritize incidents,
preserve investigation history, assign responsibility, and monitor
resolution.

CIRMS aims to provide a centralized workflow for incident submission,
risk-based prioritization, role-aware investigation, audit logging, and
reporting.

### Project Objectives

-   Provide a centralized portal for submitting and tracking security
    incidents.
-   Support separate access levels for employees, SOC analysts, and
    administrators.
-   Calculate a risk score from defined incident factors to support
    triage.
-   Record incident status changes, investigation notes, and relevant
    audit events.
-   Provide response guidance for common incident categories.
-   Present dashboards and downloadable reports for operational review.
-   Deploy the application using a containerized Java runtime and a
    managed MySQL database.

------------------------------------------------------------------------

## Week 2: Abstract, Scope, and Requirements

### Abstract

CIRMS is a role-based web application for managing the lifecycle of
cybersecurity incidents. Employees can submit security reports, analysts
can review and investigate incidents, and administrators can manage
users and inspect system-level information. The application combines a
Java web backend, a MySQL persistence layer, and browser-based
interfaces.

Its planned capabilities include risk-based incident triage, incident
status tracking, audit records, response playbooks, dashboard metrics,
and report exports. Security controls include role-based access checks,
password hashing, request validation, CSRF protection, login rate
limiting, and parameterized database queries where implemented. The
system is intended to help structure incident handling and improve
traceability; risk scores and generated playbooks are decision-support
features and must be reviewed by a responsible analyst.

### Scope

-   User registration and authentication, subject to configured account
    rules.
-   Role-based routing and access control for `USER`, `ANALYST`, and
    `ADMIN`.
-   Incident creation, review, status updates, and investigation
    chronology.
-   Risk scoring using threat category, asset criticality, impact scope,
    and data sensitivity.
-   Response playbook recommendations for supported incident types.
-   Audit event recording, dashboard metrics, and report export.
-   Cloud deployment with environment-based configuration.

### Important Limitations

-   A calculated risk score is a triage aid, not a guarantee of actual
    business impact.
-   Automated playbooks provide recommendations and must be validated
    before operational use.
-   Integrations with third-party threat-intelligence services depend on
    valid API keys, provider availability, quotas, and current
    configuration.
-   Availability and performance depend on hosting plan, database plan,
    network conditions, and external services.
-   Before production use, review authorization rules, logging of
    sensitive data, dependency security, backups, secrets management,
    and incident-response procedures.

------------------------------------------------------------------------

## Week 3: Requirements and User Roles

### User Roles

The application defines three primary role categories:

-   **USER / Employee:** Submits a security incident and reviews the
    incidents accessible to that account.
-   **ANALYST / SOC Responder:** Reviews assigned or accessible
    incidents, investigates evidence, updates incident status, and uses
    response guidance.
-   **ADMIN:** Performs authorized user-management tasks and reviews
    administrative dashboards, metrics, incidents, and audit
    information.

The effective permissions must be verified against the current code and
database configuration.

### Functional Requirements

1.  Users can authenticate and access features allowed by their role.
2.  The application can create and persist incident records.
3.  Analysts can review incident details and update lifecycle status.
4.  Risk factors can be combined into a numeric score and triage
    category.
5.  The application can display recommended response steps for supported
    incident types.
6.  Audit events can record relevant user and system actions.
7.  Administrators can review dashboard metrics and generate reports.
8.  Unauthorized users should not be able to access restricted endpoints
    or records.

### Non-Functional Requirements

-   **Security:** Validate input, protect restricted routes, and avoid
    exposing secrets.
-   **Reliability:** Handle database and external-service errors without
    silently losing workflow state.
-   **Maintainability:** Separate controllers, models, DAO classes,
    security utilities, and views.
-   **Usability:** Provide clear status labels, forms, validation
    feedback, and responsive layouts.
-   **Traceability:** Keep useful audit information for important
    actions.
-   **Portability:** Support local execution and Docker-based deployment
    with configuration supplied outside source code.

------------------------------------------------------------------------

## Week 4: System Architecture and Core Modules

### Architecture

The project follows a layered MVC-style web architecture:

``` text
Browser
  |
  | JSP / HTML / CSS / JavaScript
  v
Controller Layer
Jakarta Servlets
  |
  v
Model / Business Logic
Java Classes and Security Services
  |
  v
DAO Layer
JDBC
  |
  v
MySQL Database
```

### Core Modules

#### 1. Authentication and User Management

-   `LoginServlet.java` handles sign-in and role-aware routing.
-   `RegisterServlet.java` supports account onboarding, subject to
    current configuration.
-   `LogoutServlet.java` ends the session and can record a logout audit
    event.
-   `UserDAO.java` manages user persistence and authentication-related
    queries.
-   `PasswordUtil.java` provides password hashing utilities.

#### 2. Incident Management

-   `IncidentServlet.java` coordinates incident submission, lifecycle
    actions, and updates.
-   `Incident.java` represents an incident record.
-   `IncidentUpdate.java` represents timeline entries, comments, or
    status updates.
-   `IncidentDAO.java` provides incident persistence and query
    operations.

#### 3. Administration and Analytics

-   `AdminServlet.java` provides authorized administrative workflows.
-   `AdminDAO.java` supplies dashboard counters and metric aggregation.
-   Administrative pages support user management, incident overview, and
    reporting where enabled.

#### 4. Risk Analysis and Response Guidance

-   `RiskAnalyzer.java` maps incident inputs to risk factors.
-   `RiskCalculator.java` calculates a numeric score and triage
    category.
-   `ResponseEngine.java` provides response playbook recommendations for
    supported incident categories.

#### 5. Security and Access Control

-   `AuthFilter.java` checks authentication and access restrictions for
    protected routes.
-   Security utilities support password verification and request
    protections.
-   Database operations should use parameterized queries to reduce SQL
    injection risk.
-   Secrets and credentials should be supplied through environment
    variables or private configuration.

#### 6. Audit and Reporting

-   `AuditLog.java` models audit entries.
-   `AuditLogDAO.java` persists security-relevant events.
-   `ReportServlet.java` coordinates authorized report generation and
    CSV export where implemented.

------------------------------------------------------------------------

## Week 5: Technology Stack and Database Design

### Technology Stack

  -----------------------------------------------------------------------
  Layer                               Technology
  ----------------------------------- -----------------------------------
  Backend language                    Java (configured project JDK)

  Web runtime                         Apache Tomcat 10.1

  Web framework/API                   Jakarta Servlet API and JSP

  Architecture                        MVC-style layered architecture

  Database                            MySQL-compatible database

  Persistence                         JDBC and DAO classes

  Build tool                          Maven

  Frontend                            JSP, HTML, CSS, JavaScript

  Version control                     Git and GitHub

  Containerization                    Docker

  Cloud application hosting           Render

  Cloud database                      Aiven MySQL, as described in the
                                      deployment configuration
  -----------------------------------------------------------------------

Confirm exact version numbers from `pom.xml`, the Dockerfile, and
deployment configuration before final submission.

### Database Design

The application schema is expected to include the following core
entities/tables, depending on the checked-in SQL schema:

-   `users`
-   `incidents`
-   `incident_updates`
-   `audit_logs`

The SQL file and actual database schema are the source of truth for
column names, constraints, indexes, relationships, and seed data.

### Data Flow

1.  A user submits a request through a browser form.
2.  The servlet controller validates the request and checks the current
    session and role.
3.  The relevant model/service logic processes the request.
4.  DAO classes execute database operations through JDBC.
5.  MySQL stores or retrieves application records.
6.  The controller selects a JSP view or redirects the user.
7.  Relevant security or workflow actions may be recorded in the audit
    trail.

------------------------------------------------------------------------

## Week 6: Authentication, Sessions, and Access Control

### Work Area

This phase focuses on account access, session handling, role-aware
routing, and security controls.

### Main Deliverables

-   Login and logout workflow.
-   Role-aware routing for employee, analyst, and admin views.
-   Password hashing and verification utility.
-   Authentication filter for protected application routes.
-   Validation and error feedback for authentication requests.
-   Login rate limiting and CSRF protection where configured in the
    current code.

### Security Notes

-   Never store plaintext user passwords.
-   A salted SHA-256 implementation is present in the project
    description, but a fast general-purpose hash is not the preferred
    choice for production password storage. Prefer a dedicated
    password-hashing algorithm such as Argon2id, bcrypt, or PBKDF2 with
    an appropriate work factor.
-   Ensure session IDs are regenerated after successful authentication
    where supported.
-   Verify that CSRF protection covers every state-changing browser
    request.
-   Check permissions on the server side; hiding a button in the UI is
    not authorization.
-   Avoid logging passwords, session tokens, API keys, or unnecessary
    personal data.

------------------------------------------------------------------------

## Week 7: Incident Lifecycle and Risk Scoring

### Incident Workflow

A typical incident workflow is:

1.  An employee submits an incident report.
2.  The application validates and persists the submitted information.
3.  Risk factors are evaluated to calculate a triage score.
4.  An analyst reviews the incident and records investigation updates.
5.  The incident status is changed as the investigation progresses.
6.  Relevant actions are recorded for later review.
7.  The incident can be included in dashboard metrics or reports.

### Risk Score Model

The project description defines a weighted risk equation:

``` text
Risk Score =
(Threat Weight × 0.35
 + Asset Criticality × 0.25
 + Impact Scope × 0.20
 + Data Sensitivity × 0.20) × 100
```

The input weights are intended to be normalized between `0` and `1`.
Verify that the implementation normalizes the inputs consistently before
treating the result as a percentage.

### Triage Categories

      Score Category   Intended interpretation
  --------- ---------- -------------------------------------------------
    85--100 CRITICAL   Emergency review and urgent coordination
     65--84 HIGH       High-priority analyst review
     40--64 MEDIUM     Standard SOC triage queue
      0--39 LOW        Lower-priority review or informational handling

Thresholds and response targets should be confirmed against
`RiskCalculator.java` and the project's actual workflow rules.

------------------------------------------------------------------------

## Week 8: Response Playbooks and Investigation Workflow

### Response Engine

`ResponseEngine.java` provides response guidance for supported incident
categories. The project description includes examples such as:

-   **Phishing:** Review suspicious messages, block confirmed malicious
    senders/domains, and review affected credentials or tokens.
-   **Ransomware:** Isolate affected systems according to an approved
    procedure, preserve evidence, and coordinate recovery.
-   **Data Breach:** Preserve relevant evidence, assess scope, review
    access activity, and follow the organization's escalation process.
-   **DDoS:** Review traffic telemetry and apply approved mitigation
    controls with the network or hosting team.

These are high-level playbook examples, not automatic authorization to
execute disruptive production actions. Any containment action must be
approved and performed by an authorized responder.

### Investigation Records

The incident timeline can be used to document:

-   Initial report and triage observations.
-   Analyst comments and status transitions.
-   Evidence references and investigation findings.
-   Recommended actions and their review status.
-   Resolution notes and lessons learned.

------------------------------------------------------------------------

## Week 9: Dashboards, Audit Logs, and Reporting

### Dashboard and Metrics

The administrative workflow includes dashboard counters and metrics
aggregation through `AdminDAO.java`. Where implemented, metrics can help
summarize incident volume, status distribution, and resolution
performance.

### Audit Trail

`AuditLog.java` and `AuditLogDAO.java` represent audit records and their
persistence. Useful audit fields commonly include the actor, action,
related entity, timestamp, and outcome; use the actual schema to confirm
the stored fields.

An application-level audit log should not automatically be described as
immutable unless technical controls actually prevent unauthorized
modification or deletion.

### Reports

`ReportServlet.java` supports report workflows and CSV export as
described in the project notes. Before release, validate:

-   Report authorization and record scope.
-   Correct timestamp formatting and timezone handling.
-   CSV escaping for commas, quotes, newlines, and spreadsheet formula
    risks.
-   Whether exported data contains sensitive information.
-   Whether the report matches the currently selected filters.

------------------------------------------------------------------------

## Week 10: Cloud Database, Docker, and Deployment Preparation

### Cloud Readiness

The deployment history describes a cloud MySQL configuration and
Docker-based packaging for the Java application.

### Main Deliverables

-   Externalized database configuration.
-   JDBC connection setup for the cloud database.
-   Dockerfile for building and running the web application.
-   Environment variables for database credentials and other private
    settings.
-   Application startup and health verification.
-   Deployment configuration connected to the GitHub repository.

### Configuration Checklist

-   Do not commit live database passwords or API keys.
-   Use the provider's current SSL/TLS settings for database
    connections.
-   Confirm database host, port, database name, username, and connection
    parameters.
-   Ensure the container listens on the port expected by the hosting
    platform.
-   Check startup logs and database connectivity after each deployment.
-   Confirm that uploaded reports or other files are stored persistently
    if the application needs them after a restart.

------------------------------------------------------------------------

## Week 11: Testing, Debugging, and Integration Review

### Testing Checklist

The following checks should be performed against the current deployed or
local build. Do not claim a test passed until its result has been
observed.

-   [ ] Maven build completes successfully.
-   [ ] Tomcat/container starts without deployment errors.
-   [ ] Database connection succeeds using private configuration.
-   [ ] Login, logout, and session expiry behave as expected.
-   [ ] Each role can access permitted pages and is blocked from
    restricted pages.
-   [ ] Incident creation and retrieval work.
-   [ ] Risk scores and category thresholds match the implemented
    formula.
-   [ ] Incident updates appear in the correct timeline.
-   [ ] Audit records are generated for the expected actions.
-   [ ] CSV exports contain correct data and are properly escaped.
-   [ ] Invalid input and unavailable database conditions produce useful
    errors.
-   [ ] SQL injection and cross-site scripting cases are safely handled.
-   [ ] CSRF checks and login rate limiting are tested if enabled.
-   [ ] Cloud deployment starts and connects to the configured database.

### Recorded Integration Issues and Responses

The development notes mention these deployment/integration concerns:

1.  **Maven/Docker build issue:** An unescaped XML character in
    `pom.xml` required XML-safe encoding.
2.  **Timezone mismatch:** Cloud database timestamps and application
    display time needed consistent timezone normalization and Indian
    Standard Time formatting.
3.  **Free-tier startup latency:** The hosting platform may pause or
    restart free services, resulting in slower first requests.

Re-test these fixes in the current repository and hosting environment
before describing them as resolved.

------------------------------------------------------------------------

## Week 12: Final Deployment and Project Evaluation

### Deployment

The recorded deployment configuration uses Docker to run the Java web
application on Render and connects it to a cloud-hosted MySQL database.

-   **GitHub repository:**
    https://github.com/codewithvasu-7/CyberIncidentManagement
-   **Recorded live URL:**
    https://cyberincidentmanagement-1.onrender.com

Live status can change. Verify the URL, login flow, database
connectivity, and core workflows before a demonstration or academic
submission. Never place production credentials or secret API keys in
this README.

### Final Evaluation Criteria

-   Users can authenticate and receive role-appropriate access.
-   Incidents can be created, viewed, and updated.
-   Risk calculations return expected results for known inputs.
-   Response guidance is appropriate to the selected incident category.
-   Audit events and reports are available to authorized users.
-   The deployed application connects to its configured database.
-   Configuration values and secrets are not exposed in the repository.
-   Setup instructions match the actual repository files.

### Final Deliverables

-   Java web application source code.
-   JSP, HTML, CSS, and JavaScript interface.
-   Database schema and seed data, if included in the repository.
-   Docker and cloud deployment configuration.
-   Test evidence and screenshots.
-   Project report, research paper, presentation, and demonstration
    video (links to be added below).

------------------------------------------------------------------------

## Project Directory Structure

The following is the intended structure based on the project layout
shared during development. Confirm names and files against the current
repository before relying on it as an exact inventory.

``` text
CyberIncidentManagement/
├── src/
│   └── main/
│       ├── java/
│       │   └── com/
│       │       └── cyberincident/
│       │           ├── controller/
│       │           │   ├── LoginServlet.java
│       │           │   ├── RegisterServlet.java
│       │           │   ├── LogoutServlet.java
│       │           │   ├── IncidentServlet.java
│       │           │   ├── AdminServlet.java
│       │           │   └── ReportServlet.java
│       │           ├── model/
│       │           │   ├── User.java
│       │           │   ├── Incident.java
│       │           │   ├── IncidentUpdate.java
│       │           │   └── AuditLog.java
│       │           ├── dao/
│       │           │   ├── DBConnection.java
│       │           │   ├── UserDAO.java
│       │           │   ├── IncidentDAO.java
│       │           │   ├── AdminDAO.java
│       │           │   └── AuditLogDAO.java
│       │           ├── security/
│       │           │   ├── PasswordUtil.java
│       │           │   ├── RiskAnalyzer.java
│       │           │   ├── RiskCalculator.java
│       │           │   └── ResponseEngine.java
│       │           └── filter/
│       │               └── AuthFilter.java
│       ├── resources/
│       └── webapp/
│           ├── index.jsp
│           ├── login.jsp
│           ├── register.jsp
│           ├── css/
│           │   └── style.css
│           ├── js/
│           │   └── script.js
│           ├── user/
│           ├── analyst/
│           ├── admin/
│           └── WEB-INF/
│               └── web.xml
├── database/
│   └── database.sql
├── Dockerfile
├── pom.xml
├── README.md
└── .gitignore
```

------------------------------------------------------------------------

## Installation and Local Usage

### Prerequisites

-   JDK version compatible with the project configuration.
-   Maven.
-   Apache Tomcat 10.1-compatible runtime for Jakarta Servlet
    applications.
-   MySQL-compatible database.
-   Git.
-   Docker (optional, for container-based execution).

### 1. Clone the Repository

``` bash
git clone https://github.com/codewithvasu-7/CyberIncidentManagement.git
cd CyberIncidentManagement
```

### 2. Configure the Database

Create the database using the SQL file if it is present in the
repository. For example, from a MySQL client:

``` sql
CREATE DATABASE cyber_incident_db;
```

Then import the project's actual schema file using the correct local
path:

``` sql
SOURCE /path/to/CyberIncidentManagement/database/database.sql;
```

Update the database URL, username, and password using the project's
supported configuration method. Prefer environment variables or a local,
untracked properties file. Do not use the sample path above literally;
replace it with the path on your machine.

### 3. Configure Database Credentials

Review `DBConnection.java`, `src/main/resources/db.properties`, and the
deployment environment to determine which configuration source is
active. Do not assume that a fallback password is safe or suitable for
production. Keep real credentials out of Git.

### 4. Build the Application

From the project root:

``` bash
mvn clean package
```

If the project uses a Maven wrapper, use the wrapper commands documented
in the repository.

### 5. Run with Tomcat

Deploy the generated WAR file to the `webapps` directory of a compatible
Tomcat installation, start Tomcat, and open the context path shown by
the deployed WAR name. The exact WAR filename and context path depend on
the current Maven configuration.

### 6. Run with Docker

If the repository contains a valid Dockerfile, build the image:

``` bash
docker build -t cirms .
```

Run it using the required environment variables and port mapping for the
actual container configuration. Do not put real secrets directly in a
command that will be saved in shell history or shared.

------------------------------------------------------------------------

## Repository Branch Strategy

The recorded team branches are:

  Team Member   Branch
  ------------- ------------
  Vasudev       `vasudev`
  Shailja       `shailja`
  Tanishka      `tanishka`
  Sonu          `sonu`
  Shilpi        `shilpi`

A recommended workflow is:

1.  Each member works on their assigned branch.
2.  Changes are committed with clear, focused messages.
3.  The branch is pushed to GitHub.
4.  A pull request is opened against `main`.
5.  Changes are reviewed and tested before merging.
6.  The team verifies that the integrated application builds and runs.

Branch existence and contribution history should be checked directly on
GitHub.

------------------------------------------------------------------------

## Academic Documentation and Demonstration Links

Add the final links here when the documents are ready. Keep the
placeholder text until a real, accessible link is available.

  ---------------------------------------------------------------------------------------
  Deliverable             Description             Link
  ----------------------- ----------------------- ---------------------------------------
  Major Project Report    Full project report,    `ADD_REPORT_LINK_HERE`
                          architecture,           
                          implementation,         
                          testing, screenshots,   
                          and conclusion          

  SRS Document            Software requirements   `ADD_SRS_LINK_HERE`
                          specification           

  Research Paper          Research paper          `ADD_RESEARCH_PAPER_LINK_HERE`
                          describing the problem, 
                          approach,               
                          implementation,         
                          evaluation, and         
                          limitations             

  Project Presentation    PPT or PDF used for the `ADD_PPT_LINK_HERE`
                          final presentation      

  Demonstration Video     Video showing the       `ADD_VIDEO_LINK_HERE`
                          actual application      
                          workflow                

  Screenshots             UI and test screenshots `ADD_SCREENSHOTS_FOLDER_OR_LINK_HERE`

  Weekly Progress Reports Verified weekly         `ADD_WEEKLY_REPORTS_LINK_HERE`
                          activity reports        
  ---------------------------------------------------------------------------------------

------------------------------------------------------------------------

## Future Scope

-   Improve password storage by adopting a dedicated password-hashing
    algorithm if not already implemented.
-   Add configurable notifications for incident assignment and status
    changes.
-   Improve risk-score calibration using a documented evaluation
    dataset.
-   Add richer incident analytics and trend visualizations.
-   Add automated integration and security testing to the CI pipeline.
-   Strengthen audit-log integrity and define a documented retention
    policy.
-   Add backup, recovery, observability, and deployment rollback
    procedures.
-   Review third-party threat-intelligence integrations, API quotas, and
    secret rotation.
-   Expand accessibility, responsive UI testing, and user documentation.

------------------------------------------------------------------------

## References

-   [Apache Tomcat Documentation](https://tomcat.apache.org/)
-   [Jakarta Servlet
    Specification](https://jakarta.ee/specifications/servlet/)
-   [Java Documentation](https://docs.oracle.com/en/java/)
-   [MySQL Documentation](https://dev.mysql.com/doc/)
-   [Maven Documentation](https://maven.apache.org/guides/)
-   [NIST Computer Security Incident Handling Guide, SP 800-61
    Rev. 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
-   [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

------------------------------------------------------------------------

## Maintainer

**Project Team:** CyberIncidentManagement\
**Repository Owner:** `codewithvasu-7`\
**Project:** Cybersecurity Incident Reporting & Management System
(CIRMS)

For academic evaluation, verify all implementation details, deployment
status, team contributions, and test results against the current
repository before submission.
