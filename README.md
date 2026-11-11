# Campus Counseling Appointment and Secure Monitoring System

A PHP and MySQL-based web application developed as the final laboratory project for **IT 107 – Information Assurance and Security 1** at Caraga State University – Cabadbaran Campus.

The system is designed to provide a secure student registration and appointment-request process while demonstrating essential information security principles, including authentication, data protection, access control, and security monitoring.

> **Project Status:** Under Development  
> **Academic Year:** 1st Semester, A.Y. 2026–2027

---

## 1. Project Overview

The Campus Counseling Appointment and Secure Monitoring System is a student-developed web application intended to organize student registration and appointment requests.

The project emphasizes protecting user accounts and sensitive information through security controls required by the IT 107 final laboratory project.

It is designed for student users and authorized system personnel.

**Note:** This is an independent academic project and is not an official university-operated counseling service.

## 2. Project Objectives

The project aims to:

- Provide a structured student registration process.
- Implement secure user authentication and email verification.
- Allow students to submit appointment requests.
- Protect personal and sensitive information.
- Prevent common web application attacks.
- Record security-related activities.
- Detect suspicious activity through automated monitoring.
- Provide authorized administrators with a security monitoring dashboard.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| PHP | Server-side processing and validation |
| MySQL / MariaDB | Database management |
| HTML5 | Web page structure |
| CSS3 | Interface styling and responsive layout |
| JavaScript | Client-side interactions and validation |
| PDO | Secure database connectivity |
| PHPMailer | Email delivery |
| PHP GD | Image CAPTCHA generation |
| Composer | PHP dependency management |
| XAMPP | Local development environment |
| Git and GitHub | Version control and source code management |

## 4. Current Implemented Features

The following components have been developed:

- Initial project directory structure.
- MySQL database schema containing nine tables.
- PDO database connection.
- Application security bootstrap.
- Secure session configuration.
- CSRF token generation and validation.
- HTML output escaping helper.
- PHPMailer dependency installation.
- Privacy Notice page.
- Configuration directory access protection.
- GD-based image CAPTCHA generation.
- CAPTCHA refresh endpoint.
- Student registration interface.
- Server-side CAPTCHA verification.

**Important:** The registration interface and CAPTCHA verification are implemented, but complete account creation, OTP verification, and the remaining authentication workflows are still under development.

## 5. Planned Features

The following features are planned to satisfy the IT 107 project requirements.

### Student Registration
- Student information and account credentials.
- System-specific registration fields.
- Server-side input validation.
- Unique ID number, username, and email validation.
- Password strength checking.
- Security questions and hashed answers.
- Privacy Notice consent.
- CAPTCHA verification.
- Email-based account verification.

### Authentication
- Username and password authentication.
- OTP-based login verification.
- Failed login attempt tracking.
- Progressive account lockout.
- IP-based blocking.
- Security alert emails.
- Session hardening and automatic logout.

### Password Recovery
- Forgot Password functionality.
- Security question verification.
- OTP-based password reset.
- Password history checking.
- Prevention of password reuse.

### Security Monitoring
- Activity logging.
- Suspicious activity detection.
- Automated monitoring script.
- Security flags.
- Read-only administrator monitoring dashboard.
- Security event filtering and reporting.

## 6. Database Structure

The project currently contains nine database tables:

| Table | Purpose |
|---|---|
| `users` | Student and authorized staff accounts |
| `auth_answers` | Hashed security question answers |
| `password_history` | Previous password hashes |
| `otp_records` | Hashed one-time passwords |
| `appointments` | Student appointment requests |
| `login_attempts` | Successful and failed login attempts |
| `ip_blocks` | Temporarily blocked IP addresses |
| `activity_logs` | Recorded system and security activities |
| `security_flags` | Detected suspicious activities |

Database name: `counseling_db`

## 7. Project Directory Structure

```text
counseling/
│
├── app/
│   ├── bootstrap.php
│   └── db.php
│
├── config/
│   ├── config.php
│   ├── config.sample.php
│   └── .htaccess
│
├── database/
│   └── schema.sql
│
├── public/
│   ├── index.html
│   ├── register.php
│   ├── login.html
│   ├── privacy.php
│   ├── captcha.php
│   ├── captcha_refresh.php
│   └── css/
│       └── style.css
│
├── scripts/
│   └── monitor.php
│
├── logs/
│
├── vendor/
│
├── composer.json
├── composer.lock
├── .gitignore
└── README.md
```

## 8. Installation and Setup

### Prerequisites

Install the following:

- XAMPP with Apache, MySQL, and PHP.
- Composer.
- Visual Studio Code or another code editor.
- Git.

The PHP GD extension and OpenSSL extension must also be enabled.

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Replace the placeholder with your actual GitHub repository URL.

Alternatively, place the project folder inside:

```text
C:\xampp\htdocs\
```

### Step 2: Install Dependencies

Open a terminal inside the project directory and run:

```bash
composer install
```

This installs the PHP dependencies specified in `composer.lock`, including PHPMailer.

### Step 3: Configure the Database

1. Start Apache and MySQL using XAMPP.
2. Open phpMyAdmin:

```text
http://localhost/phpmyadmin
```

3. Select the Import tab.
4. Import `database/schema.sql`.
5. Confirm that the `counseling_db` database and its nine tables are created.

### Step 4: Configure Application Settings

Create your local configuration file using:

```text
config/config.sample.php
```

Save the local configuration as:

```text
config/config.php
```

Update the database and SMTP settings using your own local credentials.

Generate and configure a secure encryption key.

**Security warning:** Never commit `config/config.php`, SMTP App Passwords, encryption keys, or other secrets to GitHub.

### Step 5: Run the Application

Open your browser and visit:

```text
http://localhost/counseling/public/
```

Registration page:

```text
http://localhost/counseling/public/register.php
```

The application currently runs on your local XAMPP server.

## 9. Security Measures

The project follows the security requirements of the IT 107 handout.

The planned security protections include:

1. Prepared statements against SQL injection.
2. Output escaping against cross-site scripting (XSS).
3. CSRF token validation.
4. Username enumeration prevention.
5. IP-based blocking.
6. Secure session management.
7. Password history enforcement.
8. Honeypot fields.
9. Activity logging.
10. Secure error handling.
11. Protection of configuration files and secrets.
12. Security headers.
13. AES-256-GCM encryption for sensitive stored information.

These protections are being implemented and tested throughout development. Their inclusion in this list does not indicate that every protection is already complete.

## 10. Privacy and Data Protection

The application is designed to handle personal information responsibly and follows the principles of the Philippine Data Privacy Act of 2012 (Republic Act No. 10173).

The system includes a Privacy Notice explaining the information collected, its intended purpose, protection measures, retention approach, and contact information.

Access to sensitive information should be restricted to authorized users.

Sensitive appointment notes are intended to be encrypted before database storage.

## 11. Development and Version Control

Git and GitHub are used to track project development.

The IT 107 handout requires:

- At least 30 meaningful commits.
- Development spanning at least four weeks.
- Clear commit messages describing each change.
- A Development Journal with one entry per week.
- Evidence of the required project checkpoints.

Example Git commands:

```bash
git status
git add .
git commit -m "feat: describe the completed feature"
git push origin main
```

Never stage or commit secret configuration files.

## 12. Academic Information

**Course:** IT 107 – Information Assurance and Security 1  
**Project:** Final Laboratory Project  
**System:** Campus Counseling Appointment and Secure Monitoring System  
**Institution:** Caraga State University – Cabadbaran Campus  
**Academic Year:** 1st Semester, A.Y. 2026–2027

---

*This project is developed for academic and educational purposes as part of the IT 107 Information Assurance and Security 1 final laboratory requirements.*