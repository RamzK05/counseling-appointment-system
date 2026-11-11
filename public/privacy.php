
<?php
require_once dirname(__DIR__) . '/app/bootstrap.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Notice | Campus Counseling</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<header class="site-header">
    <div class="brand">
        <div class="brand-mark">CC</div>
        <div>
            <h2>Campus Counseling</h2>
            <p>Appointment and Secure Monitoring System</p>
        </div>
    </div>

    <nav>
        <a href="index.html">Home</a>
        <a href="register.php">Register</a>
        <a href="login.html">Log-in</a>
    </nav>
</header>

<main class="page-container">
    <section class="registration-card">
        <h1>Privacy Notice</h1>
        <p>
            Campus Counseling Appointment and Secure Monitoring System
        </p>

        <div class="privacy-box">
            <h3>1. Information We Collect</h3>
            <p>
                The system collects student identification details,
                name, birthdate, address, email address, username,
                password credentials, authentication answers,
                appointment details, and other information required
                for account registration and appointment management.
            </p>

            <h3>2. Purpose of Collection</h3>
            <p>
                Personal information is collected to create and verify
                student accounts, manage appointment requests, support
                account recovery, and maintain system security.
            </p>

            <h3>3. How Information Is Protected</h3>
            <p>
                The system uses password hashing, encrypted sensitive
                appointment notes, email OTP verification, access
                controls, CSRF protection, and activity monitoring.
                Access to administrative functions is restricted to
                the authorized system administrator.
            </p>

            <h3>4. Data Retention</h3>
            <p>
                Under the proposed retention policy for this
                independently managed system, account and appointment
                records are retained while an account is active and
                for up to one year after account closure. Security
                logs are retained for up to one year for monitoring
                and security purposes. Records are securely deleted
                when the applicable retention period ends, unless
                retention is otherwise required for a legitimate
                purpose or applicable law.
            </p>

            <h3>5. Sharing of Information</h3>
            <p>
                Personal information is not intended for public
                disclosure. It may be accessed by the system
                administrator for account management, appointment
                processing, and security monitoring. Information
                necessary for email verification and security alerts
                may be processed through the configured email
                service.
            </p>

            <h3>6. Data Privacy Rights</h3>
            <p>
                Under the Data Privacy Act of 2012 (Republic Act
                No. 10173), individuals may exercise applicable
                rights concerning their personal information,
                subject to legal conditions and limitations.
            </p>

            <h3>7. Contact Information</h3>
            <p>
                For questions or concerns regarding personal
                information handled by this system, contact the
                System Administrator responsible for operating
                the Campus Counseling Appointment and Secure
                Monitoring System.
            </p>

            <h3>8. System Administration</h3>
            <p>
                This system is independently managed for its
                intended campus appointment and security
                management purposes. It does not claim to be
                an officially operated university counseling
                service.
            </p>
        </div>

        <p class="small-text">
            Privacy Notice for Campus Counseling Appointment
            and Secure Monitoring System.
        </p>

        <a href="register.php" class="btn btn-primary">
            Back to Registration
        </a>
    </section>
</main>

<footer>
    <p>&copy; 2026 Campus Counseling Appointment and Secure Monitoring System.</p>
</footer>

</body>
</html>