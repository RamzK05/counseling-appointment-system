
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';

// Only authenticated students can access this page.
if (
    empty($_SESSION['logged_in']) ||
    empty($_SESSION['user_id'])
) {
    header('Location: login.php');
    exit;
}

// Get student information from the authenticated session.
$firstName = $_SESSION['user_first_name'] ?? 'Student';
$username = $_SESSION['username'] ?? '';
$email = $_SESSION['user_email'] ?? '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard | Campus Counseling</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<header class="site-header">
    <div class="brand">
        <div class="brand-mark">CC</div>
        <div>
            <strong>Campus Counseling</strong>
            <small>Student Portal</small>
        </div>
    </div>

    <nav>
        <a href="logout.php">Log Out</a>
    </nav>
</header>

<main class="container">
    <section class="dashboard-content">

        <h1>Welcome, <?= h($firstName) ?>!</h1>

        <p>
            You have successfully logged in to the
            Campus Counseling Appointment and Secure Monitoring System.
        </p>

        <div class="dashboard-card">
            <h2>Student Account Information</h2>

            <p>
                <strong>First Name:</strong>
                <?= h($firstName) ?>
            </p>

            <p>
                <strong>Username:</strong>
                <?= h($username) ?>
            </p>

            <p>
                <strong>Email Address:</strong>
                <?= h($email) ?>
            </p>

            <p>
                <strong>Account Status:</strong>
                Authenticated
            </p>
        </div>

        <div class="dashboard-card">
            <h2>Student Dashboard</h2>
            <p>
                Your account is active. Additional appointment
                and monitoring features will be added here.
            </p>
        </div>

    </section>
</main>

</body>
</html>
