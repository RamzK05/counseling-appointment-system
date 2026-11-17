
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';
require_once dirname(__DIR__) . '/app/authentication.php';

// Check whether the user is authenticated.
if (
    empty($_SESSION['logged_in']) ||
    empty($_SESSION['user_id'])
) {

    authenticationLog(
        $pdo,
        'ADMIN_ACCESS_DENIED',
        $_SESSION['username'] ?? null,
        $_SESSION['user_id'] ?? null,
        'Unauthenticated user attempted to access the admin dashboard'
    );

    header('Location: login.php');
    exit;
}

// Only administrators can access this page.
if (($_SESSION['user_role'] ?? '') !== 'admin') {

    authenticationLog(
        $pdo,
        'ADMIN_ACCESS_DENIED',
        $_SESSION['username'] ?? null,
        $_SESSION['user_id'] ?? null,
        'Non-admin user attempted to access the admin dashboard'
    );

    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Denied | Campus Counseling</title>
        <link rel="stylesheet" href="css/style.css">
    </head>
    <body>
        <main class="auth-container">
            <section class="auth-card">
                <h2>Access Denied</h2>
                <p>You are not authorized to access the administrator dashboard.</p>
                <a href="dashboard.php">Return to Dashboard</a>
            </section>
        </main>
    </body>
    </html>
    <?php
    exit;
}

// Record authorized administrator access.
authenticationLog(
    $pdo,
    'ADMIN_VIEWED_DASHBOARD',
    $_SESSION['username'],
    $_SESSION['user_id'],
    'Administrator accessed the security monitoring dashboard'
);

// Dashboard data.
$totalEvents = 0;
$totalFlags = 0;
$activeIpBlocks = 0;

$securityFlags = [];
$recentActivities = [];

$databaseError = false;

try {

    // Count activity events from the last 24 hours.
    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
         FROM activity_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );

    $stmt->execute();
    $totalEvents = (int) $stmt->fetchColumn();

    // Count security flags detected today.
    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
         FROM security_flags
         WHERE detected_date = CURDATE()'
    );

    $stmt->execute();
    $totalFlags = (int) $stmt->fetchColumn();

    // Count IP addresses currently blocked.
    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
         FROM ip_blocks
         WHERE blocked_until > NOW()'
    );

    $stmt->execute();
    $activeIpBlocks = (int) $stmt->fetchColumn();

    // Retrieve the latest security flags.
    $stmt = $pdo->prepare(
        'SELECT flag_type, description, related_ip, detected_at
         FROM security_flags
         ORDER BY detected_at DESC
         LIMIT 20'
    );

    $stmt->execute();
    $securityFlags = $stmt->fetchAll();

    // Retrieve the latest activity events.
    $stmt = $pdo->prepare(
        'SELECT event_type, username_typed, ip_address,
                details, created_at
         FROM activity_logs
         ORDER BY created_at DESC
         LIMIT 50'
    );

    $stmt->execute();
    $recentActivities = $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        'Admin dashboard database error: ' . $e->getMessage()
    );

    $databaseError = true;
}

// Administrator information.
$adminName = $_SESSION['user_first_name'] ?? 'Administrator';
$adminUsername = $_SESSION['username'] ?? '';

// CSRF token for logout.
$csrfToken = $_SESSION['csrf_token'];

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Security Monitoring | Campus Counseling</title>

    <link rel="stylesheet" href="css/style.css">

    <style>

        .admin-container {
            width: min(1200px, 94%);
            margin: 35px auto;
        }

        .admin-heading {
            margin-bottom: 25px;
        }

        .admin-heading h1 {
            margin-bottom: 8px;
        }

        .admin-heading p {
            color: #666;
        }

        .admin-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 18px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: #fff;
            border: 1px solid #e3e7ed;
            border-radius: 10px;
            padding: 22px;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.04);
        }

        .summary-card h3 {
            font-size: 14px;
            color: #666;
            margin-bottom: 12px;
        }

        .summary-card .number {
            font-size: 30px;
            font-weight: bold;
            color: #142b4a;
        }

        .monitor-card {
            background: #fff;
            border: 1px solid #e3e7ed;
            border-radius: 10px;
            padding: 22px;
            margin-bottom: 25px;
            overflow-x: auto;
        }

        .monitor-card h2 {
            margin-bottom: 18px;
            color: #142b4a;
        }

        .monitor-table {
            width: 100%;
            border-collapse: collapse;
            min-width: 650px;
        }

        .monitor-table th,
        .monitor-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e8ebef;
            font-size: 13px;
            vertical-align: top;
        }

        .monitor-table th {
            background: #f4f6fa;
            color: #142b4a;
        }

        .monitor-table td {
            overflow-wrap: anywhere;
        }

        .empty-message {
            color: #777;
            padding: 15px 0;
        }

        .database-error {
            background: #f8d7da;
            color: #842029;
            padding: 14px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .admin-label {
            display: inline-block;
            background: #142b4a;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
        }

        .readonly-note {
            font-size: 13px;
            color: #666;
            margin-bottom: 15px;
        }

        @media (max-width: 600px) {

            .admin-container {
                width: 92%;
            }

            .monitor-card {
                padding: 15px;
            }

        }

    </style>

</head>

<body>

<header class="site-header">

    <div class="brand">

        <div class="brand-mark">CC</div>

        <div>
            <strong>Campus Counseling</strong>
            <small>Security Monitoring Portal</small>
        </div>

    </div>

    <nav>

        <form action="logout.php" method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= h($csrfToken) ?>"
            >

            <button type="submit">Log Out</button>

        </form>

    </nav>

</header>

<main class="admin-container">

    <section class="admin-heading">

        <h1>Security Monitoring Dashboard</h1>

        <p>
            Welcome, <?= h($adminName) ?>.
            <span class="admin-label">Administrator</span>
        </p>

        <p>
            Username: <?= h($adminUsername) ?>
        </p>

        <p class="readonly-note">
            This dashboard provides read-only access to security
            activity records and detected security flags.
        </p>

    </section>

    <?php if ($databaseError): ?>

        <div class="database-error" role="alert">
            Unable to retrieve all monitoring information.
            Please check the application error log.
        </div>

    <?php endif; ?>

    <section class="admin-summary">

        <div class="summary-card">

            <h3>Events in the Last 24 Hours</h3>

            <div class="number">
                <?= number_format($totalEvents) ?>
            </div>

        </div>

        <div class="summary-card">

            <h3>Security Flags Detected Today</h3>

            <div class="number">
                <?= number_format($totalFlags) ?>
            </div>

        </div>

        <div class="summary-card">

            <h3>Currently Blocked IPs</h3>

            <div class="number">
                <?= number_format($activeIpBlocks) ?>
            </div>

        </div>

    </section>

    <section class="monitor-card">

        <h2>Detected Security Flags</h2>

        <p class="readonly-note">
            Latest security findings recorded by the monitoring script.
        </p>

        <?php if (empty($securityFlags)): ?>

            <p class="empty-message">
                No security flags have been recorded.
            </p>

        <?php else: ?>

            <table class="monitor-table">

                <thead>

                    <tr>
                        <th>Flag Type</th>
                        <th>Description</th>
                        <th>Related IP</th>
                        <th>Detection Time</th>
                    </tr>

                </thead>

                <tbody>

                    <?php foreach ($securityFlags as $flag): ?>

                        <tr>

                            <td>
                                <?= h($flag['flag_type']) ?>
                            </td>

                            <td>
                                <?= h($flag['description']) ?>
                            </td>

                            <td>
                                <?= h($flag['related_ip'] ?? 'N/A') ?>
                            </td>

                            <td>
                                <?= h($flag['detected_at']) ?>
                            </td>

                        </tr>

                    <?php endforeach; ?>

                </tbody>

            </table>

        <?php endif; ?>

    </section>

    <section class="monitor-card">

        <h2>Recent Activity Logs</h2>

        <p class="readonly-note">
            Latest 50 recorded authentication and security events.
        </p>

        <?php if (empty($recentActivities)): ?>

            <p class="empty-message">
                No activity records are available.
            </p>

        <?php else: ?>

            <table class="monitor-table">

                <thead>

                    <tr>
                        <th>Event</th>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Details</th>
                        <th>Date and Time</th>
                    </tr>

                </thead>

                <tbody>

                    <?php foreach ($recentActivities as $activity): ?>

                        <tr>

                            <td>
                                <?= h($activity['event_type']) ?>
                            </td>

                            <td>
                                <?= h($activity['username_typed'] ?? 'N/A') ?>
                            </td>

                            <td>
                                <?= h($activity['ip_address']) ?>
                            </td>

                            <td>
                                <?= h($activity['details'] ?? 'N/A') ?>
                            </td>

                            <td>
                                <?= h($activity['created_at']) ?>
                            </td>

                        </tr>

                    <?php endforeach; ?>

                </tbody>

            </table>

        <?php endif; ?>

    </section>

</main>

</body>
</html>