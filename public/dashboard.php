
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';

// Handle background session heartbeat requests.
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['action'] ?? '') === 'keepalive'
) {
    if (
        empty($_SESSION['logged_in']) ||
        empty($_SESSION['user_id'])
    ) {
        http_response_code(401);
        exit;
    }

    if (!verifyCsrfToken()) {
        http_response_code(403);
        exit;
    }

    // bootstrap.php already refreshed last_activity.
    http_response_code(204);
    exit;
}

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
$csrfToken = $_SESSION['csrf_token'];

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard | Campus Counseling</title>
    <link rel="stylesheet" href="css/style.css">

    <style>
        .session-warning {
            background: #fff3cd;
            color: #664d03;
            border: 1px solid #ffecb5;
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .session-warning button {
            margin-top: 10px;
            padding: 8px 14px;
            cursor: pointer;
        }

        .session-warning[hidden] {
            display: none;
        }
    </style>
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
        <form id="logoutForm" action="logout.php" method="POST">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= h($csrfToken) ?>"
            >
            <button type="submit">Log Out</button>
        </form>
    </nav>
</header>

<main class="container">

    <div
        id="sessionWarning"
        class="session-warning"
        role="alert"
        hidden
    >
        <strong>Session Timeout Warning</strong>

        <p>
            You have been inactive.
            You will be logged out in
            <strong id="countdown">60</strong> seconds.
        </p>

        <button type="button" id="stayLoggedIn">
            Stay Logged In
        </button>
    </div>

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

<script>
    const IDLE_LIMIT = 300000;
    const WARNING_TIME = 240000;
    const AUTO_LOGOUT_TIME = 299000;

    const warningBox = document.getElementById('sessionWarning');
    const countdownDisplay = document.getElementById('countdown');
    const stayLoggedInButton = document.getElementById('stayLoggedIn');
    const logoutForm = document.getElementById('logoutForm');

    const csrfToken = <?= json_encode($csrfToken) ?>;

    let warningTimer;
    let logoutTimer;
    let countdownTimer;
    let heartbeatLastSent = 0;

    function sendHeartbeat() {
        const now = Date.now();

        // Avoid sending too many requests.
        if (now - heartbeatLastSent < 1000) {
            return;
        }

        heartbeatLastSent = now;

        const formData = new FormData();

        formData.append('action', 'keepalive');
        formData.append('csrf_token', csrfToken);

        fetch('dashboard.php', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).then(response => {
            if (response.status === 401 || response.status === 403) {
                window.location.replace('login.php?session_expired=1');
            }
        }).catch(() => {
            // The server will still enforce the session timeout.
        });
    }

    function showWarning() {
        warningBox.hidden = false;

        let remainingSeconds = 60;

        countdownDisplay.textContent = remainingSeconds;

        countdownTimer = setInterval(() => {
            remainingSeconds--;

            countdownDisplay.textContent =
                Math.max(remainingSeconds, 0);

            if (remainingSeconds <= 0) {
                clearInterval(countdownTimer);
            }
        }, 1000);
    }

    function resetIdleTimers() {
        clearTimeout(warningTimer);
        clearTimeout(logoutTimer);
        clearInterval(countdownTimer);

        warningBox.hidden = true;

        sendHeartbeat();

        warningTimer = setTimeout(
            showWarning,
            WARNING_TIME
        );

        logoutTimer = setTimeout(() => {
            logoutForm.submit();
        }, AUTO_LOGOUT_TIME);
    }

    // Reset inactivity timers when the student interacts.
    [
        'keydown',
        'mousedown',
        'scroll',
        'touchstart',
        'click'
    ].forEach(eventName => {
        document.addEventListener(eventName, () => {
            if (!warningBox.hidden) {
                return;
            }

            resetIdleTimers();
        }, { passive: true });
    });

    // Allow the student to continue the session.
    stayLoggedInButton.addEventListener(
        'click',
        resetIdleTimers
    );

    // Start the inactivity timer.
    resetIdleTimers();
</script>

</body>
</html>