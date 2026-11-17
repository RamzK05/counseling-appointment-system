
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';
require_once dirname(__DIR__) . '/app/authentication.php';

$loginError = '';
$loginMessage = '';

// Process login form submission.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validate CSRF token.
    if (!verifyCsrfToken()) {
        $loginError = 'Your session has expired or the request is invalid. Please refresh the page.';

    } else {

        // CAPTCHA is single-use.
        $submittedCaptcha = strtoupper(
            trim((string) ($_POST['captcha'] ?? ''))
        );

        $storedCaptcha = $_SESSION['captcha_answer'] ?? '';

        unset($_SESSION['captcha_answer']);

        if (
            !is_string($storedCaptcha) ||
            $storedCaptcha === '' ||
            !hash_equals(
                $storedCaptcha,
                hash('sha256', $submittedCaptcha)
            )
        ) {
            $loginError = 'Incorrect CAPTCHA code. Please try again.';

            authenticationLog(
                $pdo,
                'CAPTCHA_FAILED',
                trim((string) ($_POST['username'] ?? '')),
                null,
                'Incorrect login CAPTCHA'
            );

        } else {

            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');

            if ($username === '' || $password === '') {
                $loginError = 'Please enter your username and password.';

            } else {

                $result = authenticateStudent(
                    $pdo,
                    $config,
                    $username,
                    $password
                );

                if ($result['success']) {

                    // Clear any previous login lockout countdown.
                    unset($_SESSION['login_lockout_until']);

                    // Credentials were accepted, but login is not complete
                    // until the email OTP has been verified.
                    $_SESSION['login_message'] = $result['message'];

                    header('Location: verify_login.php');
                    exit;

                } else {

                    $loginError = $result['message'];

                    // Save the account lockout end time.
                    if (
                        preg_match(
                            '/temporarily locked.*?(\d+)\s+seconds?/i',
                            $loginError,
                            $matches
                        )
                    ) {
                        $lockoutSeconds = (int) $matches[1];

                        $_SESSION['login_lockout_until'] =
                            time() + $lockoutSeconds;
                    }
                }
            }
        }
    }

    // Redirect after POST to prevent accidental form resubmission.
    if ($loginError !== '') {
        $_SESSION['login_error'] = $loginError;

        header('Location: login.php');
        exit;
    }
}

// Display saved messages.
$loginError = $_SESSION['login_error'] ?? '';
unset($_SESSION['login_error']);

$loginMessage = $_SESSION['login_message'] ?? '';
unset($_SESSION['login_message']);

// Calculate remaining account lockout time.
$lockoutUntil = (int) ($_SESSION['login_lockout_until'] ?? 0);

$remainingLockoutSeconds = max(0, $lockoutUntil - time());

$isLockedOut = $remainingLockoutSeconds > 0;

// Clear expired account countdown.
if (!$isLockedOut) {
    unset($_SESSION['login_lockout_until']);
}

// Check the actual IP block expiration in the database.
// This uses the database server's current time.
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';

$stmt = $pdo->prepare(
    'SELECT TIMESTAMPDIFF(SECOND, NOW(), blocked_until)
     FROM ip_blocks
     WHERE ip_address = ?
       AND blocked_until > NOW()
     ORDER BY blocked_until DESC
     LIMIT 1'
);

$stmt->execute([$clientIp]);

$ipBlockRemainingSeconds = max(
    0,
    (int) ($stmt->fetchColumn() ?: 0)
);

$isIpBlocked = $ipBlockRemainingSeconds > 0;

// Determine which countdown to display.
if ($isIpBlocked) {
    $countdownSeconds = $ipBlockRemainingSeconds;
} else {
    $countdownSeconds = $remainingLockoutSeconds;
}

// Disable login controls if either restriction is active.
$isLoginRestricted = $isLockedOut || $isIpBlocked;

// Display Forgot Password after repeated failed attempts.
$showForgotPassword = !empty($_SESSION['show_forgot_password']);
unset($_SESSION['show_forgot_password']);

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Student Login | Campus Counseling</title>

    <link rel="stylesheet" href="css/style.css">

    <style>

        .disabled-link {
            opacity: 0.5;
            cursor: not-allowed;
            pointer-events: none;
            text-decoration: none;
        }

        .login-button:disabled,
        .captcha-wrapper button:disabled,
        .form-group input:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .lockout-countdown {
            font-weight: bold;
            font-size: 1.1em;
            white-space: nowrap;
        }

    </style>

</head>

<body>

<header class="site-header">

    <div class="brand">

        <div class="brand-mark">CC</div>

        <div>
            <h1>Campus Counseling</h1>
            <p>Appointment and Secure Monitoring System</p>
        </div>

    </div>

    <nav>

        <a href="index.html">Home</a>

        <a
            href="register.php"
            class="<?= $isLockedOut ? 'disabled-link' : '' ?>"
            <?= $isLockedOut ? 'aria-disabled="true" tabindex="-1"' : '' ?>
        >
            Register
        </a>

    </nav>

</header>

<main class="page-container login-container">

    <div class="form-heading">

        <span class="eyebrow">STUDENT PORTAL</span>

        <h2>Welcome Back</h2>

        <p>Log in to access your account.</p>

    </div>

    <section class="registration-card login-card">

        <div class="notice">
            Please enter your registered username and password.
            Complete the security verification to continue.
        </div>

        <?php if ($isIpBlocked): ?>

            <div class="error-message" role="alert">

                Your IP address has been temporarily blocked due to
                repeated failed login attempts.

                Please try again in

                <span
                    id="lockoutCountdown"
                    class="lockout-countdown"
                >--:--</span>.

            </div>

        <?php elseif ($isLockedOut): ?>

            <div class="error-message" role="alert">

                Your account is temporarily locked.

                Please wait

                <span
                    id="lockoutCountdown"
                    class="lockout-countdown"
                >--:--</span>

                before trying again.

            </div>

        <?php elseif ($loginError !== ''): ?>

            <div class="error-message" role="alert">
                <?= h($loginError) ?>
            </div>

        <?php endif; ?>

        <?php if ($loginMessage !== ''): ?>

            <div class="notice" role="status">
                <?= h($loginMessage) ?>
            </div>

        <?php endif; ?>

        <form action="login.php" method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= h($_SESSION['csrf_token']) ?>"
            >

            <div class="form-group">

                <label for="username">Username</label>

                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter your username"
                    minlength="8"
                    maxlength="19"
                    autocomplete="username"
                    required
                    <?= $isLoginRestricted ? 'disabled' : '' ?>
                >

            </div>

            <div class="form-group">

                <label for="password">Password</label>

                <div class="password-wrapper">

                    <input
                        type="password"
                        id="password"
                        name="password"
                        placeholder="Enter your password"
                        minlength="11"
                        maxlength="64"
                        autocomplete="current-password"
                        required
                        <?= $isLoginRestricted ? 'disabled' : '' ?>
                    >

                    <button
                        type="button"
                        id="togglePassword"
                        class="password-toggle"
                        <?= $isLoginRestricted ? 'disabled' : '' ?>
                    >
                        Show
                    </button>

                </div>

            </div>

            <div class="form-section">

                <h3>Security Verification</h3>

                <p class="section-description">
                    Enter the six characters displayed in the image.
                </p>

                <div class="captcha-wrapper">

                    <img
                        src="captcha.php"
                        id="captchaImage"
                        alt="Security verification image"
                        width="200"
                        height="70"
                    >

                    <button
                        type="button"
                        id="refreshCaptcha"
                        class="btn-secondary"
                        <?= $isLoginRestricted ? 'disabled' : '' ?>
                    >
                        Refresh CAPTCHA
                    </button>

                </div>

                <div class="form-group">

                    <label for="captcha">CAPTCHA Code</label>

                    <input
                        type="text"
                        id="captcha"
                        name="captcha"
                        placeholder="Enter CAPTCHA code"
                        minlength="6"
                        maxlength="6"
                        pattern="[A-Za-z0-9]{6}"
                        autocomplete="off"
                        required
                        <?= $isLoginRestricted ? 'disabled' : '' ?>
                    >

                    <small>CAPTCHA codes are not case-sensitive.</small>

                </div>

            </div>

            <div class="form-actions">

                <button
                    type="submit"
                    class="btn-primary login-button"
                    <?= $isLoginRestricted ? 'disabled' : '' ?>
                >
                    Log In
                </button>

                <p
                    id="forgotPassword"
                    <?= $showForgotPassword ? '' : 'class="hidden"' ?>
                >
                    Forgot Password?
                    <a href="forgot_password.php">Reset Here</a>
                </p>

                <p>

                    Don't have an account?

                    <a
                        href="register.php"
                        class="<?= $isLockedOut ? 'disabled-link' : '' ?>"
                        <?= $isLockedOut ? 'aria-disabled="true" tabindex="-1"' : '' ?>
                    >
                        Please register here
                    </a>

                </p>

            </div>

        </form>

    </section>

</main>

<footer class="site-footer">

    &copy; 2026 Campus Counseling Appointment System.
    Academic project only.

</footer>

<script>

// Show or hide the password.
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");

if (togglePassword && passwordInput) {

    togglePassword.addEventListener("click", function () {

        const isHidden = passwordInput.type === "password";

        passwordInput.type = isHidden ? "text" : "password";

        togglePassword.textContent = isHidden ? "Hide" : "Show";

    });

}

// Refresh the CAPTCHA image.
const captchaImage = document.getElementById("captchaImage");
const refreshCaptcha = document.getElementById("refreshCaptcha");
const captchaInput = document.getElementById("captcha");

if (refreshCaptcha) {

    refreshCaptcha.addEventListener("click", function () {

        captchaImage.src = "captcha.php?refresh=" + Date.now();

        captchaInput.value = "";

    });

}

// Live countdown for account lockout or IP blocking.
const countdownElement = document.getElementById("lockoutCountdown");

if (countdownElement) {

    let remainingSeconds = <?= (int) $countdownSeconds ?>;

    function formatCountdown(seconds) {

        const minutes = Math.floor(seconds / 60);
        const remaining = seconds % 60;

        return String(minutes).padStart(2, "0") + ":" +
               String(remaining).padStart(2, "0");

    }

    countdownElement.textContent = formatCountdown(remainingSeconds);

    const countdownTimer = setInterval(function () {

        remainingSeconds--;

        if (remainingSeconds <= 0) {

            clearInterval(countdownTimer);

            countdownElement.textContent = "00:00";

            // Reload to check the actual server-side restriction again.
            window.location.reload();

            return;

        }

        countdownElement.textContent = formatCountdown(remainingSeconds);

    }, 1000);

}

</script>

</body>
</html>
