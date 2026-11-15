
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

                    // Credentials were accepted, but login is not complete
                    // until the email OTP has been verified.
                    $_SESSION['login_message'] = $result['message'];

                    header('Location: verify_login.php');
                    exit;

                } else {
                    $loginError = $result['message'];
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
        <a href="register.php">Register</a>
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

        <?php if ($loginError !== ''): ?>
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
                    >

                    <button
                        type="button"
                        id="togglePassword"
                        class="password-toggle"
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
                    >

                    <small>CAPTCHA codes are not case-sensitive.</small>

                </div>

            </div>

            <div class="form-actions">

                <button
                    type="submit"
                    class="btn-primary login-button"
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
                    <a href="register.php">Please register here</a>
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

    togglePassword.addEventListener("click", function () {

        const isHidden = passwordInput.type === "password";

        passwordInput.type = isHidden ? "text" : "password";

        togglePassword.textContent = isHidden ? "Hide" : "Show";

    });

    // Refresh the CAPTCHA image.
    const captchaImage = document.getElementById("captchaImage");
    const refreshCaptcha = document.getElementById("refreshCaptcha");
    const captchaInput = document.getElementById("captcha");

    refreshCaptcha.addEventListener("click", function () {

        captchaImage.src = "captcha.php?refresh=" + Date.now();

        captchaInput.value = "";

    });

</script>

</body>
</html>
