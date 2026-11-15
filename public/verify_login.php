
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';
require_once dirname(__DIR__) . '/app/authentication.php';

// A pending login must exist before this page can be accessed.
if (
    empty($_SESSION['login_pending_user_id']) ||
    empty($_SESSION['login_pending_email'])
) {
    header('Location: login.php');
    exit;
}

$pendingUserId = (string) $_SESSION['login_pending_user_id'];
$pendingEmail = (string) $_SESSION['login_pending_email'];

$error = '';
$success = false;

// Process OTP submission.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!verifyCsrfToken()) {
        http_response_code(403);
        exit('Invalid request. Please refresh the page and try again.');
    }

    $otp = trim((string) ($_POST['otp'] ?? ''));

    if (!preg_match('/^[0-9]{6}$/', $otp)) {

        $error = 'Please enter a valid 6-digit verification code.';

    } else {

        try {

            $pdo->beginTransaction();

            // Retrieve the latest unused login OTP.
            $stmt = $pdo->prepare(
                'SELECT *
                 FROM otp_records
                 WHERE user_id = ?
                 AND purpose = ?
                 AND used_at IS NULL
                 ORDER BY created_at DESC
                 LIMIT 1
                 FOR UPDATE'
            );

            $stmt->execute([
                $pendingUserId,
                'login'
            ]);

            $otpRecord = $stmt->fetch();

            if (!$otpRecord) {

                $pdo->commit();

                $error = 'Your verification code is invalid or has expired. Please log in again.';

                unset(
                    $_SESSION['login_pending_user_id'],
                    $_SESSION['login_pending_email']
                );

            } elseif (strtotime($otpRecord['expires_at']) <= time()) {

                // Expired OTPs cannot be used.
                $stmt = $pdo->prepare(
                    'UPDATE otp_records
                     SET used_at = NOW()
                     WHERE user_id = ?
                     AND purpose = ?
                     AND used_at IS NULL'
                );

                $stmt->execute([
                    $pendingUserId,
                    'login'
                ]);

                $pdo->commit();

                $error = 'Your verification code has expired. Please log in again.';

                unset(
                    $_SESSION['login_pending_user_id'],
                    $_SESSION['login_pending_email']
                );

            } elseif ((int) $otpRecord['attempts'] >= 3) {

                $stmt = $pdo->prepare(
                    'UPDATE otp_records
                     SET used_at = NOW()
                     WHERE user_id = ?
                     AND purpose = ?
                     AND used_at IS NULL'
                );

                $stmt->execute([
                    $pendingUserId,
                    'login'
                ]);

                $pdo->commit();

                $error = 'Too many incorrect attempts. Please log in again.';

                unset(
                    $_SESSION['login_pending_user_id'],
                    $_SESSION['login_pending_email']
                );

            } elseif (!password_verify($otp, $otpRecord['otp_hash'])) {

                // Count an incorrect OTP attempt.
                $newAttempts = (int) $otpRecord['attempts'] + 1;

                if ($newAttempts >= 3) {

                    $stmt = $pdo->prepare(
                        'UPDATE otp_records
                         SET attempts = attempts + 1,
                             used_at = NOW()
                         WHERE user_id = ?
                         AND purpose = ?
                         AND used_at IS NULL'
                    );

                    $stmt->execute([
                        $pendingUserId,
                        'login'
                    ]);

                } else {

                    $stmt = $pdo->prepare(
                        'UPDATE otp_records
                         SET attempts = attempts + 1
                         WHERE user_id = ?
                         AND purpose = ?
                         AND used_at IS NULL'
                    );

                    $stmt->execute([
                        $pendingUserId,
                        'login'
                    ]);
                }

                $pdo->commit();

                authenticationLog(
                    $pdo,
                    'LOGIN_OTP_FAILED',
                    null,
                    $pendingUserId,
                    'Incorrect login OTP. Attempt '
                        . $newAttempts . ' of 3'
                );

                if ($newAttempts >= 3) {

                    $error = 'You have entered an incorrect code 3 times. Please log in again.';

                    unset(
                        $_SESSION['login_pending_user_id'],
                        $_SESSION['login_pending_email']
                    );

                } else {

                    $remaining = 3 - $newAttempts;

                    $error = 'Incorrect verification code. '
                        . $remaining
                        . ' attempt(s) remaining.';
                }

            } else {

                // Correct OTP: mark it as used.
                $stmt = $pdo->prepare(
                    'UPDATE otp_records
                     SET used_at = NOW()
                     WHERE user_id = ?
                     AND purpose = ?
                     AND used_at IS NULL'
                );

                $stmt->execute([
                    $pendingUserId,
                    'login'
                ]);

                // Retrieve the account.
                $stmt = $pdo->prepare(
                    'SELECT id_number, username, email,
                            first_name, account_status, is_verified
                     FROM users
                     WHERE id_number = ?
                     LIMIT 1'
                );

                $stmt->execute([$pendingUserId]);

                $user = $stmt->fetch();

                if (
                    !$user ||
                    $user['account_status'] !== 'active' ||
                    (int) $user['is_verified'] !== 1
                ) {

                    $pdo->commit();

                    unset(
                        $_SESSION['login_pending_user_id'],
                        $_SESSION['login_pending_email']
                    );

                    $error = 'Your account could not be verified. Please log in again.';

                } else {

                    // Reset progressive lockout after completed login.
                    $stmt = $pdo->prepare(
                        'UPDATE users
                         SET failed_login_count = 0,
                             lockout_tier = 0,
                             locked_until = NULL
                         WHERE id_number = ?'
                    );

                    $stmt->execute([$pendingUserId]);

                    // Record a completed successful login.
                    authenticationRecordAttempt(
                        $pdo,
                        $user['username'],
                        $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                        true
                    );

                    authenticationLog(
                        $pdo,
                        'LOGIN_SUCCESS',
                        $user['username'],
                        $user['id_number'],
                        'Password and email OTP verified successfully'
                    );

                    $pdo->commit();

                    // Remove temporary login information.
                    unset(
                        $_SESSION['login_pending_user_id'],
                        $_SESSION['login_pending_email'],
                        $_SESSION['show_forgot_password']
                    );

                    // Regenerate the session ID after authentication.
                    session_regenerate_id(true);

                    // Create the authenticated session.
                    $_SESSION['user_id'] = $user['id_number'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_first_name'] = $user['first_name'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['last_activity'] = time();

                    // Rotate the CSRF token.
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                    // Redirect after successful login.
                    header('Location: dashboard.php');
                    exit;
                }
            }

        } catch (Throwable $e) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log(
                'Login OTP verification error: ' . $e->getMessage()
            );

            $error = 'Something went wrong. Please try again later.';
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login Verification | Campus Counseling</title>

    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<header class="site-header">
    <div class="brand">
        <div class="brand-mark">✦</div>
        <div>
            <h1>Campus Counseling</h1>
            <p>Appointment and Secure Monitoring System</p>
        </div>
    </div>
</header>

<main class="auth-container">

    <section class="auth-card">

        <h2>Email Verification</h2>

        <p>
            We sent a 6-digit verification code to your registered email:
        </p>

        <p>
            <strong><?= h($pendingEmail) ?></strong>
        </p>

        <p>
            Enter the code below to complete your login.
            The code expires in 3 minutes.
        </p>

        <?php if ($error !== ''): ?>
            <div class="alert alert-error" role="alert">
                <?= h($error) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="verify_login.php">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= h($_SESSION['csrf_token']) ?>"
            >

            <div class="form-group">
                <label for="otp">6-Digit Verification Code</label>

                <input
                    type="text"
                    id="otp"
                    name="otp"
                    inputmode="numeric"
                    pattern="[0-9]{6}"
                    maxlength="6"
                    minlength="6"
                    autocomplete="one-time-code"
                    placeholder="Enter your 6-digit code"
                    required
                    autofocus
                >
            </div>

            <button type="submit" class="btn btn-primary">
                Verify and Log In
            </button>

        </form>

        <p class="auth-footer">
            Didn't receive a code?
            <a href="login.php">Return to login</a>
        </p>

    </section>

</main>

</body>
</html>
