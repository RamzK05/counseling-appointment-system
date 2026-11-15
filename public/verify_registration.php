
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';
require_once dirname(__DIR__) . '/app/registration.php';

$message = '';
$success = false;

$pendingUserId = $_SESSION['registration_pending_user_id'] ?? '';

if (!is_string($pendingUserId) || $pendingUserId === '') {
    $message = 'There is no pending registration to verify. Please register first.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $pendingUserId !== '') {

    if (!verifyCsrfToken()) {
        $message = 'Your session has expired. Please refresh the page.';
    } else {

        $otp = trim((string)($_POST['otp'] ?? ''));

        if (!preg_match('/^\d{6}$/', $otp)) {
            $message = 'Please enter a valid six-digit verification code.';
        } else {

            try {
                $pdo->beginTransaction();

                $stmt = $pdo->prepare(
                    'SELECT id, otp_hash, expires_at, attempts
                     FROM otp_records
                     WHERE user_id = ?
                       AND purpose = "registration"
                       AND used_at IS NULL
                     ORDER BY created_at DESC
                     LIMIT 1
                     FOR UPDATE'
                );

                $stmt->execute([$pendingUserId]);
                $otpRecord = $stmt->fetch();

                if (!$otpRecord) {
                    $pdo->commit();
                    $message = 'No active verification code was found. Please contact the system administrator.';
                } elseif ((int)$otpRecord['attempts'] >= 3) {
                    $pdo->prepare(
                        'UPDATE otp_records
                         SET used_at = NOW()
                         WHERE id = ?'
                    )->execute([$otpRecord['id']]);

                    $pdo->commit();
                    $message = 'The verification code has been cancelled after three incorrect attempts. Please contact the system administrator.';
                } elseif (strtotime($otpRecord['expires_at']) <= time()) {

                    $pdo->prepare(
                        'UPDATE otp_records
                         SET used_at = NOW()
                         WHERE id = ?'
                    )->execute([$otpRecord['id']]);

                    $pdo->commit();
                    $message = 'Your verification code has expired. Please contact the system administrator.';
                } elseif (!password_verify($otp, $otpRecord['otp_hash'])) {

                    $newAttempts = (int)$otpRecord['attempts'] + 1;

                    $update = $pdo->prepare(
                        'UPDATE otp_records
                         SET attempts = ?,
                             used_at = CASE WHEN ? >= 3 THEN NOW() ELSE used_at END
                         WHERE id = ?'
                    );

                    $update->execute([
                        $newAttempts,
                        $newAttempts,
                        $otpRecord['id']
                    ]);

                    registrationLog(
                        $pdo,
                        'OTP_FAILED',
                        null,
                        $pendingUserId,
                        'Incorrect registration OTP attempt.'
                    );

                    $pdo->commit();

                    if ($newAttempts >= 3) {
                        $message = 'The verification code has been cancelled after three incorrect attempts. Please contact the system administrator.';
                    } else {
                        $remaining = 3 - $newAttempts;
                        $message = 'Incorrect verification code. You have ' . $remaining . ' attempt(s) remaining.';
                    }

                } else {

                    $userUpdate = $pdo->prepare(
                        'UPDATE users
                         SET account_status = "active",
                             is_verified = 1,
                             updated_at = NOW()
                         WHERE id_number = ?
                           AND account_status = "pending"
                           AND is_verified = 0'
                    );

                    $userUpdate->execute([$pendingUserId]);

                    if ($userUpdate->rowCount() !== 1) {
                        throw new RuntimeException('Pending account could not be activated.');
                    }

                    $otpUpdate = $pdo->prepare(
                        'UPDATE otp_records
                         SET used_at = NOW()
                         WHERE id = ?'
                    );

                    $otpUpdate->execute([$otpRecord['id']]);

                    registrationLog(
                        $pdo,
                        'REGISTRATION_VERIFIED',
                        null,
                        $pendingUserId,
                        'Registration email OTP successfully verified.'
                    );

                    $pdo->commit();

                    unset(
                        $_SESSION['registration_pending_user_id'],
                        $_SESSION['registration_pending_email']
                    );

                    session_regenerate_id(true);

                    $success = true;
                    $message = 'Your email has been verified and your account is now active. You may log in.';
                }

            } catch (Throwable $e) {

                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Registration OTP verification error: ' . $e->getMessage());

                $message = 'Verification could not be completed. Please try again later.';
            }
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification | Campus Counseling</title>
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
        <a href="login.html">Log-in</a>
    </nav>
</header>

<main class="page-container">

    <section class="form-heading">
        <span class="eyebrow">ACCOUNT SECURITY</span>
        <h2>Email Verification</h2>
        <p>Enter the six-digit code sent to your registered email address.</p>
    </section>

    <form class="registration-card" method="POST" action="verify_registration.php">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= h($_SESSION['csrf_token']) ?>"
        >

        <?php if ($message !== ''): ?>
            <div class="notice" role="status">
                <?= h($message) ?>
            </div>
        <?php endif; ?>

        <?php if (!$success && $pendingUserId !== ''): ?>

            <div class="form-section">
                <div class="form-group">
                    <label for="otp">Six-Digit Verification Code *</label>

                    <input
                        type="text"
                        id="otp"
                        name="otp"
                        inputmode="numeric"
                        pattern="[0-9]{6}"
                        minlength="6"
                        maxlength="6"
                        placeholder="Enter your OTP"
                        autocomplete="one-time-code"
                        required
                    >

                    <small>
                        Your verification code expires after three minutes.
                        You have a maximum of three incorrect attempts.
                    </small>
                </div>
            </div>

            <div class="form-actions">
                <button type="submit" class="btn-primary">
                    Verify Email
                </button>
            </div>

        <?php elseif ($success): ?>

            <div class="form-actions">
                <a href="login.html" class="btn-primary">
                    Proceed to Log-in
                </a>
            </div>

        <?php endif; ?>

    </form>

</main>

<footer class="site-footer">
    <p>© 2026 Campus Counseling Appointment and Secure Monitoring System.</p>
</footer>

</body>
</html>
