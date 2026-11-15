
<?php

/**
 * Authentication helper functions.
 * Campus Counseling Appointment and Secure Monitoring System
 *
 * IT 107 Student Handout:
 * - Secure login
 * - Progressive account lockout
 * - IP blocking
 * - Email OTP verification
 * - Activity logging
 */

function authenticationLog(
    PDO $pdo,
    string $event,
    ?string $username,
    ?string $userId = null,
    ?string $details = null
): void {
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO activity_logs
            (event_type, username_typed, user_id, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $event,
            $username,
            $userId,
            $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            $_SERVER['HTTP_USER_AGENT'] ?? null,
            $details
        ]);

    } catch (Throwable $e) {
        error_log(
            'Authentication logging failed: ' . $e->getMessage()
        );
    }
}


/**
 * Check whether an IP address is currently blocked.
 */
function authenticationIsIpBlocked(
    PDO $pdo,
    string $ip
): bool {

    $stmt = $pdo->prepare(
        'SELECT id
         FROM ip_blocks
         WHERE ip_address = ?
         AND blocked_until > NOW()
         LIMIT 1'
    );

    $stmt->execute([$ip]);

    return (bool) $stmt->fetchColumn();
}


/**
 * Record a login attempt.
 */
function authenticationRecordAttempt(
    PDO $pdo,
    string $username,
    string $ip,
    bool $successful
): void {

    $stmt = $pdo->prepare(
        'INSERT INTO login_attempts
        (username_typed, ip_address, successful, attempted_at)
        VALUES (?, ?, ?, NOW())'
    );

    $stmt->execute([
        $username,
        $ip,
        $successful ? 1 : 0
    ]);
}


/**
 * Block an IP after 11 failed attempts within 10 minutes.
 */
function authenticationCheckIpThreshold(
    PDO $pdo,
    string $ip
): void {

    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
         FROM login_attempts
         WHERE ip_address = ?
         AND successful = 0
         AND attempted_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)'
    );

    $stmt->execute([$ip]);

    $failures = (int) $stmt->fetchColumn();

    if ($failures >= 11) {

        $stmt = $pdo->prepare(
            'INSERT INTO ip_blocks
            (ip_address, reason, blocked_at, blocked_until)
            VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 15 MINUTE))
            ON DUPLICATE KEY UPDATE
                reason = VALUES(reason),
                blocked_at = NOW(),
                blocked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE)'
        );

        $stmt->execute([
            $ip,
            'Repeated failed login attempts'
        ]);

        authenticationLog(
            $pdo,
            'IP_BLOCKED',
            null,
            null,
            'IP address blocked after 11 failed attempts'
        );
    }
}


/**
 * Send a login OTP through PHPMailer.
 *
 * OTP:
 * - Six digits
 * - Secure random generation
 * - Hashed before database storage
 * - Expires after 3 minutes
 * - Previous unused login OTP is invalidated
 */
function authenticationSendLoginOtp(
    PDO $pdo,
    array $config,
    array $user
): bool {

    $otp = (string) random_int(100000, 999999);

    $otpHash = password_hash(
        $otp,
        PASSWORD_DEFAULT
    );

    // Save the OTP in the database.
    $pdo->beginTransaction();

    try {

        // Invalidate previous unused login OTPs.
        $stmt = $pdo->prepare(
            'UPDATE otp_records
             SET used_at = NOW()
             WHERE user_id = ?
             AND purpose = ?
             AND used_at IS NULL'
        );

        $stmt->execute([
            $user['id_number'],
            'login'
        ]);

        // Create the new OTP.
        $stmt = $pdo->prepare(
            'INSERT INTO otp_records
            (user_id, purpose, otp_hash, expires_at, attempts, created_at)
            VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 3 MINUTE), 0, NOW())'
        );

        $stmt->execute([
            $user['id_number'],
            'login',
            $otpHash
        ]);

        $otpRecordId = (int) $pdo->lastInsertId();

        $pdo->commit();

    } catch (Throwable $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log(
            'Login OTP database error: ' . $e->getMessage()
        );

        return false;
    }

    // Send the OTP email.
    try {

        require_once dirname(__DIR__) . '/vendor/autoload.php';

        $smtp = $config['smtp'];

        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        $mail->isSMTP();

        $mail->Host = $smtp['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $smtp['user'];
        $mail->Password = $smtp['pass'];
        $mail->Port = (int) $smtp['port'];

        $mail->SMTPSecure =
            PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;

        $mail->setFrom(
            $smtp['from'],
            $smtp['from_name']
        );

        $mail->addAddress(
            $user['email'],
            $user['first_name']
        );

        $mail->isHTML(true);

        $mail->Subject = 'Your Campus Counseling log-in code';

        $safeName = htmlspecialchars(
            $user['first_name'],
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        $safeOtp = htmlspecialchars(
            $otp,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        $mail->Body = "
            <h2>Campus Counseling Login Verification</h2>

            <p>Hello {$safeName},</p>

            <p>Your log-in verification code is:</p>

            <h1 style='letter-spacing: 6px;'>{$safeOtp}</h1>

            <p>This code expires in 3 minutes.</p>

            <p>
                If you did not request this code, ignore this email
                and consider changing your password.
            </p>
        ";

        $mail->AltBody =
            "Your Campus Counseling log-in code is: {$otp}. "
            . "This code expires in 3 minutes. "
            . "If you did not request this code, ignore this email "
            . "and consider changing your password.";

        $mail->send();

        return true;

    } catch (Throwable $e) {

        error_log(
            'Login OTP email failed: ' . $e->getMessage()
        );

        // Invalidate the OTP if the email could not be sent.
        try {

            $stmt = $pdo->prepare(
                'UPDATE otp_records
                 SET used_at = NOW()
                 WHERE id = ?
                 AND used_at IS NULL'
            );

            $stmt->execute([$otpRecordId]);

        } catch (Throwable $databaseError) {

            error_log(
                'Failed to invalidate unsent OTP: '
                . $databaseError->getMessage()
            );
        }

        return false;
    }
}


/**
 * Process a student login attempt.
 *
 * The account is NOT authenticated until the login OTP
 * has been successfully verified.
 */
function authenticateStudent(
    PDO $pdo,
    array $config,
    string $username,
    string $password
): array {

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // 1. Check IP blocking first.
    if (authenticationIsIpBlocked($pdo, $ip)) {

        authenticationLog(
            $pdo,
            'IP_BLOCKED',
            $username,
            null,
            'Login attempt from blocked IP address'
        );

        return [
            'success' => false,
            'message' => 'Too many attempts. Please try again later.'
        ];
    }

    // 2. Retrieve the account.
    $stmt = $pdo->prepare(
        'SELECT *
         FROM users
         WHERE username = ?
         LIMIT 1'
    );

    $stmt->execute([$username]);

    $user = $stmt->fetch();

    // 3. Unknown usernames receive the same generic response.
    if (!$user) {

        authenticationRecordAttempt(
            $pdo,
            $username,
            $ip,
            false
        );

        authenticationCheckIpThreshold($pdo, $ip);

        authenticationLog(
            $pdo,
            'LOGIN_FAILED',
            $username,
            null,
            'Invalid login credentials'
        );

        return [
            'success' => false,
            'message' => 'Invalid username or password.'
        ];
    }

    // 4. Check account lockout BEFORE password verification.
    if (!empty($user['locked_until'])) {

        $stmt = $pdo->prepare(
            'SELECT GREATEST(
                0,
                TIMESTAMPDIFF(SECOND, NOW(), locked_until)
            )
            FROM users
            WHERE id_number = ?'
        );

        $stmt->execute([$user['id_number']]);

        $remaining = (int) $stmt->fetchColumn();

        if ($remaining > 0) {

            authenticationLog(
                $pdo,
                'LOGIN_LOCKED',
                $username,
                $user['id_number'],
                'Login attempted while account was locked'
            );

            return [
                'success' => false,
                'message' => 'Your account is temporarily locked. Please wait '
                    . $remaining . ' seconds.'
            ];
        }
    }

    // 5. Verify the password.
    if (!password_verify($password, $user['password_hash'])) {

        authenticationRecordAttempt(
            $pdo,
            $username,
            $ip,
            false
        );

        // Increment the consecutive failure counter atomically.
        $stmt = $pdo->prepare(
            'UPDATE users
             SET failed_login_count = failed_login_count + 1
             WHERE id_number = ?'
        );

        $stmt->execute([$user['id_number']]);

        // Get the updated failure count.
        $stmt = $pdo->prepare(
            'SELECT failed_login_count, lockout_tier
             FROM users
             WHERE id_number = ?'
        );

        $stmt->execute([$user['id_number']]);

        $updatedUser = $stmt->fetch();

        $failedCount = (int) $updatedUser['failed_login_count'];

        // 6. Show Forgot Password after 3 consecutive failures.
        if ($failedCount >= 3) {
            $_SESSION['show_forgot_password'] = true;
        }

        // 7. Apply progressive lockout at failures 3, 6 and 9.
        $lockoutDurations = [
            1 => 20,
            2 => 40,
            3 => 80
        ];

        if (
            $failedCount >= 3 &&
            $failedCount % 3 === 0
        ) {

            $newTier = min(
                intdiv($failedCount, 3),
                3
            );

            $lockoutSeconds = $lockoutDurations[$newTier];

            $stmt = $pdo->prepare(
                'UPDATE users
                 SET lockout_tier = ?,
                     locked_until = DATE_ADD(
                         NOW(),
                         INTERVAL ? SECOND
                     )
                 WHERE id_number = ?'
            );

            $stmt->execute([
                $newTier,
                $lockoutSeconds,
                $user['id_number']
            ]);

            authenticationLog(
                $pdo,
                'LOGIN_LOCKOUT',
                $username,
                $user['id_number'],
                'Lockout tier ' . $newTier
                    . ' activated for '
                    . $lockoutSeconds
                    . ' seconds'
            );
        }

        // 8. Check IP threshold.
        authenticationCheckIpThreshold($pdo, $ip);

        authenticationLog(
            $pdo,
            'LOGIN_FAILED',
            $username,
            $user['id_number'],
            'Invalid login credentials'
        );

        return [
            'success' => false,
            'message' => 'Invalid username or password.'
        ];
    }

    // 9. Reject inactive or unverified accounts.
    if (
        $user['account_status'] !== 'active' ||
        (int) $user['is_verified'] !== 1
    ) {

        authenticationLog(
            $pdo,
            'LOGIN_REJECTED',
            $username,
            $user['id_number'],
            'Account inactive or not verified'
        );

        return [
            'success' => false,
            'message' => 'Invalid username or password.'
        ];
    }

    // 10. Send the login OTP.
    // No authenticated session is created at this stage.
    if (!authenticationSendLoginOtp($pdo, $config, $user)) {

        authenticationLog(
            $pdo,
            'LOGIN_OTP_SEND_FAILED',
            $username,
            $user['id_number'],
            'Could not send login OTP'
        );

        return [
            'success' => false,
            'message' => 'Unable to send your verification code. Please try again later.'
        ];
    }

    // 11. Store temporary login information.
    $_SESSION['login_pending_user_id'] = $user['id_number'];
    $_SESSION['login_pending_email'] = $user['email'];

    authenticationLog(
        $pdo,
        'LOGIN_OTP_SENT',
        $username,
        $user['id_number'],
        'Login OTP sent successfully'
    );

    return [
        'success' => true,
        'message' => 'Verification code sent to your registered email.'
    ];
}