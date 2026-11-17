
<?php

// Allow execution through the command line only.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Not Found');
}

date_default_timezone_set('Asia/Manila');

require_once dirname(__DIR__) . '/app/db.php';

// Use Philippine time for database operations.
$pdo->exec("SET time_zone = '+08:00'");

// Detection thresholds.
$ipThreshold = 11;
$accountIpThreshold = 3;
$otpFailureThreshold = 5;

$eventsScanned = 0;
$detections = 0;
$newFlags = 0;
$alreadyFlagged = 0;

echo "============================================\n";
echo " CAMPUS COUNSELING SECURITY MONITOR\n";
echo "============================================\n";
echo "Time: " . date('Y-m-d H:i:s') . " (Philippine Time)\n";
echo "Scanning activity from the last 24 hours...\n\n";

try {
    // Count events from the last 24 hours.
    $stmt = $pdo->prepare(
        'SELECT COUNT(*)
         FROM activity_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );

    $stmt->execute();
    $eventsScanned = (int) $stmt->fetchColumn();

    /*
     * Save a security flag.
     * INSERT IGNORE uses the database unique constraint
     * to prevent duplicates for the same target and date.
     */
    $saveFlag = function (
        string $flagType,
        string $description,
        ?string $relatedIp
    ) use ($pdo, &$newFlags, &$alreadyFlagged): void {

        $stmt = $pdo->prepare(
            'INSERT IGNORE INTO security_flags
                (flag_type, description, related_ip, detected_date)
             VALUES (?, ?, ?, CURDATE())'
        );

        $stmt->execute([
            $flagType,
            $description,
            $relatedIp
        ]);

        if ($stmt->rowCount() === 1) {
            $newFlags++;
            echo "[NEW FLAG] {$flagType}\n";
        } else {
            $alreadyFlagged++;
            echo "[ALREADY FLAGGED] {$flagType}\n";
        }
    };

    /*
     * PATTERN 1: IP OVER THRESHOLD
     * At least 11 failed login events from one IP
     * within the last 24 hours.
     */
    $stmt = $pdo->prepare(
        'SELECT
            ip_address,
            COUNT(*) AS failure_count
         FROM activity_logs
         WHERE event_type = ?
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY ip_address
         HAVING COUNT(*) >= ?'
    );

    $stmt->execute(['LOGIN_FAILED', $ipThreshold]);

    foreach ($stmt->fetchAll() as $row) {
        $detections++;

        $ip = $row['ip_address'];
        $count = (int) $row['failure_count'];

        $flagType = 'IP_OVER_THRESHOLD:' . $ip;

        $description =
            "HIGH severity: IP address {$ip} generated {$count} "
            . "failed login events within the last 24 hours.";

        echo "[DETECTION] HIGH - IP over threshold: "
            . "{$ip} ({$count} failures)\n";

        $saveFlag($flagType, $description, $ip);
    }

    /*
     * PATTERN 2: ACCOUNT TARGETED
     * One username receives failed login attempts
     * from at least 3 different IP addresses.
     */
    $stmt = $pdo->prepare(
        'SELECT
            username_typed,
            COUNT(*) AS failure_count,
            COUNT(DISTINCT ip_address) AS different_ips
         FROM activity_logs
         WHERE event_type = ?
           AND username_typed IS NOT NULL
           AND username_typed <> ""
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY username_typed
         HAVING COUNT(DISTINCT ip_address) >= ?'
    );

    $stmt->execute(['LOGIN_FAILED', $accountIpThreshold]);

    foreach ($stmt->fetchAll() as $row) {
        $detections++;

        $username = $row['username_typed'];
        $count = (int) $row['failure_count'];
        $differentIps = (int) $row['different_ips'];

        $targetHash = substr(hash('sha256', $username), 0, 32);
        $flagType = 'ACCOUNT_TARGETED:' . $targetHash;

        $description =
            "HIGH severity: Username {$username} received {$count} "
            . "failed login attempts from {$differentIps} "
            . "different IP addresses within the last 24 hours.";

        echo "[DETECTION] HIGH - Account targeted: "
            . "{$username} ({$differentIps} different IPs)\n";

        $saveFlag($flagType, $description, null);
    }

    /*
     * PATTERN 3: OTP GUESSING
     * At least 5 OTP_FAILED events for one account
     * within the last 10 minutes.
     */
    $stmt = $pdo->prepare(
        'SELECT
            user_id,
            COUNT(*) AS failure_count
         FROM activity_logs
         WHERE event_type = ?
           AND user_id IS NOT NULL
           AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
         GROUP BY user_id
         HAVING COUNT(*) >= ?'
    );

    $stmt->execute(['OTP_FAILED', $otpFailureThreshold]);

    foreach ($stmt->fetchAll() as $row) {
        $detections++;

        $userId = $row['user_id'];
        $count = (int) $row['failure_count'];

        $targetHash = substr(hash('sha256', $userId), 0, 32);
        $flagType = 'OTP_GUESSING:' . $targetHash;

        $description =
            "HIGH severity: Account {$userId} received {$count} "
            . "failed OTP attempts within 10 minutes.";

        echo "[DETECTION] HIGH - OTP guessing: "
            . "Account {$userId} ({$count} failed attempts)\n";

        $saveFlag($flagType, $description, null);
    }

    /*
     * PATTERN 4: OFF-HOURS LOGIN
     * Successful login between 12:00 AM and 5:00 AM
     * Philippine time within the last 24 hours.
     */
    $stmt = $pdo->prepare(
        'SELECT
            user_id,
            username_typed,
            ip_address,
            created_at
         FROM activity_logs
         WHERE event_type = ?
           AND TIME(created_at) >= "00:00:00"
           AND TIME(created_at) < "05:00:00"
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         ORDER BY created_at ASC'
    );

    $stmt->execute(['LOGIN_SUCCESS']);

    foreach ($stmt->fetchAll() as $row) {
        $detections++;

        $userId = $row['user_id'];
        $username = $row['username_typed'];
        $ip = $row['ip_address'];

        $target = $userId ?: ($username ?: $ip);
        $targetHash = substr(hash('sha256', $target), 0, 32);

        $flagType = 'OFF_HOURS_LOGIN:' . $targetHash;

        $loginTime = $row['created_at'];

        $description =
            "MEDIUM severity: Successful login detected during off-hours. "
            . "Account: " . ($username ?: ($userId ?: 'Unknown'))
            . ". IP: {$ip}. Philippine time: {$loginTime}.";

        echo "[DETECTION] MEDIUM - Off-hours login: "
            . ($username ?: ($userId ?: 'Unknown'))
            . " at {$loginTime}\n";

        $saveFlag($flagType, $description, $ip);
    }

    // Monitoring summary.
    echo "\n============================================\n";
    echo " MONITORING SUMMARY\n";
    echo "============================================\n";
    echo "Events scanned:        {$eventsScanned}\n";
    echo "Detections:            {$detections}\n";
    echo "New security flags:    {$newFlags}\n";
    echo "Already flagged today: {$alreadyFlagged}\n";
    echo "============================================\n";
    echo "Monitoring completed successfully.\n";

} catch (Throwable $e) {
    error_log('Security monitoring error: ' . $e->getMessage());

    echo "\nMonitoring failed. Check the PHP error log.\n";
    exit(1);
}
