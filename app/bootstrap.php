
<?php

// Load the application configuration.
$config = require dirname(__DIR__) . '/config/config.php';

// Configure secure session cookies.
$isHttps = !empty($_SERVER['HTTPS']) &&
    $_SERVER['HTTPS'] !== 'off';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();
}

// Enforce a 5-minute idle session timeout.
$idleTimeout = 300;

if (isset($_SESSION['last_activity']) &&
    time() - $_SESSION['last_activity'] > $idleTimeout) {

    $_SESSION = [];
    session_regenerate_id(true);
}

$_SESSION['last_activity'] = time();

// Generate a CSRF token if one does not exist.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate CSRF tokens on POST requests.
function verifyCsrfToken(): bool
{
    $submittedToken = $_POST['csrf_token'] ?? '';

    return is_string($submittedToken) &&
        isset($_SESSION['csrf_token']) &&
        hash_equals($_SESSION['csrf_token'], $submittedToken);
}

// Safely escape values displayed in HTML.
function h(mixed $value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

// Load the database connection.
require_once __DIR__ . '/db.php';
