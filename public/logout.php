
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';

// Logout must be submitted through POST.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

// Verify CSRF token.
if (!verifyCsrfToken()) {
    http_response_code(403);
    exit('Invalid request. Please refresh the page and try again.');
}

// Clear all session data.
$_SESSION = [];

// Remove the session cookie.
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();

    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params['path'],
        'domain' => $params['domain'],
        'secure' => $params['secure'],
        'httponly' => $params['httponly'],
        'samesite' => $params['samesite'] ?? 'Strict',
    ]);
}

// Destroy the session.
session_destroy();

// Return to the login page.
header('Location: login.php?logged_out=1');
exit;
