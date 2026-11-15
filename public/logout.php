
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';

// If the session has already expired, finish clearing it.
if (
    empty($_SESSION['logged_in']) ||
    empty($_SESSION['user_id'])
) {
    $_SESSION = [];

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

    session_destroy();

    header('Location: login.php?session_expired=1');
    exit;
}

// Logout must use POST.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

// Verify CSRF token for an active session.
if (!verifyCsrfToken()) {
    http_response_code(403);
    exit('Invalid request. Please refresh the page and try again.');
}

// Clear session data.
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

header('Location: login.php?logged_out=1');
exit;
