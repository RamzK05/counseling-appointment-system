
<?php

// Load database configuration.
$config = require dirname(__DIR__) . '/config/config.php';

// Create the database connection.
$dsn = sprintf(
    'mysql:host=%s;dbname=%s;charset=utf8mb4',
    $config['db']['host'],
    $config['db']['name']
);

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO(
        $dsn,
        $config['db']['user'],
        $config['db']['pass'],
        $options
    );
} catch (PDOException $e) {
    error_log('Database connection failed: ' . $e->getMessage());

    http_response_code(500);
    exit('A database connection error occurred. Please try again later.');
}
