<?php
// Copy this file to config.php and fill in REAL values.
// config.php is listed in .gitignore and must NEVER be committed.
// This sample file (fake values only) IS committed.
return [
    'db' => [
        'host' => 'localhost',
        'name' => 'counseling_db',
        'user' => 'root',
        'pass' => 'CHANGE_ME',
    ],
    'smtp' => [
        'host' => 'smtp.gmail.com',   // or 127.0.0.1 for Mailpit
        'port' => 587,                // Mailpit: 1025
        'user' => 'your-email@gmail.com',
        'pass' => 'YOUR_GMAIL_APP_PASSWORD',
        'from' => 'your-email@gmail.com',
        'from_name' => 'Campus Counseling Appointment System',
    ],
    'captcha' => [
        'site_key'   => 'FAKE_SITE_KEY',
        'secret_key' => 'FAKE_SECRET_KEY',
    ],
    'encryption_key' => 'CHANGE_ME_32_BYTE_RANDOM_KEY_HEX',
];
