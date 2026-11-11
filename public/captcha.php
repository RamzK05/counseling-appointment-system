
<?php

// Start session.
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Prevent PHP warnings from appearing inside the image.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

try {
    $width = 200;
    $height = 70;

    $image = imagecreatetruecolor($width, $height);

    if (!$image) {
        throw new RuntimeException('Image creation failed.');
    }

    $background = imagecolorallocate($image, 245, 247, 250);
    $textColor = imagecolorallocate($image, 20, 43, 74);
    $noiseColor = imagecolorallocate($image, 170, 180, 195);
    $lineColor = imagecolorallocate($image, 190, 170, 120);

    imagefill($image, 0, 0, $background);

    $characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $captchaCode = '';

    for ($i = 0; $i < 6; $i++) {
        $captchaCode .= $characters[random_int(0, strlen($characters) - 1)];
    }

    $_SESSION['captcha_answer'] = hash('sha256', $captchaCode);

    for ($i = 0; $i < 8; $i++) {
        imageline(
            $image,
            random_int(0, $width - 1),
            random_int(0, $height - 1),
            random_int(0, $width - 1),
            random_int(0, $height - 1),
            $lineColor
        );
    }

    for ($i = 0; $i < 150; $i++) {
        imagesetpixel(
            $image,
            random_int(0, $width - 1),
            random_int(0, $height - 1),
            $noiseColor
        );
    }

    imagestring($image, 5, 35, 25, $captchaCode, $textColor);

    // Remove any buffered output before sending the PNG.
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    header('Content-Type: image/png');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');

    imagepng($image);
    exit;

} catch (Throwable $e) {
    error_log('CAPTCHA Error: ' . $e->getMessage());

    http_response_code(500);
    exit('CAPTCHA generation failed.');
}
