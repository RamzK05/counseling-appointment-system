
<?php

/**
 * Campus Counseling
 * Secure student registration handler.
 */

function registrationLog(
    PDO $pdo,
    string $event,
    ?string $username,
    ?string $userId,
    string $details = ''
): void {
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO activity_logs
                (event_type, username_typed, user_id, ip_address, user_agent, details)
             VALUES
                (?, ?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $event,
            $username,
            $userId,
            $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 1000),
            $details
        ]);
    } catch (Throwable $e) {
        error_log('Registration activity log failed: ' . $e->getMessage());
    }
}

function registrationLength(string $value): int
{
    preg_match_all('/./us', $value, $matches);
    return count($matches[0]);
}

function validateRegistration(array $data): array
{
    $errors = [];

    $id = trim((string)($data['id_number'] ?? ''));
    $course = trim((string)($data['course'] ?? ''));
    $year = trim((string)($data['year_level'] ?? ''));

    $first = trim((string)($data['first_name'] ?? ''));
    $middle = trim((string)($data['middle_name'] ?? ''));
    $family = trim((string)($data['family_name'] ?? ''));

    $extension = trim((string)($data['extension'] ?? ''));
    $otherExtension = trim((string)($data['other_extension'] ?? ''));

    $birthdate = trim((string)($data['birthdate'] ?? ''));

    $street = trim((string)($data['street'] ?? ''));
    $barangay = trim((string)($data['barangay'] ?? ''));
    $municipality = trim((string)($data['municipality'] ?? ''));
    $province = trim((string)($data['province'] ?? ''));
    $country = trim((string)($data['country'] ?? ''));
    $zip = trim((string)($data['zip_code'] ?? ''));

    $email = strtolower(trim((string)($data['email'] ?? '')));
    $username = trim((string)($data['username'] ?? ''));

    $password = (string)($data['password'] ?? '');
    $confirmation = (string)($data['confirm_password'] ?? '');

    $questionCodes = [
        (string)($data['question_1'] ?? ''),
        (string)($data['question_2'] ?? ''),
        (string)($data['question_3'] ?? '')
    ];

    $answers = [
        trim((string)($data['answer_1'] ?? '')),
        trim((string)($data['answer_2'] ?? '')),
        trim((string)($data['answer_3'] ?? ''))
    ];

    $concern = trim((string)($data['concern_category'] ?? ''));
    $schedule = trim((string)($data['preferred_schedule'] ?? ''));
    $guardian = trim((string)($data['guardian_contact'] ?? ''));
    $notes = trim((string)($data['notes'] ?? ''));

    // Student ID.
    if (!preg_match('/^\d{4}-\d{4}$/', $id)) {
        $errors['id_number'] = 'ID Number must follow the format xxxx-xxxx.';
    }

    // Server-side dropdown validation.
    if ($course !== 'BSIT') {
        $errors['course'] = 'Please select a valid course.';
    }

    if (!in_array($year, [
        '1st Year', '2nd Year', '3rd Year', '4th Year'
    ], true)) {
        $errors['year_level'] = 'Please select a valid year level.';
    }

    // Name validation.
    $validateName = function (
        string $value,
        string $field,
        string $label,
        bool $required
    ) use (&$errors): void {
        if ($value === '' && !$required) {
            return;
        }

        if ($value === '') {
            $errors[$field] = $label . ' is required.';
            return;
        }

        if (registrationLength($value) < 2 || registrationLength($value) > 23) {
            $errors[$field] = $label . ' must be between 2 and 23 characters.';
            return;
        }

        if (preg_match('/\d/u', $value)) {
            $errors[$field] = 'Numbers are not allowed in ' . $label . '.';
            return;
        }

        if (preg_match('/[^\p{L} ]/u', $value)) {
            $errors[$field] = 'Special characters are not allowed in ' . $label . '.';
            return;
        }

        if (str_contains($value, '  ')) {
            $errors[$field] = 'Double space is not allowed.';
            return;
        }

        if (preg_match('/(\p{L})\1\1/iu', $value)) {
            $errors[$field] = 'Three consecutive identical letters are not allowed.';
            return;
        }

        if (preg_match('/^\p{Lu}+$/u', $value)) {
            $errors[$field] = 'Do not use all capital letters.';
            return;
        }

        if (!preg_match('/^\p{Lu}/u', $value)) {
            $errors[$field] = 'First letter of your name must be capital.';
            return;
        }

        if (!preg_match('/^\p{Lu}\p{Ll}+(?: \p{Lu}\p{Ll}+)*$/u', $value)) {
            $errors[$field] = $label . ' must use proper title case.';
        }
    };

    $validateName($first, 'first_name', 'First Name', true);
    $validateName($middle, 'middle_name', 'Middle Name', false);
    $validateName($family, 'family_name', 'Family Name', true);

    // Name extension.
    if (!in_array($extension, ['', 'Jr.', 'Sr.', 'Other'], true)) {
        $errors['extension'] = 'Please select a valid name extension.';
    }

    $finalExtension = $extension;

    if ($extension === 'Other') {
        if (!in_array($otherExtension, ['I', 'II', 'III', 'IV', 'IX', 'X'], true)) {
            $errors['other_extension'] = 'Please enter a valid extension: I, II, III, IV, IX, or X.';
        } else {
            $finalExtension = $otherExtension;
        }
    }

    // Birthdate and age.
    $birth = DateTime::createFromFormat('!Y-m-d', $birthdate);
    $today = new DateTime('today');

    if (!$birth || $birth->format('Y-m-d') !== $birthdate) {
        $errors['birthdate'] = 'Please enter a valid birthdate.';
    } elseif ($birth > $today) {
        $errors['birthdate'] = 'Birthdate cannot be in the future.';
    } elseif ($birth->diff($today)->y < 18) {
        $errors['birthdate'] = 'You must be at least 18 years old to register.';
    }

    // Address.
    $addressFields = [
        'street' => [$street, 3, 50, 'Purok / Street'],
        'barangay' => [$barangay, 2, 50, 'Barangay'],
        'municipality' => [$municipality, 2, 50, 'Municipality / City'],
        'province' => [$province, 2, 50, 'Province'],
        'country' => [$country, 2, 50, 'Country']
    ];

    foreach ($addressFields as $field => [$value, $min, $max, $label]) {
        $length = registrationLength($value);

        if ($length < $min || $length > $max) {
            $errors[$field] = $label . " must be between {$min} and {$max} characters.";
        }
    }

    if (!preg_match('/^\d{4}$/', $zip)) {
        $errors['zip_code'] = 'ZIP Code must contain exactly 4 digits.';
    }

    // Email and username.
    if (
        strlen($email) > 100 ||
        preg_match('/\s/', $email) ||
        !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
        $errors['email'] = 'Please enter a valid email address.';
    }

    if (!preg_match('/^[A-Za-z][A-Za-z0-9]{7,18}$/', $username)) {
        $errors['username'] = 'Username must be 8–19 characters, start with a letter, and contain only letters and numbers.';
    }

    // Password.
    if (strlen($password) < 11 || strlen($password) > 64) {
        $errors['password'] = 'Password must be between 11 and 64 characters.';
    } else {
        $score = 0;

        if (preg_match('/[a-z]/', $password) && preg_match('/[A-Z]/', $password)) {
            $score++;
        }

        if (preg_match('/[0-9]/', $password)) {
            $score++;
        }

        if (preg_match('/[^A-Za-z0-9]/', $password)) {
            $score++;
        }

        if ($score < 2) {
            $errors['password'] = 'Password strength is Weak. Use a stronger password.';
        }
    }

    if ($password !== $confirmation) {
        $errors['confirm_password'] = 'Passwords do not match.';
    }

    // Authentication questions.
    if ($questionCodes !== ['Q4', 'Q7', 'Q1']) {
        $errors['answers'] = 'Invalid authentication question selection.';
    }

    foreach ($answers as $index => $answer) {
        if (
            registrationLength($answer) < 2 ||
            registrationLength($answer) > 50 ||
            !preg_match('/^\p{L}+(?: \p{L}+)*$/u', $answer)
        ) {
            $errors['answer_' . ($index + 1)] =
                'Answer must contain 2–50 letters and single spaces only.';
        }
    }

    // Appointment information.
    $validConcerns = [
        'Academic Concerns',
        'Personal Concerns',
        'Family Concerns',
        'Relationship Concerns',
        'Emotional and Stress Concerns',
        'Career and Future Planning',
        'Other Concerns'
    ];

    if (!in_array($concern, $validConcerns, true)) {
        $errors['concern_category'] = 'Please select a valid concern category.';
    }

    $appointmentDate = DateTime::createFromFormat('!Y-m-d', $schedule);

    if (
        !$appointmentDate ||
        $appointmentDate->format('Y-m-d') !== $schedule ||
        $appointmentDate < $today
    ) {
        $errors['preferred_schedule'] = 'Please select a valid appointment date that is today or later.';
    }

    if (!preg_match('/^09\d{9}$/', $guardian)) {
        $errors['guardian_contact'] = 'Guardian contact must be an 11-digit mobile number beginning with 09.';
    }

    if (registrationLength($notes) > 2000) {
        $errors['notes'] = 'Notes cannot exceed 2000 characters.';
    }

    if (($_POST['privacy_consent'] ?? '') !== '1') {
        $errors['privacy_consent'] =
            'You must agree to the Privacy Notice to register.';
    }

    return [
        'errors' => $errors,
        'values' => [
            'id_number' => $id,
            'course' => $course,
            'year_level' => $year,
            'first_name' => $first,
            'middle_name' => $middle,
            'family_name' => $family,
            'name_extension' => $finalExtension,
            'birthdate' => $birthdate,
            'street' => $street,
            'barangay' => $barangay,
            'municipality' => $municipality,
            'province' => $province,
            'country' => $country,
            'zip_code' => $zip,
            'email' => $email,
            'username' => $username,
            'password' => $password,
            'answers' => $answers,
            'question_codes' => $questionCodes,
            'concern_category' => $concern,
            'preferred_schedule' => $schedule,
            'guardian_contact' => $guardian,
            'notes' => $notes
        ]
    ];
}

function createStudentRegistration(
    PDO $pdo,
    array $config,
    array $data
): array {
    $validation = validateRegistration($data);

    if ($validation['errors']) {
        return [
            'success' => false,
            'errors' => $validation['errors']
        ];
    }

    $v = $validation['values'];

    // Check for existing student ID, email, or username.
    $check = $pdo->prepare(
        'SELECT id_number, email, username
         FROM users
         WHERE id_number = ? OR email = ? OR username = ?
         LIMIT 1'
    );

    $check->execute([
        $v['id_number'],
        $v['email'],
        $v['username']
    ]);

    $existing = $check->fetch();

    if ($existing) {
        $errors = [];

        if ($existing['id_number'] === $v['id_number']) {
            $errors['id_number'] = 'This ID Number is already registered.';
        }

        if ($existing['email'] === $v['email']) {
            $errors['email'] = 'This email address is already registered.';
        }

        if ($existing['username'] === $v['username']) {
            $errors['username'] = 'This username is already taken.';
        }

        return ['success' => false, 'errors' => $errors];
    }

    // Encrypt appointment notes using AES-256-GCM.
    $encryptedNotes = null;
    $notesIv = null;
    $notesTag = null;

    if ($v['notes'] !== '') {
        $keyHex = $config['encryption_key'] ?? '';

        if (!is_string($keyHex) || !preg_match('/^[a-fA-F0-9]{64}$/', $keyHex)) {
            error_log('Registration failed: encryption key is invalid.');
            return [
                'success' => false,
                'errors' => ['general' => 'Registration could not be completed. Please contact the system administrator.']
            ];
        }

        $key = hex2bin($keyHex);
        $notesIv = random_bytes(12);

        $encryptedNotes = openssl_encrypt(
            $v['notes'],
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $notesIv,
            $notesTag
        );

        if ($encryptedNotes === false) {
            return [
                'success' => false,
                'errors' => ['general' => 'Registration could not be completed. Please try again.']
            ];
        }
    }

    // Generate a six-digit registration OTP.
    $otp = (string) random_int(100000, 999999);
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    $mailSent = false;

    try {
        $pdo->beginTransaction();

        $userInsert = $pdo->prepare(
            'INSERT INTO users (
                id_number, first_name, middle_name, family_name,
                name_extension, birthdate, purok_street, barangay,
                municipality_city, province, country, zip_code,
                email, username, password_hash, student_course,
                year_level, role, account_status, is_verified,
                consent_at, consent_version
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, "student", "pending", 0, NOW(), "1.0"
            )'
        );

        $userInsert->execute([
            $v['id_number'],
            $v['first_name'],
            $v['middle_name'] !== '' ? $v['middle_name'] : null,
            $v['family_name'],
            $v['name_extension'] !== '' ? $v['name_extension'] : null,
            $v['birthdate'],
            $v['street'],
            $v['barangay'],
            $v['municipality'],
            $v['province'],
            $v['country'],
            $v['zip_code'],
            $v['email'],
            $v['username'],
            password_hash($v['password'], PASSWORD_DEFAULT),
            $v['course'],
            $v['year_level']
        ]);

        // Save the three hashed security answers.
        $answerInsert = $pdo->prepare(
            'INSERT INTO auth_answers (user_id, question_code, answer_hash)
             VALUES (?, ?, ?)'
        );

        foreach ($v['answers'] as $index => $answer) {
            $answerInsert->execute([
                $v['id_number'],
                $v['question_codes'][$index],
                password_hash(mb_strtolower($answer, 'UTF-8'), PASSWORD_DEFAULT)
            ]);
        }

        // Save the appointment request.
        $appointmentInsert = $pdo->prepare(
            'INSERT INTO appointments (
                student_id, concern_category, preferred_schedule,
                guardian_contact, notes_encrypted, notes_iv, notes_tag
            ) VALUES (?, ?, ?, ?, ?, ?, ?)'
        );

        $appointmentInsert->execute([
            $v['id_number'],
            $v['concern_category'],
            $v['preferred_schedule'],
            $v['guardian_contact'],
            $encryptedNotes,
            $notesIv,
            $notesTag
        ]);

        // Save the hashed OTP. It expires after 3 minutes.
        $otpInsert = $pdo->prepare(
            'INSERT INTO otp_records (
                user_id, purpose, otp_hash, expires_at, attempts
            ) VALUES (?, "registration", ?, DATE_ADD(NOW(), INTERVAL 3 MINUTE), 0)'
        );

        $otpInsert->execute([
            $v['id_number'],
            $otpHash
        ]);

        // Send the OTP email.
        require_once dirname(__DIR__) . '/vendor/autoload.php';

        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        $smtp = $config['smtp'];

        $mail->isSMTP();
        $mail->Host = $smtp['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $smtp['user'];
        $mail->Password = $smtp['pass'];
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = (int) $smtp['port'];

        $mail->setFrom($smtp['from'], $smtp['from_name']);
        $mail->addAddress($v['email'], $v['first_name']);
        $mail->isHTML(true);
        $mail->Subject = 'Campus Counseling - Registration Verification Code';

        $mail->Body =
            '<p>Hello ' . htmlspecialchars($v['first_name'], ENT_QUOTES, 'UTF-8') . ',</p>' .
            '<p>Your registration verification code is:</p>' .
            '<h2 style="letter-spacing:5px;">' . htmlspecialchars($otp, ENT_QUOTES, 'UTF-8') . '</h2>' .
            '<p>This code expires in <strong>3 minutes</strong>.</p>' .
            '<p>If you did not request this registration, you may ignore this email.</p>';

        $mail->AltBody =
            "Your Campus Counseling registration verification code is {$otp}. It expires in 3 minutes.";

        $mail->send();
        $mailSent = true;

        registrationLog(
            $pdo,
            'REGISTRATION_PENDING',
            $v['username'],
            $v['id_number'],
            'Student registration submitted; email verification required.'
        );

        $pdo->commit();

        $_SESSION['registration_pending_user_id'] = $v['id_number'];
        $_SESSION['registration_pending_email'] = $v['email'];

        return [
            'success' => true,
            'message' => 'Your registration was received. A verification code has been sent to your email address.'
        ];

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('Student registration error: ' . $e->getMessage());

        if ($e instanceof PDOException && $e->getCode() === '23000') {
            return [
                'success' => false,
                'errors' => [
                    'general' => 'The ID Number, email address, or username is already registered.'
                ]
            ];
        }

        return [
            'success' => false,
            'errors' => [
                'general' => 'Registration could not be completed. Please check your information and try again.'
            ]
        ];
    }
}
