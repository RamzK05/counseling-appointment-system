
<?php

require_once dirname(__DIR__) . '/app/bootstrap.php';

$captchaMessage = '';
$captchaSuccess = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!verifyCsrfToken()) {
        $captchaMessage = 'Your session has expired or the request is invalid. Please refresh the page.';
    } else {
        $submittedCaptcha = strtoupper(trim($_POST['captcha'] ?? ''));
        $storedCaptcha = $_SESSION['captcha_answer'] ?? '';

        // CAPTCHA is single-use.
        unset($_SESSION['captcha_answer']);

        if (
            !is_string($submittedCaptcha) ||
            !is_string($storedCaptcha) ||
            $storedCaptcha === '' ||
            !hash_equals($storedCaptcha, hash('sha256', $submittedCaptcha))
        ) {
            $captchaMessage = 'Incorrect CAPTCHA code. Please try again.';
        } else {
            $captchaSuccess = true;
            $captchaMessage = 'CAPTCHA verified successfully. Registration processing will be connected in the next step.';
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Registration | Campus Counseling</title>
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
        <span class="eyebrow">STUDENT PORTAL</span>
        <h2>Create Your Account</h2>
        <p>Register to request counseling appointments.</p>
    </section>

    <form id="registrationForm" class="registration-card" method="POST" action="register.php">

        <input
            type="hidden"
            name="csrf_token"
            value="<?= h($_SESSION['csrf_token']) ?>"
        >

        <div class="notice">
            <strong>Before you begin:</strong>
            Please provide accurate information. Fields marked with
            an asterisk (*) are required.
        </div>

        <?php if ($captchaMessage !== ''): ?>
            <div class="notice" role="alert">
                <?= h($captchaMessage) ?>
            </div>
        <?php endif; ?>

        <!-- 1. STUDENT INFORMATION -->
        <section class="form-section">
            <h3>1. Student Information</h3>

            <div class="form-grid">

                <div class="form-group">
                    <label for="id_number">Student ID Number *</label>
                    <input type="text" id="id_number" name="id_number"
                           placeholder="xxxx-xxxx"
                           maxlength="9" required>
                </div>

                <div class="form-group">
                    <label for="course">Student Course *</label>
                    <select id="course" name="course" required>
                        <option value="">Select your course</option>
                        <option value="BSIT">BS Information Technology (BSIT)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="year_level">Year Level *</label>
                    <select id="year_level" name="year_level" required>
                        <option value="">Select year level</option>
                        <option value="1st Year">1st Year</option>
                        <option value="2nd Year">2nd Year</option>
                        <option value="3rd Year">3rd Year</option>
                        <option value="4th Year">4th Year</option>
                    </select>
                </div>

            </div>
        </section>

        <!-- 2. PERSONAL INFORMATION -->
        <section class="form-section">
            <h3>2. Personal Information</h3>

            <div class="form-grid">

                <div class="form-group">
                    <label for="first_name">First Name *</label>
                    <input type="text" id="first_name" name="first_name"
                           maxlength="23" autocomplete="given-name" required>
                </div>

                <div class="form-group">
                    <label for="middle_name">Middle Name</label>
                    <input type="text" id="middle_name" name="middle_name"
                           maxlength="23" autocomplete="additional-name">
                </div>

                <div class="form-group">
                    <label for="family_name">Family Name *</label>
                    <input type="text" id="family_name" name="family_name"
                           maxlength="23" autocomplete="family-name" required>
                </div>

                <div class="form-group">
                    <label for="extension">Name Extension</label>
                    <select id="extension" name="extension">
                        <option value="">None</option>
                        <option value="Jr.">Jr.</option>
                        <option value="Sr.">Sr.</option>
                        <option value="Other">Other</option>
                    </select>
                </div>

                <div class="form-group hidden" id="otherExtensionGroup">
                    <label for="other_extension">Specify Extension</label>
                    <input type="text" id="other_extension"
                           name="other_extension" placeholder="Example: II">
                </div>

                <div class="form-group">
                    <label for="birthdate">Birthdate *</label>
                    <input type="date" id="birthdate" name="birthdate" required>
                </div>

                <div class="form-group">
                    <label for="age">Age</label>
                    <input type="text" id="age" name="age"
                           placeholder="Automatically calculated" readonly>
                    <small>Age is calculated from your birthdate.</small>
                </div>

            </div>
        </section>

        <!-- 3. ADDRESS -->
        <section class="form-section">
            <h3>3. Complete Address</h3>

            <div class="form-grid">

                <div class="form-group">
                    <label for="street">Purok / Street *</label>
                    <input type="text" id="street" name="street"
                           minlength="3" maxlength="50" required>
                </div>

                <div class="form-group">
                    <label for="barangay">Barangay *</label>
                    <input type="text" id="barangay" name="barangay"
                           minlength="2" maxlength="50" required>
                </div>

                <div class="form-group">
                    <label for="municipality">Municipality / City *</label>
                    <input type="text" id="municipality" name="municipality"
                           minlength="2" maxlength="50" required>
                </div>

                <div class="form-group">
                    <label for="province">Province *</label>
                    <input type="text" id="province" name="province"
                           minlength="2" maxlength="50" required>
                </div>

                <div class="form-group">
                    <label for="country">Country *</label>
                    <input type="text" id="country" name="country"
                           value="Philippines" maxlength="50" required>
                </div>

                <div class="form-group">
                    <label for="zip_code">ZIP Code *</label>
                    <input type="text" id="zip_code" name="zip_code"
                           inputmode="numeric" maxlength="4"
                           placeholder="4 digits" required>
                </div>

            </div>
        </section>

        <!-- 4. ACCOUNT CREDENTIALS -->
        <section class="form-section">
            <h3>4. Account Credentials</h3>

            <div class="form-grid">

                <div class="form-group">
                    <label for="email">Email Address *</label>
                    <input type="email" id="email" name="email"
                           maxlength="100" autocomplete="email"
                           placeholder="example@email.com" required>
                </div>

                <div class="form-group">
                    <label for="username">Username *</label>
                    <input type="text" id="username" name="username"
                           minlength="8" maxlength="19"
                           pattern="[A-Za-z][A-Za-z0-9]{7,18}"
                           autocomplete="username" required>
                    <small>8–19 characters. Start with a letter; letters and numbers only.</small>
                </div>

                <div class="form-group">
                    <label for="password">Password *</label>
                    <input type="password" id="password" name="password"
                           minlength="11" maxlength="64"
                           autocomplete="new-password" required>

                    <div class="password-meter">
                        <div id="passwordStrengthBar"></div>
                    </div>
                    <small id="passwordStrengthText">Password strength: Not entered</small>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Re-enter Password *</label>
                    <input type="password" id="confirm_password"
                           name="confirm_password" minlength="11"
                           maxlength="64" autocomplete="new-password" required>
                </div>

            </div>
        </section>

        <!-- 5. AUTHENTICATION QUESTIONS -->
        <section class="form-section">
            <h3>5. Authentication Questions</h3>

            <p class="section-description">
                These questions may be used to help verify your identity
                during account recovery. Keep your answers private.
            </p>

            <div class="form-group">
                <label>Question 1 *</label>
                <input type="text"
                       value="What is your mother’s maiden first name?"
                       readonly>
                <input type="hidden" name="question_1" value="Q4">
                <input type="text" name="answer_1"
                       placeholder="Your answer" minlength="2"
                       maxlength="50" required>
            </div>

            <div class="form-group">
                <label>Question 2 *</label>
                <input type="text"
                       value="What was the name of your elementary school?"
                       readonly>
                <input type="hidden" name="question_2" value="Q7">
                <input type="text" name="answer_2"
                       placeholder="Your answer" minlength="2"
                       maxlength="50" required>
            </div>

            <div class="form-group">
                <label>Question 3 *</label>
                <input type="text"
                       value="What was the name of your first pet?"
                       readonly>
                <input type="hidden" name="question_3" value="Q1">
                <input type="text" name="answer_3"
                       placeholder="Your answer" minlength="2"
                       maxlength="50" required>
            </div>
        </section>

        <!-- 6. APPOINTMENT INFORMATION -->
        <section class="form-section">
            <h3>6. Appointment Information</h3>

            <p class="section-description">
                Provide your appointment preferences. These details
                will help organize your appointment request.
            </p>

            <div class="form-grid">

                <div class="form-group">
                    <label for="concern_category">Concern Category *</label>
                    <select id="concern_category"
                            name="concern_category" required>
                        <option value="">Select a concern category</option>
                        <option value="Academic Concerns">Academic Concerns</option>
                        <option value="Personal Concerns">Personal Concerns</option>
                        <option value="Family Concerns">Family Concerns</option>
                        <option value="Relationship Concerns">Relationship Concerns</option>
                        <option value="Emotional and Stress Concerns">Emotional and Stress Concerns</option>
                        <option value="Career and Future Planning">Career and Future Planning</option>
                        <option value="Other Concerns">Other Concerns</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="preferred_schedule">Preferred Schedule *</label>
                    <input type="date" id="preferred_schedule"
                           name="preferred_schedule" required>
                </div>

                <div class="form-group">
                    <label for="guardian_contact">Guardian Contact *</label>
                    <input type="tel" id="guardian_contact"
                           name="guardian_contact"
                           placeholder="09XXXXXXXXX"
                           maxlength="11" minlength="11"
                           pattern="09[0-9]{9}"
                           inputmode="numeric" required>
                    <small>Enter an 11-digit mobile number beginning with 09.</small>
                </div>

                <div class="form-group">
                    <label for="notes">Notes for Counselor</label>
                    <textarea id="notes" name="notes" rows="4"
                              maxlength="2000"
                              placeholder="Briefly describe anything you would like to share about your appointment request."></textarea>
                    <small>
                        Optional. Avoid including unnecessary sensitive personal information.
                    </small>
                </div>

            </div>
        </section>

        <!-- 7. CAPTCHA -->
        <section class="form-section">
            <h3>7. Security Verification</h3>

            <p class="section-description">
                Enter the six characters displayed in the image below.
            </p>

            <div class="form-group">
                <div class="captcha-container">
                    <img
                        id="captchaImage"
                        src="captcha.php"
                        alt="CAPTCHA verification image"
                        width="200"
                        height="70"
                    >

                    <button
                        type="button"
                        id="refreshCaptcha"
                        class="btn-secondary"
                    >
                        Refresh CAPTCHA
                    </button>
                </div>

                <label for="captcha">Enter CAPTCHA Code *</label>
                <input
                    type="text"
                    id="captcha"
                    name="captcha"
                    maxlength="6"
                    minlength="6"
                    pattern="[A-Za-z0-9]{6}"
                    autocomplete="off"
                    placeholder="Enter the 6 characters"
                    required
                >
                <small>CAPTCHA codes are not case-sensitive.</small>
            </div>
        </section>

        <!-- 8. PRIVACY NOTICE -->
        <section class="form-section" id="privacy-notice">
            <h3>8. Privacy Notice and Consent</h3>

            <div class="privacy-box">
                <h4>Privacy Notice</h4>

                <p>
                    The Campus Counseling Appointment and Secure Monitoring
                    System collects student identification, personal details,
                    contact information, account credentials, authentication
                    answers, and appointment information for account
                    registration, email verification, appointment management,
                    account recovery, and system security.
                </p>

                <p>
                    Personal information is protected through security
                    measures such as password hashing, encryption of
                    sensitive appointment notes, email OTP verification,
                    access controls, and activity monitoring.
                </p>

                <p>
                    Under the proposed system retention policy, account
                    and appointment records are retained while an account
                    is active and for up to one year after account closure.
                    Security logs are retained for up to one year for
                    security monitoring.
                </p>

                <p>
                    This system is independently managed by its System
                    Administrator. It is not represented as an officially
                    operated university counseling office.
                </p>

                <p>
                    For privacy-related questions or concerns, contact
                    the System Administrator responsible for this system.
                </p>

                <p>
                    Personal data is processed in accordance with the
                    Data Privacy Act of 2012 (RA 10173).
                </p>

                <p>
                    <a href="privacy.php" target="_blank" rel="noopener">
                        Read the complete Privacy Notice
                    </a>
                </p>
            </div>

            <label class="consent-label">
                <input type="checkbox"
                       id="privacy_consent"
                       name="privacy_consent"
                       value="1"
                       required>
                <span>
                    I have read the Privacy Notice and agree to the collection
                    and processing of my personal data in accordance with the
                    Data Privacy Act of 2012 (RA 10173).
                </span>
            </label>
        </section>

        <!-- SUBMIT -->
        <div class="form-actions">
            <button type="submit" class="btn-primary">
                Create Account
            </button>

            <p>
                Already have an account?
                <a href="login.html">Log in here</a>.
            </p>
        </div>

    </form>
</main>

<footer class="site-footer">
    <p>© 2026 Campus Counseling Appointment and Secure Monitoring System.</p>
</footer>

<script>
    // Set the maximum birthdate to today.
    const birthdateInput = document.getElementById("birthdate");

    const today = new Date();
    const localToday = new Date(
        today.getTime() - today.getTimezoneOffset() * 60000
    ).toISOString().split("T")[0];

    birthdateInput.max = localToday;

    // Calculate age from the selected birthdate.
    birthdateInput.addEventListener("change", function () {
        const birthdate = new Date(this.value + "T00:00:00");
        const today = new Date();

        if (!this.value || birthdate > today) {
            document.getElementById("age").value = "";
            return;
        }

        let age = today.getFullYear() - birthdate.getFullYear();
        const monthDifference = today.getMonth() - birthdate.getMonth();

        if (
            monthDifference < 0 ||
            (monthDifference === 0 && today.getDate() < birthdate.getDate())
        ) {
            age--;
        }

        document.getElementById("age").value = age;
    });

    // Show the extension field only when "Other" is selected.
    document.getElementById("extension").addEventListener("change", function () {
        const otherGroup = document.getElementById("otherExtensionGroup");
        const otherInput = document.getElementById("other_extension");

        otherGroup.classList.toggle("hidden", this.value !== "Other");
        otherInput.required = this.value === "Other";

        if (this.value !== "Other") {
            otherInput.value = "";
        }
    });

    // Password strength indicator.
    const passwordInput = document.getElementById("password");

    passwordInput.addEventListener("input", function () {
        const password = this.value;
        const bar = document.getElementById("passwordStrengthBar");
        const text = document.getElementById("passwordStrengthText");

        let score = 0;

        if (password.length >= 11) score++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        const labels = ["Weak", "Weak", "Medium", "Strong", "Strong"];
        const widths = ["10%", "25%", "50%", "75%", "100%"];

        bar.style.width = password.length === 0 ? "0%" : widths[score];
        bar.dataset.strength = labels[score];

        text.textContent = password.length === 0
            ? "Password strength: Not entered"
            : "Password strength: " + labels[score];
    });

    // Set minimum preferred appointment date to today.
    const scheduleInput = document.getElementById("preferred_schedule");
    scheduleInput.min = localToday;

    // Refresh CAPTCHA image.
    document.getElementById("refreshCaptcha").addEventListener("click", function () {
        const captchaImage = document.getElementById("captchaImage");

        captchaImage.src = "captcha.php?refresh=" + Date.now();

        document.getElementById("captcha").value = "";
    });

    // Check password confirmation before submitting.
    document.getElementById("registrationForm").addEventListener("submit", function (event) {
        const password = document.getElementById("password").value;
        const confirmation = document.getElementById("confirm_password").value;

        if (password !== confirmation) {
            event.preventDefault();
            alert("Passwords do not match.");
        }
    });

    // Clear the CAPTCHA input after the page is loaded.
    document.getElementById("captcha").value = "";
</script>

</body>
</html>