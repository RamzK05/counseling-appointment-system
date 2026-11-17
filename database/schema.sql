
-- =========================================================
-- CAMPUS COUNSELING APPOINTMENT AND SECURE MONITORING SYSTEM
-- IT 107 - Database Schema
-- MySQL / MariaDB
-- =========================================================

CREATE DATABASE IF NOT EXISTS counseling_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE counseling_db;


-- =========================================================
-- 1. USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id_number CHAR(9) PRIMARY KEY,

    first_name VARCHAR(23) NOT NULL,
    middle_name VARCHAR(23) NULL,
    family_name VARCHAR(23) NOT NULL,
    name_extension VARCHAR(10) NULL,

    birthdate DATE NOT NULL,

    purok_street VARCHAR(50) NOT NULL,
    barangay VARCHAR(50) NOT NULL,
    municipality_city VARCHAR(50) NOT NULL,
    province VARCHAR(50) NOT NULL,
    country VARCHAR(50) NOT NULL,
    zip_code CHAR(4) NOT NULL,

    email VARCHAR(100) NOT NULL UNIQUE,
    username VARCHAR(19) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,

    student_course VARCHAR(100) NOT NULL,
    year_level VARCHAR(30) NOT NULL,

    role ENUM('student', 'counselor', 'admin')
        NOT NULL DEFAULT 'student',

    account_status ENUM('pending', 'active', 'disabled')
        NOT NULL DEFAULT 'pending',

    is_verified TINYINT(1) NOT NULL DEFAULT 0,

    failed_login_count INT NOT NULL DEFAULT 0,
    lockout_tier TINYINT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,

    consent_at DATETIME NOT NULL,
    consent_version VARCHAR(20) NOT NULL,

    last_login_at DATETIME NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_users_role (role),
    INDEX idx_users_status (account_status)
) ENGINE=InnoDB;


-- =========================================================
-- 2. AUTHENTICATION ANSWERS
-- =========================================================

CREATE TABLE IF NOT EXISTS auth_answers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    user_id CHAR(9) NOT NULL,
    question_code CHAR(2) NOT NULL,
    answer_hash VARCHAR(255) NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_user_question (user_id, question_code),

    CONSTRAINT fk_auth_answers_user
        FOREIGN KEY (user_id)
        REFERENCES users(id_number)
        ON DELETE CASCADE
) ENGINE=InnoDB;


-- =========================================================
-- 3. PASSWORD HISTORY
-- =========================================================

CREATE TABLE IF NOT EXISTS password_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    user_id CHAR(9) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_password_history_user_date (user_id, created_at),

    CONSTRAINT fk_password_history_user
        FOREIGN KEY (user_id)
        REFERENCES users(id_number)
        ON DELETE CASCADE
) ENGINE=InnoDB;


-- =========================================================
-- 4. OTP RECORDS
-- =========================================================

CREATE TABLE IF NOT EXISTS otp_records (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    user_id CHAR(9) NOT NULL,

    purpose ENUM('registration', 'login', 'password_reset')
        NOT NULL,

    otp_hash VARCHAR(255) NOT NULL,

    expires_at DATETIME NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    used_at DATETIME NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_otp_user_purpose (user_id, purpose),
    INDEX idx_otp_expiry (expires_at),

    CONSTRAINT fk_otp_user
        FOREIGN KEY (user_id)
        REFERENCES users(id_number)
        ON DELETE CASCADE
) ENGINE=InnoDB;


-- =========================================================
-- 5. COUNSELING APPOINTMENTS
-- =========================================================

CREATE TABLE IF NOT EXISTS appointments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    student_id CHAR(9) NOT NULL,
    assigned_counselor_id CHAR(9) NULL,

    concern_category VARCHAR(100) NOT NULL,
    preferred_schedule DATE NOT NULL,
    guardian_contact CHAR(11) NULL,

    notes_encrypted MEDIUMBLOB NULL,
    notes_iv VARBINARY(12) NULL,
    notes_tag VARBINARY(16) NULL,

    status ENUM('pending', 'confirmed', 'completed', 'cancelled')
        NOT NULL DEFAULT 'pending',

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_appointments_student (student_id),
    INDEX idx_appointments_counselor (assigned_counselor_id),
    INDEX idx_appointments_schedule (preferred_schedule),
    INDEX idx_appointments_status (status),

    CONSTRAINT fk_appointment_student
        FOREIGN KEY (student_id)
        REFERENCES users(id_number)
        ON DELETE RESTRICT,

    CONSTRAINT fk_appointment_counselor
        FOREIGN KEY (assigned_counselor_id)
        REFERENCES users(id_number)
        ON DELETE SET NULL
) ENGINE=InnoDB;


-- =========================================================
-- 6. LOGIN ATTEMPTS
-- =========================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    username_typed VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    successful TINYINT(1) NOT NULL DEFAULT 0,

    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_login_ip_time (ip_address, attempted_at),
    INDEX idx_login_username_time (username_typed, attempted_at)
) ENGINE=InnoDB;


-- =========================================================
-- 7. IP BLOCKS
-- =========================================================

CREATE TABLE IF NOT EXISTS ip_blocks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255) NOT NULL,

    blocked_at DATETIME NOT NULL,
    blocked_until DATETIME NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_ip_block_expiry (blocked_until)
) ENGINE=InnoDB;


-- =========================================================
-- 8. ACTIVITY LOGS
-- =========================================================

CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    event_type VARCHAR(60) NOT NULL,

    username_typed VARCHAR(100) NULL,
    user_id CHAR(9) NULL,

    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    details TEXT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_activity_event_time (event_type, created_at),
    INDEX idx_activity_username (username_typed),
    INDEX idx_activity_ip (ip_address),
    INDEX idx_activity_user (user_id),

    CONSTRAINT fk_activity_user
        FOREIGN KEY (user_id)
        REFERENCES users(id_number)
        ON DELETE SET NULL
) ENGINE=InnoDB;


-- =========================================================
-- 9. SECURITY FLAGS
-- Prevents duplicate flags for the same target per day.
-- =========================================================

CREATE TABLE IF NOT EXISTS security_flags (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    flag_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    related_ip VARCHAR(45) NULL,

    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    detected_date DATE NOT NULL DEFAULT (CURRENT_DATE),

    UNIQUE KEY unique_flag_per_day (flag_type, detected_date),

    INDEX idx_security_flag_date (detected_at),
    INDEX idx_security_flag_type (flag_type)
) ENGINE=InnoDB;


-- =========================================================
-- END OF DATABASE SCHEMA
-- =========================================================