-- Migration script for MySQL database
-- Run this to set up the initial database schema

-- Create database (if running manually)
-- CREATE DATABASE IF NOT EXISTS securedb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE securedb;

-- Users table
-- Migration script for MySQL database
-- Run this to set up the initial database schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_active (user_id, is_revoked, is_used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) NOT NULL,
    user_id INT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    endpoint VARCHAR(255) NULL,
    event_metadata TEXT NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_user_id (user_id),
    INDEX idx_user_event (user_id, event_type),
    INDEX idx_timestamp_event (timestamp, event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Create a test admin user (password: AdminPassword123!)
-- Hash generated for: AdminPassword123!
INSERT INTO users (email, hashed_password, full_name, role) VALUES
('admin@example.com', '$argon2id$v=19$m=65536,t=2,p=4$somehashedpasswordhere', 'Admin User', 'admin')
ON DUPLICATE KEY UPDATE email=email;

-- Create a test regular user (password: UserPassword123!)
INSERT INTO users (email, hashed_password, full_name, role) VALUES
('user@example.com', '$argon2id$v=19$m=65536,t=2,p=4$somehashedpasswordhere', 'Regular User', 'user')
ON DUPLICATE KEY UPDATE email=email;