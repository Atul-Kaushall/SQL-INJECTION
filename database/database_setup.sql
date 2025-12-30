-- ============================================
-- SQL Injection Educational Project
-- Database Setup Script
-- ============================================
-- This script creates the necessary database and tables
-- for the SQL Injection demonstrations
-- ============================================

-- Drop existing database if it exists (optional)
DROP DATABASE IF EXISTS testdb;

-- Create the database
CREATE DATABASE testdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Select the database
USE testdb;

-- ============================================
-- USERS TABLE SCHEMA
-- ============================================
-- This table stores user credentials for authentication
-- It is intentionally basic to demonstrate SQL injection
-- vulnerabilities and their fixes

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- PRODUCTS TABLE (for UNION-based SQLi demo)
-- ============================================
-- This table stores product information
-- Used to demonstrate UNION-based SQL injection

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_name VARCHAR(150) NOT NULL,
    category VARCHAR(50),
    price DECIMAL(10, 2) NOT NULL,
    quantity INT DEFAULT 0,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_available BOOLEAN DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- LOGS TABLE (for tracking access and attacks)
-- ============================================
-- This table stores login attempts and detected attacks
-- Used for security monitoring

CREATE TABLE login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password_attempt VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    login_status VARCHAR(20), -- 'success', 'failed', 'sql_injection'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sql_query_executed LONGTEXT,
    is_injection_attempt BOOLEAN DEFAULT FALSE,
    injection_type VARCHAR(50),
    INDEX idx_username (username),
    INDEX idx_created_at (created_at),
    INDEX idx_is_injection (is_injection_attempt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- INSERT TEST DATA
-- ============================================

-- Insert test users
-- NOTE: In real applications, passwords should be hashed using bcrypt or similar
-- These are plain text passwords for educational demonstration purposes only!
INSERT INTO users (username, password, email, full_name, role) VALUES
('admin', 'adminpass', 'admin@example.com', 'Administrator', 'admin'),
('user1', 'password123', 'user1@example.com', 'John Doe', 'user'),
('user2', 'securepass456', 'user2@example.com', 'Jane Smith', 'user'),
('moderator', 'modpass789', 'moderator@example.com', 'Bob Wilson', 'moderator'),
('guest', 'guestpass', 'guest@example.com', 'Guest User', 'user');

-- Insert test products
INSERT INTO products (product_name, category, price, quantity, description) VALUES
('Laptop Computer', 'Electronics', 799.99, 15, 'High-performance laptop with 16GB RAM'),
('Wireless Mouse', 'Accessories', 29.99, 50, 'Ergonomic wireless mouse with 2.4GHz receiver'),
('USB-C Cable', 'Cables', 12.99, 100, 'Durable USB-C charging and data cable'),
('Monitor Stand', 'Office', 49.99, 25, 'Adjustable monitor stand for better ergonomics'),
('Keyboard', 'Accessories', 89.99, 30, 'Mechanical gaming keyboard with RGB lighting');

-- ============================================
-- GRANT PRIVILEGES
-- ============================================
-- Create a dedicated database user with limited privileges
-- for the application (recommended practice)

-- For development/testing (you may need to adjust user/host)
CREATE USER IF NOT EXISTS 'sqli_demo'@'localhost' IDENTIFIED BY 'demo_password123';

-- Grant necessary privileges
GRANT SELECT, INSERT, UPDATE ON testdb.* TO 'sqli_demo'@'localhost';

-- Flush privileges to apply changes
FLUSH PRIVILEGES;

-- ============================================
-- DISPLAY SCHEMA INFORMATION
-- ============================================

-- Show created tables
SHOW TABLES;

-- Show users table structure
DESCRIBE users;

-- Show products table structure
DESCRIBE products;

-- Show login_logs table structure
DESCRIBE login_logs;

-- ============================================
-- VERIFICATION QUERIES
-- ============================================

-- Verify data was inserted correctly
SELECT 'Users Table Data:' AS 'Status';
SELECT * FROM users;

SELECT 'Products Table Data:' AS 'Status';
SELECT * FROM products;

-- Count records
SELECT 
    (SELECT COUNT(*) FROM users) AS Total_Users,
    (SELECT COUNT(*) FROM products) AS Total_Products,
    (SELECT COUNT(*) FROM login_logs) AS Total_Logs;

-- ============================================
-- END OF SETUP SCRIPT
-- ============================================
-- Database is now ready for SQL Injection demonstrations
-- Students can now use these tables with the provided PHP scripts
-- Remember: This is for educational purposes only!
-- ============================================
