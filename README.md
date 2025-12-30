# SQL Injection Educational Project

A comprehensive, interactive educational project demonstrating SQL Injection (SQLi) vulnerabilities and secure coding practices. Perfect for students, developers, and security enthusiasts learning about web application security.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Database Setup](#database-setup)
- [SQL Injection Types](#sql-injection-types)
- [Installation & Configuration](#installation--configuration)

## 🎯 Project Overview

This project provides hands-on demonstrations of SQL Injection vulnerabilities alongside their secure implementations. It covers multiple SQLi attack types with detailed explanations of attack mechanisms and their countermeasures.



## ✨ Features

### 1. **Classic SQL Injection Demo** (`login_demo.php` & `login_demo_secure.php`)
- Interactive login system with intentional vulnerability
- Side-by-side comparison of vulnerable vs. secure code
- Visual SQL query display
- Payload suggestions for educational testing

### 2. **Union-based SQL Injection Demo** (`union_based_sqli_demo.html`)
- Learn how to extract data using UNION attacks
- Interactive demonstrations with real-time feedback
- Secure implementation with prepared statements

### 3. **Time-based Blind SQL Injection Demo** (`time_based_blind_sqli_demo.html`)
- Understand attacks without error feedback
- Response time analysis visualization
- Binary search character extraction simulation

### 4. **Database Setup Script** (`database_setup.sql`)
- Complete MySQL schema ready for deployment
- Test data included
- Users, Products, and Logs tables
- Instant deployment for students

## 🚀 Quick Start (5 Minutes)

1. **Clone Repository**
   ```bash
   git clone <repository-url>
   ```

2. **Create Database**
   ```bash
   mysql -u root -p < database_setup.sql
   ```

3. **Copy to Web Server**
   - **Windows (XAMPP)**: `C:\xampp\htdocs\sqli-demo\`
   - **Mac (MAMP)**: `/Applications/MAMP/htdocs/sqli-demo/`
   - **Linux**: `/var/www/html/sqli-demo/`

4. **Access in Browser**
   ```
   http://localhost/sqli-demo/login_demo.php
   ```

## 📊 Database Setup

### Database Schema

The project includes three main tables:

#### **users** Table
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user'
);
```

**Test Credentials:**
| Username | Password | Role |
|----------|----------|------|
| admin | adminpass | admin |
| user1 | password123 | user |
| user2 | securepass456 | user |
| moderator | modpass789 | moderator |
| guest | guestpass | user |

#### **products** Table
For Union-based SQLi demonstrations with product data examples.

#### **login_logs** Table
For tracking and analyzing login attempts and detected attacks.

### Setting Up Database

**Option 1: Command Line**
```bash
mysql -u root -p < database_setup.sql
```

**Option 2: phpMyAdmin**
1. Open phpMyAdmin
2. Go to Import tab
3. Select `database_setup.sql`
4. Click Import

**Option 3: MySQL Workbench**
1. File → Open SQL Script
2. Select `database_setup.sql`
3. Execute (Ctrl+Enter)

## 📁 Project Structure

```
SQL-INJECTION-main/
├── README.md                      # Complete documentation
├── LICENSE                        # MIT License
├── database_setup.sql             # MySQL schema & test data
├── login_demo.php                 # Vulnerable login system
├── login_demo_secure.php          # Secure login implementation
├── union_based_sqli_demo.html     # Union-based attack demo
├── time_based_blind_sqli_demo.html# Time-based blind attack demo
├── VulnerableLoginServlet.java    # Java vulnerable servlet
└── SecureLoginServlet.java        # Java secure servlet
```

## 🔓 SQL Injection Types Demonstrated

### 1. Classic/Direct SQL Injection
**Characteristics:**
- Direct database error feedback
- Quickest to exploit
- Easiest to detect

**Example Attack:**
```
Username: admin' OR '1'='1' --
Password: anything
```

### 2. Union-based SQL Injection
**Characteristics:**
- Combines results from multiple queries
- Requires matching column counts
- Very effective for data extraction

**Example Attack:**
```
Search: ' UNION SELECT username, password, 3, 4, 5, 6, 7, 8 FROM users --
```

### 3. Time-based Blind SQL Injection
**Characteristics:**
- No error messages or visual feedback
- Measures response time delays
- Binary search to extract data character-by-character

**Example Attack:**
```
Username: admin' AND IF(1=1, SLEEP(5), 0) --
```

## 💻 Installation & Configuration

### Windows Setup (XAMPP)

1. Download XAMPP from https://www.apachefriends.org/
2. Install with PHP and MySQL
3. Start Apache and MySQL from XAMPP Control Panel
4. Copy files to `C:\xampp\htdocs\sqli-demo\`
5. Import database: http://localhost/phpmyadmin
6. Access: http://localhost/sqli-demo/login_demo.php

### Mac Setup (MAMP)

1. Download MAMP from https://www.mamp.info/
2. Install and start services
3. Copy files to `/Applications/MAMP/htdocs/sqli-demo/`
4. Import database via phpMyAdmin
5. Access: http://localhost:8888/sqli-demo/login_demo.php

### Linux Setup (Ubuntu/Debian)

```bash
# Install packages
sudo apt update
sudo apt install apache2 php php-mysql mysql-server

# Start services
sudo systemctl start apache2 mysql

# Copy files
sudo cp -r SQL-INJECTION /var/www/html/sqli-demo
sudo chown -R www-data:www-data /var/www/html/sqli-demo

# Create database
sudo mysql -u root -p < database_setup.sql

# Access: http://localhost/sqli-demo/login_demo.php
```

## 🎯 Usage Examples

### Testing Classic SQLi
1. Open login_demo.php
2. Username: `admin' OR '1'='1`
3. Password: leave empty
4. Click "Try SQL Injection Attack"
5. See SQL query and successful bypass

### Testing Union-based
1. Open union_based_sqli_demo.html
2. Try: `' UNION SELECT username, password, 3, 4, 5, 6, 7, 8 FROM users --`
3. Compare vulnerable vs. secure implementations

### Testing Time-based Blind
1. Open time_based_blind_sqli_demo.html
2. Username: `admin' AND SLEEP(5) --`
3. Observe the response delay
4. Use binary search simulation to extract data

## 🛡️ Security Best Practices

### 1. Prepared Statements

**PHP (MySQLi)**
```php
$stmt = $con->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

**PHP (PDO)**
```php
$stmt = $con->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->execute([$username, $password]);
```

**Java**
```java
PreparedStatement stmt = con.prepareStatement("SELECT * FROM users WHERE username=? AND password=?");
stmt.setString(1, username);
stmt.setString(2, password);
```

### 2. Input Validation

```php
if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
    die('Invalid username format');
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die('Invalid email');
}
if (strlen($password) < 8) {
    die('Password too short');
}
```

### 3. Principle of Least Privilege

```sql
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT ON testdb.users TO 'app_user'@'localhost';
REVOKE ALL PRIVILEGES ON *.* FROM 'app_user'@'localhost';
```

### 4. Password Hashing

```php
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);
if (password_verify($input, $hashedPassword)) {
    // Correct password
}
```

### 5. Error Handling

```php
try {
    $result = $con->query($sql);
} catch (Exception $e) {
    error_log($e->getMessage());
    die('An error occurred. Please try again later.');
}
```

### 6. Security Headers

```php
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000");
```

## 🔧 Technologies Used

| Technology | Version | Purpose |
|-----------|---------|------|
| PHP | 7.4+ | Server scripting |
| MySQL | 5.7+ | Database |
| HTML5 | - | Markup |
| CSS3 | - | Styling |
| JavaScript | ES6+ | Interactivity |
| Java | 8+ | Servlets |
| Apache | 2.4+ | Web server |

## 📚 Learning Outcomes

✅ SQL Injection mechanics and vulnerabilities
✅ Different SQLi attack types
✅ Secure coding practices
✅ Prepared statements and parameterized queries
✅ Input validation and sanitization
✅ Database security best practices
✅ Error handling and secure implementations
✅ Detection and prevention techniques

## 📖 Additional Resources

### OWASP
- [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Top 10](https://owasp.org/www-project-top-ten/)
- [Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### CWE
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## ⚠️ Disclaimer

**IMPORTANT: Educational Purposes Only**

### ✅ Ethical Use
- Learn security concepts
- Test on your own systems
- Build secure applications

### ❌ DO NOT
- Attack systems without permission
- Use for unauthorized access
- Bypass security illegally

### Legal Notice
Unauthorized computer access is illegal. Only use in authorized testing and educational contexts.

### Production Warning
**NEVER** use vulnerable code in production. Always implement secure versions with prepared statements and input validation.

## 👨‍💻 Created By
**ATARFU TEAM** - Educational Security & Development

---

**Version:** 2.0
**Last Updated:** December 2024
**Status:** Active Development

### Changelog

**v2.0 - Educational Enhancement**
- Comprehensive database setup script
- Interactive Union-based SQLi demo
- Interactive Time-based Blind SQLi demo
- Expanded documentation
- Security best practices guide
- Multi-platform setup instructions

**v1.0 - Initial Release**
- Vulnerable login demo
- Secure implementation
- Java servlet examples
<img width="1919" height="1079" alt="no bypass sanatized&#39;" src="https://github.com/user-attachments/assets/0cdc955b-d35b-4836-b188-7ec807354486" />
<img width="1919" height="1079" alt="bypass pratised" src="https://github.com/user-attachments/assets/42871fae-ae89-460a-ad89-7456c8734777" />
