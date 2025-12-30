# Configuration Reference Guide

## Database Configuration

### MySQL Connection Details

**Default Configuration:**
```
Host: localhost
Port: 3306
Database: testdb
User: sqli_demo
Password: demo_password123
```

### Changing Database Credentials

#### Option 1: Modify PHP Files

**File: login_demo.php**
```php
// Line ~10-15
$servername = "localhost";
$username = "YOUR_USERNAME";    // Change this
$password = "YOUR_PASSWORD";    // Change this
$dbname = "testdb";
```

**File: login_demo_secure.php**
Same location, update credentials

#### Option 2: Modify Java Servlets

**File: SecureLoginServlet.java**
```java
// Lines 20-21
private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
private static final String DB_USER = "YOUR_USERNAME";      // Change this
private static final String DB_PASSWORD = "YOUR_PASSWORD";  // Change this
```

**File: ZVulnerableLoginServlet.java**
```java
// Lines 17-19
private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
private static final String DB_USER = "YOUR_USERNAME";      // Change this
private static final String DB_PASSWORD = "YOUR_PASSWORD";  // Change this
```

## Web Server Configuration

### Apache Configuration (Linux)

**Configuration File Locations:**
- Main config: `/etc/apache2/apache2.conf`
- Virtual hosts: `/etc/apache2/sites-available/000-default.conf`
- Ports: `/etc/apache2/ports.conf`

**Change Default Port:**
```bash
sudo nano /etc/apache2/ports.conf
```
```apache
# Change from:
Listen 80

# To:
Listen 8080
```

**Enable Modules:**
```bash
# Enable PHP
sudo a2enmod php7.4

# Enable rewrite
sudo a2enmod rewrite

# Enable SSL
sudo a2enmod ssl

# Restart Apache
sudo systemctl restart apache2
```

### Apache Configuration (Windows XAMPP)

**Configuration File:**
`C:\xampp\apache\conf\httpd.conf`

**Change Default Port:**
```apache
# Find line:
Listen 80

# Change to:
Listen 8080
```

**Enable Modules:**
- Edit `httpd.conf`
- Uncomment required modules
- Restart Apache from XAMPP Control Panel

### Apache Configuration (Mac MAMP)

**Configuration File:**
`/Applications/MAMP/conf/apache/httpd.conf`

**Change Port:**
```bash
sudo nano /Applications/MAMP/conf/apache/httpd.conf
```

## MySQL Configuration

### Create Custom User

```sql
-- Create user with specific permissions
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'apppassword';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE ON testdb.users TO 'appuser'@'localhost';
GRANT SELECT ON testdb.products TO 'appuser'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify
SHOW GRANTS FOR 'appuser'@'localhost';
```

### Reset Permissions

```sql
-- Reset to full access (for testing only)
GRANT ALL PRIVILEGES ON testdb.* TO 'sqli_demo'@'localhost';
FLUSH PRIVILEGES;
```

### Change MySQL Root Password

**Linux/Mac Command Line:**
```bash
sudo mysql -u root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
FLUSH PRIVILEGES;
EXIT;
```

**Windows Command Line:**
```cmd
mysql -u root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
FLUSH PRIVILEGES;
EXIT;
```

### Enable Query Logging

```sql
-- Enable general query log
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';

-- View logs
SELECT * FROM mysql.general_log;

-- Clear logs
TRUNCATE mysql.general_log;

-- Disable logging
SET GLOBAL general_log = 'OFF';
```

### Create Backup

```bash
# Backup entire database
mysqldump -u root -p testdb > testdb_backup.sql

# Backup specific table
mysqldump -u root -p testdb users > users_backup.sql

# Restore from backup
mysql -u root -p testdb < testdb_backup.sql
```

## PHP Configuration

### Error Reporting

**Development (Show all errors):**
```php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
?>
```

**Production (Hide errors from users):**
```php
<?php
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php-errors.log');
?>
```

### PHP.ini Changes

**Location:**
- Linux/Mac: `/etc/php/7.4/apache2/php.ini`
- Windows XAMPP: `C:\xampp\php\php.ini`
- MAMP: `/Applications/MAMP/bin/php/php7.4.21/conf/php.ini`

**Important Settings:**
```ini
; Maximum upload size
upload_max_filesize = 50M

; Maximum post size
post_max_size = 50M

; Maximum execution time
max_execution_time = 300

; Memory limit
memory_limit = 256M

; Enable short open tags (optional)
short_open_tag = On

; Timezone
date.timezone = "America/New_York"

; Display errors (development only)
display_errors = On
```

## Security Headers

### Add to PHP Files

```php
<?php
// Prevent MIME type sniffing
header("X-Content-Type-Options: nosniff");

// Prevent framing
header("X-Frame-Options: DENY");

// Enable XSS protection
header("X-XSS-Protection: 1; mode=block");

// HSTS (HTTPS only)
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// Content Security Policy
header("Content-Security-Policy: default-src 'self'");

// Referrer Policy
header("Referrer-Policy: no-referrer");
?>
```

### Add to Apache Configuration

```apache
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "DENY"
    Header set X-XSS-Protection "1; mode=block"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
```

## Database Schema Reference

### Users Table
```sql
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
);
```

### Products Table
```sql
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_name VARCHAR(150) NOT NULL,
    category VARCHAR(50),
    price DECIMAL(10, 2) NOT NULL,
    quantity INT DEFAULT 0,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_available BOOLEAN DEFAULT TRUE
);
```

### Login Logs Table
```sql
CREATE TABLE login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password_attempt VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    login_status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sql_query_executed LONGTEXT,
    is_injection_attempt BOOLEAN DEFAULT FALSE,
    injection_type VARCHAR(50)
);
```

## Firewall and Network Configuration

### Open Ports

**For Apache:**
```bash
# Linux firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Or for specific port
sudo ufw allow 8080/tcp
```

**For MySQL (if remote access needed):**
```bash
# Linux firewall (use with caution!)
sudo ufw allow 3306/tcp

# Only allow from specific IP
sudo ufw allow from 192.168.1.100 to any port 3306
```

### MySQL Remote Access

**Edit MySQL Configuration:**
```bash
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
```

**Change bind-address:**
```ini
# Default (localhost only)
bind-address = 127.0.0.1

# Allow all addresses (security risk!)
# bind-address = 0.0.0.0

# Allow specific IP
# bind-address = 192.168.1.100
```

## Performance Tuning

### MySQL Optimization

```sql
-- Analyze tables for query optimization
ANALYZE TABLE users;
ANALYZE TABLE products;
ANALYZE TABLE login_logs;

-- Repair corrupted tables
REPAIR TABLE users;

-- Optimize tables
OPTIMIZE TABLE users;
OPTIMIZE TABLE products;
```

### Apache Performance

**Enable Caching:**
```apache
<IfModule mod_cache.c>
    CacheEnable disk /sqli-demo
    CacheDirLevels 2
    CacheDirLength 1
</IfModule>
```

**Enable Compression:**
```apache
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml
    AddOutputFilterByType DEFLATE text/javascript application/javascript
    AddOutputFilterByType DEFLATE text/css
</IfModule>
```

## SSL/HTTPS Configuration

### Generate Self-Signed Certificate

```bash
# Generate private key and certificate (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/sqli-demo.key \
    -out /etc/ssl/certs/sqli-demo.crt
```

### Enable SSL in Apache

```bash
# Enable SSL module
sudo a2enmod ssl

# Create SSL configuration
sudo nano /etc/apache2/sites-available/default-ssl.conf

# Update SSL paths:
SSLCertificateFile /etc/ssl/certs/sqli-demo.crt
SSLCertificateKeyFile /etc/ssl/private/sqli-demo.key

# Enable site and restart
sudo a2ensite default-ssl
sudo systemctl restart apache2
```

## Docker Configuration (Optional)

### Docker Compose File

```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: sqli_mysql
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: testdb
    ports:
      - "3306:3306"
    volumes:
      - ./database_setup.sql:/docker-entrypoint-initdb.d/setup.sql
      - mysql_data:/var/lib/mysql

  apache:
    image: php:7.4-apache
    container_name: sqli_apache
    ports:
      - "80:80"
    volumes:
      - ./:/var/www/html
    depends_on:
      - mysql

volumes:
  mysql_data:
```

**Usage:**
```bash
docker-compose up -d
# Access at http://localhost
```

## Environment Variables

### Create .env File

**File: .env**
```
DB_HOST=localhost
DB_PORT=3306
DB_NAME=testdb
DB_USER=sqli_demo
DB_PASS=demo_password123

SERVER_PORT=80
SERVER_HOST=localhost

DEBUG=true
LOG_LEVEL=info
```

### Use in PHP

```php
<?php
// Load environment variables
$dotenv = parse_ini_file('.env');

$db_host = $dotenv['DB_HOST'];
$db_user = $dotenv['DB_USER'];
$db_pass = $dotenv['DB_PASS'];
$db_name = $dotenv['DB_NAME'];
?>
```

## Version Information

**Compatible With:**
- PHP 7.4, 8.0, 8.1, 8.2
- MySQL 5.7, 8.0
- MariaDB 10.4, 10.5, 10.6
- Apache 2.4+
- Nginx 1.18+

**Last Updated:** December 2024
**Version:** 2.0
