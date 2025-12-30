# SQL Injection Educational Project - Setup & Installation Guide

## 📋 Overview

This guide provides step-by-step instructions to set up the SQL Injection Educational Project on Windows, Mac, and Linux. The project is designed for instant deployment and testing.

## ✅ System Requirements

### Minimum Requirements
- **PHP**: 7.4 or higher
- **MySQL**: 5.7 or MariaDB 10.4+
- **Apache/Nginx**: Latest version
- **Browser**: Modern browser (Chrome, Firefox, Safari, Edge)
- **RAM**: 2GB minimum
- **Disk Space**: 500MB free

### Recommended Requirements
- **PHP**: 8.0+
- **MySQL**: 8.0+
- **Apache**: 2.4.43+
- **4GB RAM**
- **1GB free disk space**

## 🪟 Windows Setup (XAMPP)

### Step 1: Download and Install XAMPP

1. Visit https://www.apachefriends.org/
2. Download XAMPP for Windows (PHP 7.4+ recommended)
3. Run the installer (right-click as Administrator)
4. Choose installation folder (default: `C:\xampp\`)
5. Select components:
   - ✅ Apache
   - ✅ MySQL
   - ✅ PHP
   - ✅ phpMyAdmin
6. Complete the installation

### Step 2: Start XAMPP Services

1. Open XAMPP Control Panel
2. Click "Start" next to "Apache"
3. Click "Start" next to "MySQL"
4. Wait for status indicators to turn green

**Verify Installation:**
- Open browser: http://localhost/
- You should see the XAMPP dashboard

### Step 3: Prepare Project Files

1. Create folder: `C:\xampp\htdocs\sqli-demo\`
2. Copy all project files to this folder:
   ```
   database_setup.sql
   README.md
   login_demo.php
   login_demo_secure.php
   union_based_sqli_demo.html
   time_based_blind_sqli_demo.html
   SecureLoginServlet.java
   ZVulnerableLoginServlet.java
   ```

### Step 4: Create Database

**Method A: Using phpMyAdmin (Recommended for Beginners)**

1. Open browser: http://localhost/phpmyadmin
2. Click "Import" tab at top
3. Click "Choose File"
4. Select `database_setup.sql` from project folder
5. Click "Import" button
6. You should see: "Import has been successfully finished"

**Method B: Using Command Prompt**

1. Open Command Prompt (Win+R → cmd)
2. Navigate to XAMPP MySQL: `cd C:\xampp\mysql\bin`
3. Import database:
   ```bash
   mysql -u root < "C:\xampp\htdocs\sqli-demo\database_setup.sql"
   ```

**Method C: Using MySQL Workbench**

1. Open MySQL Workbench
2. File → Open SQL Script
3. Select `database_setup.sql`
4. Click Execute (Ctrl+Enter)

### Step 5: Verify Installation

1. Open browser: http://localhost/phpmyadmin
2. Select `testdb` from left panel
3. Verify these tables exist:
   - users
   - products
   - login_logs

### Step 6: Access the Application

Open browser and navigate to:

| Demo | URL |
|------|-----|
| Classic SQLi | http://localhost/sqli-demo/login_demo.php |
| Secure Login | http://localhost/sqli-demo/login_demo_secure.php |
| Union-based | http://localhost/sqli-demo/union_based_sqli_demo.html |
| Time-based Blind | http://localhost/sqli-demo/time_based_blind_sqli_demo.html |

## 🍎 Mac Setup (MAMP)

### Step 1: Download and Install MAMP

1. Visit https://www.mamp.info/
2. Download MAMP (free version is sufficient)
3. Open the DMG file
4. Drag MAMP folder to Applications folder
5. Wait for installation to complete

### Step 2: Start MAMP Services

1. Open Applications → MAMP → MAMP.app
2. Click "Start Servers" button
3. Wait for all indicators to show green
4. Browser should automatically open with MAMP welcome page

### Step 3: Create Project Directory

```bash
mkdir -p /Applications/MAMP/htdocs/sqli-demo
```

### Step 4: Copy Project Files

1. Open Finder
2. Navigate to `/Applications/MAMP/htdocs/sqli-demo/`
3. Copy all project files into this directory

### Step 5: Create Database

**Method A: phpMyAdmin (Recommended)**

1. Open browser: http://localhost:8888/phpmyadmin
2. Click "Import" tab
3. Select `database_setup.sql`
4. Click "Import"

**Method B: Command Line**

```bash
mysql -u root -p < /Applications/MAMP/htdocs/sqli-demo/database_setup.sql
```

Default MAMP password: usually empty or "root"

### Step 6: Verify Installation

1. Open phpMyAdmin: http://localhost:8888/phpmyadmin
2. Check database `testdb` exists
3. Verify tables: users, products, login_logs

### Step 7: Access Application

| Demo | URL |
|------|-----|
| Classic SQLi | http://localhost:8888/sqli-demo/login_demo.php |
| Secure Version | http://localhost:8888/sqli-demo/login_demo_secure.php |
| Union-based | http://localhost:8888/sqli-demo/union_based_sqli_demo.html |
| Time-based Blind | http://localhost:8888/sqli-demo/time_based_blind_sqli_demo.html |

## 🐧 Linux Setup (Ubuntu/Debian)

### Step 1: Install Required Packages

```bash
# Update package manager
sudo apt update
sudo apt upgrade -y

# Install Apache, PHP, and MySQL
sudo apt install -y apache2 php php-mysql mysql-server

# Install additional useful packages
sudo apt install -y git curl wget nano
```

### Step 2: Start Services

```bash
# Start Apache
sudo systemctl start apache2
sudo systemctl enable apache2

# Start MySQL
sudo systemctl start mysql
sudo systemctl enable mysql

# Verify services are running
sudo systemctl status apache2
sudo systemctl status mysql
```

### Step 3: Create Project Directory

```bash
sudo mkdir -p /var/www/html/sqli-demo
```

### Step 4: Copy Project Files

```bash
# Navigate to project folder
cd ~/SQL-INJECTION-main

# Copy files to Apache directory
sudo cp -r . /var/www/html/sqli-demo/

# Set correct permissions
sudo chown -R www-data:www-data /var/www/html/sqli-demo
sudo chmod -R 755 /var/www/html/sqli-demo
```

### Step 5: Create Database

```bash
# Login to MySQL
sudo mysql -u root -p

# If prompted for password, use your MySQL root password
# Otherwise, just press Enter
```

Once in MySQL prompt:

```sql
-- Import the SQL script
SOURCE /var/www/html/sqli-demo/database_setup.sql;

-- Verify database was created
SHOW DATABASES;
SELECT * FROM testdb.users;

-- Exit
EXIT;
```

**Alternative: Direct import**

```bash
sudo mysql -u root < /var/www/html/sqli-demo/database_setup.sql
```

### Step 6: Enable PHP Module (if needed)

```bash
# Enable PHP Apache module
sudo a2enmod php7.4
# (Replace 7.4 with your PHP version)

# Restart Apache
sudo systemctl restart apache2
```

### Step 7: Access Application

| Demo | URL |
|------|-----|
| Classic SQLi | http://localhost/sqli-demo/login_demo.php |
| Secure Version | http://localhost/sqli-demo/login_demo_secure.php |
| Union-based | http://localhost/sqli-demo/union_based_sqli_demo.html |
| Time-based Blind | http://localhost/sqli-demo/time_based_blind_sqli_demo.html |

## 🔧 Troubleshooting

### Issue: "Cannot connect to database"

**Solution:**
1. Verify MySQL is running
2. Check database credentials in PHP files
3. Confirm `testdb` database exists: `SHOW DATABASES;` in MySQL
4. Verify user `sqli_demo` has permissions

```sql
-- Reset permissions
GRANT ALL PRIVILEGES ON testdb.* TO 'sqli_demo'@'localhost';
FLUSH PRIVILEGES;
```

### Issue: "Cannot load JDBC driver" (Java Servlets)

**Solution:**
1. Download MySQL JDBC Driver
2. Add to classpath:
   ```bash
   export CLASSPATH=$CLASSPATH:/path/to/mysql-connector-java-8.0.xx.jar
   ```

### Issue: "Port 3306 already in use"

**Solution:**
Check if MySQL is already running:
```bash
# Linux
sudo netstat -tulpn | grep 3306

# Kill existing process
sudo kill <PID>
```

### Issue: "Permission denied" errors

**Solution:**
Fix file permissions:
```bash
# Linux/Mac
sudo chmod -R 755 /var/www/html/sqli-demo
sudo chown -R www-data:www-data /var/www/html/sqli-demo
```

### Issue: "Error: Table 'testdb.users' doesn't exist"

**Solution:**
Re-import the database:
```bash
mysql -u root -p < database_setup.sql
```

## 📝 Configuration

### Change MySQL Credentials

If you use different MySQL credentials, update these files:

**login_demo.php & login_demo_secure.php:**
```php
$host = "localhost";
$user = "your_username";
$password = "your_password";
$dbname = "testdb";
```

**Java Servlets:**
```java
String DB_URL = "jdbc:mysql://localhost:3306/testdb";
String DB_USER = "your_username";
String DB_PASSWORD = "your_password";
```

### Change Server Port

**Apache Configuration:**
```bash
# Linux/Mac
sudo nano /etc/apache2/ports.conf
# Change "Listen 80" to "Listen 8080" (or desired port)
sudo systemctl restart apache2
```

**MySQL Configuration:**
```bash
# Linux/Mac
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# Find "port = 3306" and change as needed
sudo systemctl restart mysql
```

## 🧪 First Test Run

### Test 1: Classic SQL Injection

1. Open: http://localhost/sqli-demo/login_demo.php
2. Enter username: `admin' OR '1'='1`
3. Leave password empty
4. Click "Try SQL Injection Attack"
5. You should see:
   - The SQL query displayed
   - Message: "SQL Injection successful!"
   - "VULNERABLE TO SQL INJECTION" warning

### Test 2: Secure Implementation

1. Open: http://localhost/sqli-demo/login_demo_secure.php
2. Try same injection: `admin' OR '1'='1`
3. Password empty
4. Click login
5. You should see:
   - Error: "Invalid username or password"
   - No injection occurred (protected by prepared statements)

### Test 3: Union-based Attack

1. Open: http://localhost/sqli-demo/union_based_sqli_demo.html
2. In vulnerable search: `' UNION SELECT username,password,3,4,5,6,7,8 FROM users --`
3. Click search
4. See how user credentials are exposed
5. Compare with secure version (no exposure)

### Test 4: Time-based Blind Attack

1. Open: http://localhost/sqli-demo/time_based_blind_sqli_demo.html
2. Username: `admin' AND SLEEP(5) --`
3. Click execute
4. Observe the 5-second delay
5. Understand response-time based attacks

## 🎓 Learning Path

### Day 1: Introduction
- [ ] Read README.md completely
- [ ] Understand project structure
- [ ] Set up database and access application

### Day 2: Classic SQL Injection
- [ ] Test vulnerable login form
- [ ] Try different payloads
- [ ] Analyze SQL queries displayed
- [ ] Compare with secure version

### Day 3: Union-based Attacks
- [ ] Open union_based_sqli_demo.html
- [ ] Understand UNION operator
- [ ] Try data extraction payloads
- [ ] Study prepared statement protection

### Day 4: Time-based Blind Attacks
- [ ] Open time_based_blind_sqli_demo.html
- [ ] Understand timing attacks
- [ ] Use binary search simulation
- [ ] Learn response-time analysis

### Day 5: Security Best Practices
- [ ] Review secure code examples
- [ ] Study input validation
- [ ] Learn prepared statements
- [ ] Implement in your own projects

## 📚 Additional Resources

### Official Documentation
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PHP Security](https://www.php.net/manual/en/security.php)
- [MySQL Security](https://dev.mysql.com/doc/refman/8.0/en/security.html)

### Tools for Testing
- **Burp Suite**: Web proxy for security testing
- **SQLmap**: Automated SQL injection tool
- **Postman**: API testing
- **curl**: Command-line HTTP tool

## ✅ Checklist

Before you start, verify:

- [ ] All required software installed
- [ ] Database created successfully
- [ ] All project files copied
- [ ] File permissions set correctly
- [ ] Services (Apache, MySQL) running
- [ ] Can access phpMyAdmin
- [ ] Can open login_demo.php in browser
- [ ] Classic SQLi injection works
- [ ] Secure version prevents injection

## 🆘 Get Help

### Check Logs

**Apache Logs (Linux/Mac):**
```bash
tail -f /var/log/apache2/error.log
tail -f /var/log/apache2/access.log
```

**MySQL Logs (Linux/Mac):**
```bash
tail -f /var/log/mysql/error.log
```

### Debug SQL

Add this to PHP files for debugging:
```php
// Add after mysqli_query()
if (!$result) {
    echo "Query error: " . mysqli_error($con);
    echo "Query: " . $sql;
}
```

## 📞 Support

If you encounter issues:

1. Check this guide's Troubleshooting section
2. Review official documentation links
3. Check error logs
4. Verify all components are running
5. Try restarting services

---

**Last Updated:** December 2024
**Version:** 2.0
