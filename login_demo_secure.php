<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Testing Lab - MySQL Security Demo</title>
    <style>
        :root {
            --primary-color: #00d9ff;
            --secondary-color: #0066ff;
            --danger-color: #ff3366;
            --success-color: #00ff88;
            --warning-color: #ffaa00;
            --dark-bg: #0a0e1a;
            --darker-bg: #050810;
            --card-bg: rgba(15, 23, 42, 0.8);
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--darker-bg);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        /* Animated Matrix-style Background */
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            overflow: hidden;
            background: linear-gradient(135deg, #0a0e1a 0%, #1a1f35 100%);
        }

        .matrix-bg::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background-image: 
                repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 217, 255, 0.03) 2px, rgba(0, 217, 255, 0.03) 4px),
                repeating-linear-gradient(90deg, transparent, transparent 2px, rgba(0, 217, 255, 0.03) 2px, rgba(0, 217, 255, 0.03) 4px);
            animation: matrix-scroll 20s linear infinite;
        }

        @keyframes matrix-scroll {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }

        /* Floating Database Icons */
        .floating-icons {
            position: fixed;
            width: 100%;
            height: 100%;
            z-index: 1;
            pointer-events: none;
        }

        .db-icon {
            position: absolute;
            font-size: 40px;
            opacity: 0.1;
            animation: float 15s ease-in-out infinite;
        }

        .db-icon:nth-child(1) { left: 10%; top: 20%; animation-delay: 0s; }
        .db-icon:nth-child(2) { left: 80%; top: 40%; animation-delay: 3s; }
        .db-icon:nth-child(3) { left: 15%; top: 70%; animation-delay: 6s; }
        .db-icon:nth-child(4) { left: 70%; top: 15%; animation-delay: 9s; }
        .db-icon:nth-child(5) { left: 45%; top: 85%; animation-delay: 12s; }

        @keyframes float {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            25% { transform: translateY(-30px) rotate(5deg); }
            50% { transform: translateY(-60px) rotate(-5deg); }
            75% { transform: translateY(-30px) rotate(5deg); }
        }

        /* Main Container */
        .container {
            position: relative;
            z-index: 10;
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 40px;
            animation: slideDown 0.8s ease-out;
        }

        @keyframes slideDown {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .header h1 {
            font-size: 3rem;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            text-shadow: 0 0 30px rgba(0, 217, 255, 0.3);
        }

        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        .warning-badge {
            display: inline-block;
            background: rgba(255, 51, 102, 0.2);
            border: 2px solid var(--danger-color);
            color: var(--danger-color);
            padding: 8px 20px;
            border-radius: 20px;
            margin-top: 15px;
            font-weight: 600;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 10px rgba(255, 51, 102, 0.3); }
            50% { box-shadow: 0 0 25px rgba(255, 51, 102, 0.6); }
        }

        /* Main Content Grid */
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }

        @media (max-width: 968px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Login Card */
        .login-card {
            background: var(--card-bg);
            border: 1px solid rgba(0, 217, 255, 0.3);
            border-radius: 20px;
            padding: 40px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 50px rgba(0, 0, 0, 0.5);
            animation: slideInLeft 0.8s ease-out;
            position: relative;
            overflow: hidden;
        }

        .login-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0, 217, 255, 0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        @keyframes slideInLeft {
            from { transform: translateX(-100px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .card-header {
            position: relative;
            z-index: 1;
            text-align: center;
            margin-bottom: 30px;
        }

        .card-header h2 {
            font-size: 2rem;
            color: var(--primary-color);
            margin-bottom: 10px;
        }

        .mysql-logo {
            width: 120px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, #00758f, #00d9ff);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: bold;
            color: white;
            box-shadow: 0 5px 20px rgba(0, 217, 255, 0.4);
            animation: logoGlow 2s ease-in-out infinite;
        }

        @keyframes logoGlow {
            0%, 100% { box-shadow: 0 5px 20px rgba(0, 217, 255, 0.4); }
            50% { box-shadow: 0 5px 40px rgba(0, 217, 255, 0.8); }
        }

        .form-group {
            position: relative;
            z-index: 1;
            margin-bottom: 25px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .input-wrapper {
            position: relative;
        }

        .input-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.2rem;
            color: var(--primary-color);
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 15px 15px 15px 50px;
            background: rgba(15, 23, 42, 0.6);
            border: 2px solid rgba(0, 217, 255, 0.3);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 20px rgba(0, 217, 255, 0.3);
        }

        .btn {
            position: relative;
            z-index: 1;
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            box-shadow: 0 5px 20px rgba(0, 217, 255, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0, 217, 255, 0.6);
        }

        .btn-danger {
            background: linear-gradient(135deg, var(--danger-color), #ff6666);
            color: white;
            margin-top: 10px;
            box-shadow: 0 5px 20px rgba(255, 51, 102, 0.4);
        }

        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(255, 51, 102, 0.6);
        }

        /* Info Panel */
        .info-panel {
            background: var(--card-bg);
            border: 1px solid rgba(255, 170, 0, 0.3);
            border-radius: 20px;
            padding: 40px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 50px rgba(0, 0, 0, 0.5);
            animation: slideInRight 0.8s ease-out;
        }

        @keyframes slideInRight {
            from { transform: translateX(100px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .info-panel h3 {
            color: var(--warning-color);
            font-size: 1.5rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .injection-examples {
            margin-top: 20px;
        }

        .example {
            background: rgba(255, 170, 0, 0.1);
            border-left: 4px solid var(--warning-color);
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.95rem;
        }

        .example-label {
            color: var(--warning-color);
            font-weight: 600;
            margin-bottom: 5px;
        }

        .example-code {
            color: var(--text-primary);
            background: rgba(0, 0, 0, 0.3);
            padding: 8px;
            border-radius: 5px;
            margin-top: 5px;
            overflow-x: auto;
        }

        /* Database Info */
        .db-info {
            background: var(--card-bg);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 20px;
            padding: 30px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 50px rgba(0, 0, 0, 0.5);
            animation: fadeIn 1s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .db-info h3 {
            color: var(--success-color);
            font-size: 1.5rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .db-details {
            display: grid;
            gap: 15px;
        }

        .db-detail-item {
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid rgba(0, 255, 136, 0.2);
            padding: 15px;
            border-radius: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .db-label {
            color: var(--text-secondary);
            font-weight: 600;
        }

        .db-value {
            color: var(--success-color);
            font-family: 'Courier New', monospace;
            font-weight: 600;
        }

        /* Success Screen */
        .success-screen {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .success-content {
            text-align: center;
            animation: zoomIn 0.8s ease-out;
        }

        @keyframes zoomIn {
            from { transform: scale(0.5); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }

        .success-icon {
            font-size: 8rem;
            margin-bottom: 30px;
            animation: bounce 1s ease-in-out infinite;
        }

        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }

        .success-title {
            font-size: 4rem;
            background: linear-gradient(135deg, var(--success-color), var(--primary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
            font-weight: 700;
            text-shadow: 0 0 50px rgba(0, 255, 136, 0.5);
        }

        .success-message {
            font-size: 1.5rem;
            color: var(--text-secondary);
            margin-bottom: 30px;
        }

        .admin-panel {
            background: var(--card-bg);
            border: 2px solid var(--success-color);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            margin: 0 auto;
            box-shadow: 0 0 50px rgba(0, 255, 136, 0.3);
        }

        .admin-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-top: 20px;
        }

        .stat-box {
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid rgba(0, 255, 136, 0.3);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .stat-value {
            font-size: 2.5rem;
            color: var(--success-color);
            font-weight: 700;
        }

        .stat-label {
            color: var(--text-secondary);
            margin-top: 10px;
        }

        /* Alert Messages */
        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            animation: slideIn 0.5s ease-out;
            position: relative;
            z-index: 1;
        }

        @keyframes slideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .alert-error {
            background: rgba(255, 51, 102, 0.2);
            border: 1px solid var(--danger-color);
            color: var(--danger-color);
        }

        .alert-success {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid var(--success-color);
            color: var(--success-color);
        }

        .sql-display {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(0, 217, 255, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            position: relative;
            z-index: 1;
        }

        .sql-label {
            color: var(--primary-color);
            font-weight: 600;
            margin-bottom: 10px;
        }

        .sql-code {
            color: var(--success-color);
            line-height: 1.6;
        }

        .vulnerability-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 51, 102, 0.2);
            border: 1px solid var(--danger-color);
            color: var(--danger-color);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            margin-top: 10px;
            animation: blink 1.5s ease-in-out infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Creator Badge */
        .creator-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 2000;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            padding: 12px 25px;
            border-radius: 10px;
            font-weight: 700;
            font-size: 1.1rem;
            color: white;
            box-shadow: 0 5px 25px rgba(0, 217, 255, 0.5);
            animation: creatorGlow 2s ease-in-out infinite;
            letter-spacing: 1px;
        }

        @keyframes creatorGlow {
            0%, 100% { 
                box-shadow: 0 5px 25px rgba(0, 217, 255, 0.5);
                transform: scale(1);
            }
            50% { 
                box-shadow: 0 8px 35px rgba(0, 217, 255, 0.8);
                transform: scale(1.05);
            }
        }

        /* Team Logo */
        .team-logo {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 2000;
            width: 280px;
            height: 280px;
            border-radius: 15px;
            box-shadow: 0 5px 30px rgba(0, 217, 255, 0.6);
            animation: logoFloat 3s ease-in-out infinite;
            border: 3px solid var(--primary-color);
            background: rgba(10, 14, 26, 0.8);
            backdrop-filter: blur(10px);
            overflow: hidden;
        }

        .team-logo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        @keyframes logoFloat {
            0%, 100% { 
                transform: translateY(0);
                box-shadow: 0 5px 30px rgba(0, 217, 255, 0.6);
            }
            50% { 
                transform: translateY(-10px);
                box-shadow: 0 10px 40px rgba(0, 217, 255, 0.9);
            }
        }

        @media (max-width: 768px) {
            .creator-badge {
                top: 10px;
                left: 10px;
                padding: 8px 15px;
                font-size: 0.9rem;
            }

            .team-logo {
                top: 10px;
                right: 10px;
                width: 150px;
                height: 150px;
            }
        }
    </style>
</head>
<body>

    </div>
    <div class="creator-badge">CREATED BY ATARFU TEAM</div>
    <div class="matrix-bg"></div>
    
    <div class="floating-icons">
        <div class="db-icon">🗄️</div>
        <div class="db-icon">🔒</div>
        <div class="db-icon">💾</div>
        <div class="db-icon">🛡️</div>
        <div class="db-icon">🔐</div>
    </div>

    <div class="container">
        <div class="header">
            <h1>🔓 SQL Injection Testing Lab</h1>
            <p class="subtitle">MySQL Security Demonstration & Educational Tool</p>
            <span class="warning-badge">⚠️ FOR EDUCATIONAL PURPOSES ONLY</span>
        </div>

        <div class="content-grid">
            <div class="login-card">
                <div class="card-header">
                    <div class="mysql-logo">MySQL</div>
                    <h2>Admin Login Portal</h2>
                    <p style="color: var(--text-secondary); margin-top: 10px;">Database: <span style="color: var(--primary-color);">testdb</span></p>
                </div>

                <div id="alertContainer"></div>

                <form id="loginForm">
                    <div class="form-group">
                        <label>👤 Username</label>
                        <div class="input-wrapper">
                            <span class="input-icon">👤</span>
                            <input type="text" id="username" placeholder="Enter username or try SQL injection..." autocomplete="off">
                        </div>
                    </div>

                    <div class="form-group">
                        <label>🔑 Password</label>
                        <div class="input-wrapper">
                            <span class="input-icon">🔑</span>
                            <input type="password" id="password" placeholder="Enter password or try SQL injection..." autocomplete="off">
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        🚀 Login to System
                    </button>
                    
                    <button type="button" class="btn btn-danger" onclick="tryInjection()">
                        💉 Try SQL Injection Attack
                    </button>
                </form>

                <div id="sqlDisplay" style="display: none;" class="sql-display">
                    <div class="sql-label">📝 Executed SQL Query:</div>
                    <div class="sql-code" id="sqlCode"></div>
                    <span class="vulnerability-indicator">
                        ⚠️ VULNERABLE TO SQL INJECTION
                    </span>
                </div>
            </div>

            <div class="info-panel">
                <h3>⚡ SQL Injection Examples</h3>
                <p style="color: var(--text-secondary); margin-bottom: 20px;">
                    Try these payloads to bypass authentication:
                </p>

                <div class="injection-examples">
                    <div class="example">
                        <div class="example-label">1️⃣ Classic OR Attack</div>
                        <div class="example-code">Username: admin' OR '1'='1<br>Password: anything</div>
                    </div>

                    <div class="example">
                        <div class="example-label">2️⃣ Comment-based Bypass</div>
                        <div class="example-code">Username: admin'--<br>Password: (leave empty)</div>
                    </div>

                    <div class="example">
                        <div class="example-label">3️⃣ Always True Condition</div>
                        <div class="example-code">Username: ' OR 1=1--<br>Password: anything</div>
                    </div>

                    <div class="example">
                        <div class="example-label">4️⃣ UNION Attack</div>
                        <div class="example-code">Username: admin' UNION SELECT 'admin','pass'--<br>Password: pass</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="db-info">                <h3>🗄️ Database Configuration</h3>
            <div class="db-details">
                <div class="db-detail-item">
                    <span class="db-label">Database Name:</span>
                    <span class="db-value">testdb</span>
                </div>
                <div class="db-detail-item">
                    <span class="db-label">Default Username:</span>
                    <span class="db-value">admin</span>
                </div>
                <div class="db-detail-item">
                    <span class="db-label">Default Password:</span>
                    <span class="db-value">adminpass</span>
                </div>
                <div class="db-detail-item">
                    <span class="db-label">Vulnerability Status:</span>
                    <span class="db-value" style="color: var(--success-color);">✅ PROTECTED</span>
                </div>
                <div class="db-detail-item">
                    <span class="db-label">Protection Level:</span>
                    <span class="db-value" style="color: var(--success-color);">🛡️ FULLY SANITIZED</span>
                </div>
            </div>
        </div>
    </div>

    <div class="success-screen" id="successScreen">
        <div class="success-content">
            <div class="success-icon">✅</div>
            <h1 class="success-title">WELCOME ADMIN!</h1>
            <p class="success-message">🎉 Successfully Authenticated</p>
            
            <div class="admin-panel">
                <h3 style="color: var(--success-color); text-align: center; margin-bottom: 20px;">
                    🎯 Admin Dashboard Access Granted
                </h3>
                <div class="admin-stats">
                    <div class="stat-box">
                        <div class="stat-value">1,247</div>
                        <div class="stat-label">Total Users</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">98%</div>
                        <div class="stat-label">System Health</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">5.2GB</div>
                        <div class="stat-label">Database Size</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">24/7</div>
                        <div class="stat-label">Uptime</div>
                    </div>
                </div>
                <button class="btn btn-primary" style="margin-top: 30px;" onclick="closeSuccess()">
                    🔙 Back to Login
                </button>
            </div>
        </div>
    </div>

    <script>
        // Simulated user database
        const users = {
            'admin': 'adminpass'
        };            // Sanitization function to prevent SQL injection
        function sanitizeInput(input) {
            // Remove dangerous SQL characters and keywords
            return input
                .replace(/'/g, "''")  // Escape single quotes (parameterized style)
                .replace(/--/g, '')   // Remove SQL comments
                .replace(/;/g, '')    // Remove statement terminators
                .replace(/#/g, '')    // Remove hash comments
                .replace(/\/\*/g, '') // Remove multi-line comment start
                .replace(/\*\//g, '') // Remove multi-line comment end
                .trim();
        }

        // Validate input - only allow alphanumeric and basic characters
        function validateInput(input) {
            // Allow letters, numbers, spaces, and basic punctuation only
            const validPattern = /^[a-zA-Z0-9\s\-_.@]+$/;
            return validPattern.test(input);
        }

        // Handle form submission
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            let username = document.getElementById('username').value;
            let password = document.getElementById('password').value;

            // Clear previous alerts
            document.getElementById('alertContainer').innerHTML = '';

            // Check for SQL injection patterns BEFORE sanitization
            const injectionPatterns = [
                /'/i,
                /--/i,
                /OR.*=/i,
                /UNION/i,
                /SELECT/i,
                /1=1/i,
                /;/i,
                /#/i,
                /\/\*/i,
                /\*\//i
            ];

            let injectionAttempted = injectionPatterns.some(pattern => 
                pattern.test(username) || pattern.test(password)
            );

            // Display detection message if injection was attempted
            if (injectionAttempted) {
                showAlert('🛡️ SQL Injection attempt detected and blocked! Input sanitized.', 'error');
            }

            // Sanitize and validate inputs
            username = sanitizeInput(username);
            password = sanitizeInput(password);

            // Additional validation
            if (!validateInput(username) || !validateInput(password)) {
                showAlert('❌ Invalid characters detected. Only alphanumeric characters allowed.', 'error');
                document.getElementById('sqlDisplay').style.display = 'none';
                return;
            }

            // Construct SAFE parameterized SQL query (for demonstration)
            const sqlQuery = `SELECT * FROM users WHERE username=? AND password=?`;
            const paramInfo = `\nParameters: ['${username}', '${password}']`;
            
            // Display the SAFE SQL query
            document.getElementById('sqlDisplay').style.display = 'block';
            document.getElementById('sqlCode').textContent = sqlQuery + paramInfo;
            
            // Update vulnerability indicator
            const vulnIndicator = document.querySelector('.vulnerability-indicator');
            vulnIndicator.innerHTML = '✅ PROTECTED WITH PARAMETERIZED QUERY';
            vulnIndicator.style.borderColor = 'var(--success-color)';
            vulnIndicator.style.color = 'var(--success-color)';
            vulnIndicator.style.background = 'rgba(0, 255, 136, 0.2)';
            vulnIndicator.style.animation = 'none';

            // Check credentials (only exact match works now)
            if (users[username] && users[username] === password) {
                // Legitimate login with correct credentials
                showSuccess(false);
            } else {
                // Invalid credentials - SQL injection cannot bypass
                showAlert('❌ Invalid username or password! SQL injection blocked.', 'error');
            }
        });

        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            document.getElementById('alertContainer').appendChild(alertDiv);
        }

        function showSuccess(isInjection = false) {
            if (isInjection) {
                showAlert('✅ SQL Injection successful! Authentication bypassed!', 'success');
            } else {
                showAlert('✅ Login successful! Welcome Admin!', 'success');
            }
            
            // Show success screen after delay
            setTimeout(() => {
                document.getElementById('successScreen').style.display = 'flex';
                // Update welcome message based on login type
                const welcomeMsg = document.querySelector('.success-message');
                if (isInjection) {
                    welcomeMsg.textContent = '⚠️ Bypassed via SQL Injection';
                    welcomeMsg.style.color = 'var(--warning-color)';
                } else {
                    welcomeMsg.textContent = '🎉 Successfully Authenticated';
                    welcomeMsg.style.color = 'var(--text-secondary)';
                }
            }, 1000);
        }

        function closeSuccess() {
            document.getElementById('successScreen').style.display = 'none';
            document.getElementById('loginForm').reset();
            document.getElementById('alertContainer').innerHTML = '';
            document.getElementById('sqlDisplay').style.display = 'none';
        }

        function tryInjection() {
            document.getElementById('username').value = "admin' OR '1'='1";
            document.getElementById('password').value = "anything";
            
            showAlert('💉 Attempting SQL injection attack...', 'error');
            
            // Trigger form submission after short delay
            setTimeout(() => {
                document.getElementById('loginForm').dispatchEvent(new Event('submit'));
            }, 500);
        }

        // Add typing effect for placeholder
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');

        usernameInput.addEventListener('focus', function() {
            this.style.borderColor = 'var(--primary-color)';
        });

        passwordInput.addEventListener('focus', function() {
            this.style.borderColor = 'var(--primary-color)';
        });

        // Add real-time SQL query preview
        usernameInput.addEventListener('input', updateSQLPreview);
        passwordInput.addEventListener('input', updateSQLPreview);

        function updateSQLPreview() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            if (username || password) {
                const sqlQuery = `SELECT * FROM users WHERE username=? AND password=?`;
                const paramInfo = `\nParameters: ['${sanitizeInput(username)}', '${sanitizeInput(password)}']`;
                document.getElementById('sqlDisplay').style.display = 'block';
                document.getElementById('sqlCode').textContent = sqlQuery + paramInfo;
                
                // Update indicator for preview
                const vulnIndicator = document.querySelector('.vulnerability-indicator');
                vulnIndicator.innerHTML = '✅ PROTECTED WITH PARAMETERIZED QUERY';
                vulnIndicator.style.borderColor = 'var(--success-color)';
                vulnIndicator.style.color = 'var(--success-color)';
                vulnIndicator.style.background = 'rgba(0, 255, 136, 0.2)';
                vulnIndicator.style.animation = 'none';
            }
        }
    </script>
</body>
</html>