<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrojanDetect ML - Machine Learning-Based Trojan Detection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            min-height: 100vh;
        }
        
        /* Navigation */
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 50px;
            background: rgba(30, 58, 138, 0.95);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .navbar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.3em;
            font-weight: bold;
            color: white;
            text-decoration: none;
        }
        
        .navbar-brand svg {
            width: 30px;
            height: 30px;
        }
        
        .brand-text {
            display: flex;
            flex-direction: column;
        }
        
        .brand-title {
            font-size: 1em;
            line-height: 1.2;
        }
        
        .brand-subtitle {
            font-size: 0.4em;
            opacity: 0.8;
            font-weight: normal;
        }
        
        .navbar-buttons {
            display: flex;
            gap: 15px;
        }
        
        .btn {
            padding: 10px 25px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 0.95em;
        }
        
        .btn-nav-login {
            background: transparent;
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .btn-nav-login:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: white;
        }
        
        .btn-nav-register {
            background: white;
            color: #1e3a8a;
            border: 1px solid white;
        }
        
        .btn-nav-register:hover {
            background: rgba(255, 255, 255, 0.9);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        /* Container */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 60px 20px;
        }
        
        /* Hero Section */
        .hero {
            text-align: center;
            margin-bottom: 60px;
        }
        
        .hero-icon {
            margin-bottom: 30px;
        }
        
        .shield-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
            border: 3px solid rgba(255, 255, 255, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
        }
        
        .shield-circle svg {
            width: 60px;
            height: 60px;
        }
        
        .hero h1 {
            font-size: 3em;
            margin-bottom: 20px;
            line-height: 1.2;
        }
        
        .hero p {
            font-size: 1.1em;
            opacity: 0.9;
            max-width: 700px;
            margin: 0 auto 30px;
            line-height: 1.6;
        }
        
        .hero-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
        }
        
        .btn-primary {
            background: white;
            color: #1e3a8a;
            padding: 15px 35px;
            font-size: 1.1em;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
        }
        
        .btn-secondary {
            background: transparent;
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.5);
            padding: 15px 35px;
            font-size: 1.1em;
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: white;
        }
        
        /* Features Section */
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 60px 0;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.35);
            border: 1px solid rgba(255, 255, 255, 0.45);
            border-radius: 12px;
            padding: 30px;
            text-align: left;
            transition: all 0.3s ease;
            backdrop-filter: blur(4px);
        }
        
        .feature-card:hover {
            background: rgba(255, 255, 255, 0.45);
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }
        
        .feature-icon {
            width: 50px;
            height: 50px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        
        .icon-blue { background: rgba(37, 99, 235, 0.3); }
        .icon-green { background: rgba(22, 163, 74, 0.3); }
        .icon-purple { background: rgba(147, 51, 234, 0.3); }
        
        .feature-card h3 {
            font-size: 1.3em;
            margin-bottom: 12px;
            color: white;
        }
        
        .feature-card p {
            opacity: 0.85;
            line-height: 1.6;
            font-size: 0.95em;
            color: white;
        }
        
        /* Stats Section */
        .stats {
            background: rgba(255, 255, 255, 0.35);
            border: 1px solid rgba(255, 255, 255, 0.45);
            border-radius: 12px;
            padding: 40px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 30px;
            margin: 60px 0;
            backdrop-filter: blur(4px);
        }
        
        .stat-item {
            text-align: center;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
            margin-bottom: 8px;
            color: white;
        }
        
        .stat-label {
            opacity: 0.8;
            font-size: 0.9em;
            color: white;
        }
        
        /* Why Section */
        .why-section {
            margin: 60px 0;
            text-align: center;
        }
        
        .why-section h2 {
            font-size: 2.2em;
            margin-bottom: 40px;
        }
        
        .problem-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
        }
        
        .problem-card {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            padding: 30px;
            text-align: left;
            transition: all 0.3s ease;
        }
        
        .problem-card:hover {
            transform: translateY(-5px);
        }
        
        .problem-red {
            border: 2px solid #f87171;
            background: rgba(248, 113, 113, 0.1);
        }
        
        .problem-yellow {
            border: 2px solid #fbbf24;
            background: rgba(251, 191, 36, 0.1);
        }
        
        .problem-icon {
            width: 40px;
            height: 40px;
            margin-bottom: 15px;
        }
        
        .problem-card h4 {
            font-size: 1.2em;
            margin-bottom: 12px;
        }
        
        .problem-red h4 { color: #fca5a5; }
        .problem-yellow h4 { color: #fcd34d; }
        
        .problem-card p {
            opacity: 0.85;
            line-height: 1.6;
        }
        
        /* CTA Section */
        .cta {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 50px 30px;
            text-align: center;
            margin: 60px 0;
        }
        
        .cta h2 {
            font-size: 2em;
            margin-bottom: 15px;
        }
        
        .cta p {
            opacity: 0.9;
            margin-bottom: 30px;
            font-size: 1.05em;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px 20px;
            opacity: 0.7;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .navbar {
                padding: 15px 20px;
            }
            
            .hero h1 {
                font-size: 2em;
            }
            
            .hero-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                padding: 12px 30px;
            }
            
            .stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <a href="home.php" class="navbar-brand">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <div class="brand-text">
                <span class="brand-title">TrojanDetect ML</span>
                <span class="brand-subtitle">Machine Learning-Based Trojan Detection</span>
            </div>
        </a>
        <div class="navbar-buttons">
            <a href="login.php" class="btn btn-nav-login">Login</a>
            <a href="register.php" class="btn btn-nav-register">Register</a>
        </div>
    </nav>

    <!-- Main Container -->
    <div class="container">
        <!-- Hero Section -->
        <div class="hero">
            <div class="hero-icon">
                <div class="shield-circle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
            </div>
            <h1>Protect Your System from<br>Trojan Malware</h1>
            <p>Advanced Machine Learning-powered trojan detection system that scans Windows files before execution. Detect new and modified trojans with high accuracy.</p>
            <div class="hero-buttons">
                <a href="register.php" class="btn btn-primary">Get Started Free</a>
                <a href="login.php" class="btn btn-secondary">Login to Dashboard</a>
            </div>
        </div>

        <!-- Features Section -->
        <div class="features">
            <div class="feature-card">
                <div class="feature-icon icon-blue">
                    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2">
                        <rect x="4" y="4" width="16" height="16" rx="2" ry="2"/>
                        <rect x="9" y="9" width="6" height="6"/>
                        <line x1="9" y1="1" x2="9" y2="4"/>
                        <line x1="15" y1="1" x2="15" y2="4"/>
                        <line x1="9" y1="20" x2="9" y2="23"/>
                        <line x1="15" y1="20" x2="15" y2="23"/>
                        <line x1="20" y1="9" x2="23" y2="9"/>
                        <line x1="20" y1="14" x2="23" y2="14"/>
                        <line x1="1" y1="9" x2="4" y2="9"/>
                        <line x1="1" y1="14" x2="4" y2="14"/>
                    </svg>
                </div>
                <h3>ML-Powered Detection</h3>
                <p>Advanced machine learning algorithms detect new and modified trojans that traditional antivirus cannot identify.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon icon-green">
                    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                </div>
                <h3>Pre-Execution Scanning</h3>
                <p>Scans files BEFORE opening to prevent trojan execution and protect your system in real-time.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon icon-purple">
                    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#9333ea" stroke-width="2">
                        <line x1="18" y1="20" x2="18" y2="10"/>
                        <line x1="12" y1="20" x2="12" y2="4"/>
                        <line x1="6" y1="20" x2="6" y2="14"/>
                    </svg>
                </div>
                <h3>97.3% Accuracy</h3>
                <p>Validated detection accuracy with proper metrics including precision, recall, and F1-score measurements.</p>
            </div>
        </div>

        <!-- Stats Section -->
        <div class="stats">
            <div class="stat-item">
                <span class="stat-number">50K+</span>
                <span class="stat-label">Malware Samples</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">97.3%</span>
                <span class="stat-label">Detection Accuracy</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">1.2s</span>
                <span class="stat-label">Avg Scan Time</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">156</span>
                <span class="stat-label">Active Users</span>
            </div>
        </div>

        <!-- Why Section -->
        <div class="why-section">
            <h2>Why TrojanDetect ML?</h2>
            <div class="problem-grid">
                <div class="problem-card problem-red">
                    <svg class="problem-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <!-- Shield-Off: broken/failed shield -->
                        <path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/>
                        <path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/>
                        <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                    <h4>Traditional Limitations</h4>
                    <p>Signature-based antivirus cannot detect new or modified trojans, leaving systems vulnerable.</p>
                </div>

                <div class="problem-card problem-yellow">
                    <svg class="problem-icon" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <!-- Clock: too late, already executed before scan -->
                        <circle cx="12" cy="12" r="10"/>
                        <polyline points="12 6 12 12 16 14"/>
                        <line x1="12" y1="2" x2="12" y2="4"/>
                    </svg>
                    <h4>No Pre-Scan Protection</h4>
                    <p>Most solutions scan files already in execution, allowing trojans to execute and compromise systems.</p>
                </div>

                <div class="problem-card problem-yellow">
                    <svg class="problem-icon" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <!-- Bar chart with X cross: no metrics/validation -->
                        <line x1="18" y1="20" x2="18" y2="10"/>
                        <line x1="12" y1="20" x2="12" y2="4"/>
                        <line x1="6" y1="20" x2="6" y2="14"/>
                        <line x1="3" y1="20" x2="21" y2="20"/>
                        <line x1="1" y1="1" x2="7" y2="7"/>
                        <line x1="7" y1="1" x2="1" y2="7"/>
                    </svg>
                    <h4>Lack of Validation</h4>
                    <p>Existing systems lack proper measurement and validation metrics for detection results.</p>
                </div>
            </div>
        </div>

        <!-- CTA Section -->
        <div class="cta">
            <h2>Ready to Protect Your System?</h2>
            <p>Join students and lecturers using TrojanDetect ML for advanced malware protection</p>
            <a href="register.php" class="btn btn-primary">Create Free Account</a>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>© 2026 TrojanDetect ML. Machine Learning-Based Trojan Horse Detection System.</p>
    </div>
</body>
</html>