<?php
// reset_db.php - ULTIMATE VERSION (9 Tables for FYP)
// PROTECTED: Requires secret token to run.
// Usage: http://localhost/trojan_detection/reset_db.php?token=RESET_SECRET_2025

// ── SECURITY GUARD ──────────────────────────────────────────────
$secret_token = 'RESET_SECRET_2025'; // Change this to something unique!
if (!isset($_GET['token']) || $_GET['token'] !== $secret_token) {
    http_response_code(403);
    die("<div style='font-family:sans-serif;text-align:center;padding:50px;color:#991b1b;background:#fee2e2;border:1px solid #fca5a5;border-radius:12px;max-width:500px;margin:80px auto;'>
        <h2>🚫 Access Denied</h2>
        <p>This page requires a valid secret token to run.<br>Direct access is not allowed.</p>
    </div>");
}
// ────────────────────────────────────────────────────────────────

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 1. Drop old tables
    $db->exec("PRAGMA foreign_keys = OFF;");
    $db->exec("DROP TABLE IF EXISTS audit_history;");
    $db->exec("DROP TABLE IF EXISTS threat_logs;");
    $db->exec("DROP TABLE IF EXISTS reports;"); // Ensure this is dropped if exists
    $db->exec("DROP TABLE IF EXISTS scans;");
    $db->exec("DROP TABLE IF EXISTS ml_models;");
    $db->exec("DROP TABLE IF EXISTS files;");
    $db->exec("DROP TABLE IF EXISTS password_resets;");
    $db->exec("DROP TABLE IF EXISTS users;");
    $db->exec("PRAGMA foreign_keys = ON;");

    // 2. Table: User
    $db->exec("CREATE TABLE users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT, email TEXT UNIQUE, password TEXT, user_type TEXT, status TEXT DEFAULT 'Active', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");

    // 3. Table: Files
    $db->exec("CREATE TABLE files (file_id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT, file_path TEXT, file_hash TEXT, file_type TEXT, file_size INTEGER, upload_date DATETIME DEFAULT CURRENT_TIMESTAMP)");

    // 4. Table: ML Models
    $db->exec("CREATE TABLE ml_models (model_id INTEGER PRIMARY KEY AUTOINCREMENT, model_name TEXT, algorithm TEXT, accuracy REAL, is_active INTEGER DEFAULT 0)");

    // 5. Table: Scans
    $db->exec("CREATE TABLE scans (scan_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, file_id INTEGER, model_id INTEGER, file_name TEXT, file_size INTEGER, scan_result TEXT, accuracy_score REAL, scan_date DATETIME DEFAULT CURRENT_TIMESTAMP, ip_address TEXT, pc_name TEXT)");

    // 6. Table: Reports (REQUIRED BY api_upload.php)
    $db->exec("CREATE TABLE reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_id INTEGER NOT NULL, 
        scan_id INTEGER NOT NULL, 
        report_path TEXT, 
        generated_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
    )");

    // 7. Other tables
    $db->exec("CREATE TABLE threat_logs (log_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, threat_name TEXT, severity_level TEXT, action_taken TEXT, detected_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $db->exec("CREATE TABLE audit_history (history_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $db->exec("CREATE TABLE password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, token TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");

    // 8. Seeding Default Admin
    $admin_pass = password_hash('admin123', PASSWORD_DEFAULT);
    $db->prepare("INSERT INTO users (full_name, email, password, user_type, status) VALUES (?, ?, ?, ?, ?)")
       ->execute(['Administrator', 'admin@gmail.com', $admin_pass, 'admin', 'Active']);

    $db->prepare("INSERT INTO ml_models (model_name, algorithm, accuracy, is_active) VALUES (?, ?, ?, ?)")
       ->execute(['TrojanDetector v2.5', 'Random Forest', 94.5, 1]);

    echo "<div style='font-family:sans-serif; text-align:center; padding:50px; background:#f0fdf4; color:#166534; border:1px solid #bbf7d0; border-radius:12px; max-width:600px; margin:50px auto;'>";
    echo "<h2>✅ 9-Table Database Setup Completed!</h2>";
    echo "<p>Table <b>reports</b> has been successfully created. You can perform scans now.</p>";
    echo "<a href='login.php' style='color:#2563eb; font-weight:bold;'>Login Again</a>";
    echo "</div>";

} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}
?>
