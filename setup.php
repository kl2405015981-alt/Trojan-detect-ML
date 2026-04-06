<?php
// PROTECTED: Requires secret token to run.
// Usage: http://localhost/trojan_detection/setup.php?token=RESET_SECRET_2025

// ── SECURITY GUARD ──────────────────────────────────────────────
$secret_token = 'RESET_SECRET_2025';
if (!isset($_GET['token']) || $_GET['token'] !== $secret_token) {
    http_response_code(403);
    die("<div style='font-family:sans-serif;text-align:center;padding:50px;color:#991b1b;background:#fee2e2;border:1px solid #fca5a5;border-radius:12px;max-width:500px;margin:80px auto;'>
        <h2>🚫 Access Denied</h2>
        <p>This page requires a valid secret token to run.<br>Direct access is not allowed.</p>
    </div>");
}
// ────────────────────────────────────────────────────────────────
$db = new PDO("sqlite:database.sqlite");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Drop and recreate users table for "reset"
$db->exec("DROP TABLE IF EXISTS users");
$db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");

// Insert official admin account
$email = "admin@gmail.com";
$pass = password_hash("admin123", PASSWORD_DEFAULT);
$db->prepare("INSERT INTO users (username, password) VALUES (?, ?)")->execute([$email, $pass]);

echo "✅ Users database has been reset! Please login using admin@gmail.com and password admin123";
?>