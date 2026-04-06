<?php
// This file only needs to be run ONCE to update existing database
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Add columns for reset token and expiry to users table
    // We use 'ALTER TABLE' so existing user data is not lost
    $db->exec("ALTER TABLE users ADD COLUMN reset_token TEXT DEFAULT NULL");
    $db->exec("ALTER TABLE users ADD COLUMN token_expiry DATETIME DEFAULT NULL");

    echo "✅ Database updated successfully! Columns 'reset_token' and 'token_expiry' added.";
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage();
}
?>