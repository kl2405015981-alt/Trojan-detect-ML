<?php
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Add is_verified and verification_token columns to users table
    try {
        $db->exec("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0");
        echo "Successfully added 'is_verified' column.\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'duplicate column name') !== false) {
            echo "'is_verified' column already exists.\n";
        } else {
            echo "Error adding 'is_verified': " . $e->getMessage() . "\n";
        }
    }

    try {
        $db->exec("ALTER TABLE users ADD COLUMN verification_token TEXT");
        echo "Successfully added 'verification_token' column.\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'duplicate column name') !== false) {
            echo "'verification_token' column already exists.\n";
        } else {
            echo "Error adding 'verification_token': " . $e->getMessage() . "\n";
        }
    }

} catch (PDOException $e) {
    die("Database Connection Failed: " . $e->getMessage());
}
?>
