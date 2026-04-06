<?php
// Test file untuk diagnose masalah
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>Testing Admin Manage User Page</h1>";
echo "<hr>";

// Test 1: Session
session_start();
echo "<h2>1. Session Test</h2>";
echo "Session ID: " . session_id() . "<br>";
echo "Session data: <pre>" . print_r($_SESSION, true) . "</pre>";

// Test 2: Database Connection
echo "<h2>2. Database Connection Test</h2>";
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "✅ Database connection successful<br>";
    
    // Test query
    $total = $db->query("SELECT count(*) FROM users")->fetchColumn();
    echo "✅ Total users in database: " . $total . "<br>";
    
} catch (PDOException $e) {
    echo "❌ Database error: " . $e->getMessage() . "<br>";
}

// Test 3: Check if user is logged in as admin
echo "<h2>3. Authentication Test</h2>";
if (!isset($_SESSION['is_logged_in'])) {
    echo "❌ User NOT logged in<br>";
    echo "➡️ You need to login first at: <a href='login.php'>login.php</a><br>";
} else {
    echo "✅ User is logged in<br>";
    echo "User type: " . ($_SESSION['user_type'] ?? 'not set') . "<br>";
    
    if ($_SESSION['user_type'] !== 'admin') {
        echo "❌ User is NOT admin (user_type: " . $_SESSION['user_type'] . ")<br>";
        echo "➡️ You need to login as admin<br>";
    } else {
        echo "✅ User is admin - access granted!<br>";
        echo "➡️ <a href='admin_manageuser.php'>Go to Admin Manage Users page</a><br>";
    }
}
?>
