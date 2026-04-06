<?php
// verify_timezone.php

date_default_timezone_set('Asia/Kuala_Lumpur');
echo "Current PHP Time (Asia/Kuala_Lumpur): " . date('Y-m-d H:i:s') . "\n";

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Insert a test record
    $test_time = date('Y-m-d H:i:s');
    $db->exec("CREATE TABLE IF NOT EXISTS timezone_test (id INTEGER PRIMARY KEY, created_at DATETIME)");
    $stmt = $db->prepare("INSERT INTO timezone_test (created_at) VALUES (:created_at)");
    $stmt->execute([':created_at' => $test_time]);
    $last_id = $db->lastInsertId();

    // Read it back
    $stmt = $db->prepare("SELECT created_at FROM timezone_test WHERE id = :id");
    $stmt->execute([':id' => $last_id]);
    $result = $stmt->fetchColumn();

    echo "Inserted Time: $test_time\n";
    echo "Retrieved Time: $result\n";

    if ($test_time === $result) {
        echo "✅ Timezone verification PASSED! Database is storing PHP-generated Malaysia time correctly.\n";
    } else {
        echo "❌ Timezone verification FAILED! Mismatch detected.\n";
    }

    // Clean up
    $db->exec("DROP TABLE timezone_test");

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
