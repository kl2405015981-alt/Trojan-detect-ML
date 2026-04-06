<?php
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Add ip_address column
    try {
        $db->exec("ALTER TABLE scans ADD COLUMN ip_address TEXT DEFAULT NULL;");
        echo "Column ip_address added successfully.\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'duplicate column name') !== false) {
            echo "Column ip_address already exists.\n";
        } else {
            throw $e;
        }
    }

    // Add pc_name column
    try {
        $db->exec("ALTER TABLE scans ADD COLUMN pc_name TEXT DEFAULT NULL;");
        echo "Column pc_name added successfully.\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'duplicate column name') !== false) {
            echo "Column pc_name already exists.\n";
        } else {
            throw $e;
        }
    }

    echo "Database structure updated successfully.\n";
} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}
?>
