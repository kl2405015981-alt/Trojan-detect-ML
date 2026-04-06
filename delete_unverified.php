<?php
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $db->prepare("DELETE FROM users WHERE is_verified = 0 AND user_type != 'admin'");
    $stmt->execute();
    $count = $stmt->rowCount();

    echo "Successfully deleted $count unverified user(s).\n";

} catch (PDOException $e) {
    echo "Database Error: " . $e->getMessage() . "\n";
}
?>
