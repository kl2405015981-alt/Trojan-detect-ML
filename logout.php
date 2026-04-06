<?php
// 1. Start existing session
session_start();

// 2. Clear all session data
session_unset();

// 3. Destroy session completely
session_destroy();

// 4. Redirect user to login page
header("Location: login.php?logout=success");
exit;
?>