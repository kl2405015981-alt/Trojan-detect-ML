<?php
session_start();

$message = "";
$message_type = "error"; // "error" or "success"

if (isset($_GET['email']) && isset($_GET['token'])) {
    $email = $_GET['email'];
    $token = $_GET['token'];

    try {
        $db = new PDO("sqlite:database.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if user exists with the given token
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ? AND verification_token = ? LIMIT 1");
        $stmt->execute([$email, $token]);
        $user = $stmt->fetch();

        if ($user) {
            if ($user['is_verified'] == 1) {
                $message = "Your email is already verified. You can now login.";
                $message_type = "success";
            } else {
                // Update user to verified
                $update_stmt = $db->prepare("UPDATE users SET is_verified = 1 WHERE user_id = ?"); 
                $update_stmt->execute([$user['user_id'] ?? $user['id']]);

                $message = "Email successfully verified! You can now login to your account.";
                $message_type = "success";
            }
        } else {
            $message = "Invalid verification link or the link has expired.";
            $message_type = "error";
        }
    } catch (PDOException $e) {
        $message = "Error connecting to database: " . $e->getMessage();
        $message_type = "error";
    }
} else {
    $message = "Invalid request. Missing email or verification token.";
    $message_type = "error";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Email - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
</head>
<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card" style="text-align: center;">
            <div class="auth-header">
                <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="#2563eb" style="width:50px; height:50px; margin: 0 auto;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <h1>Email Verification</h1>
            </div>

            <div class="auth-form-container" style="margin-top: 20px;">
                <?php if ($message_type === "success"): ?>
                    <div style="color: #155724; background: #d4edda; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #c3e6cb;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width: 48px; height: 48px; margin-bottom: 10px; color: #28a745;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <h3 style="margin-top: 0;">Verified!</h3>
                        <p><?php echo htmlspecialchars($message); ?></p>
                        <a href="login.php" class="btn-full" style="display: inline-block; padding: 10px 20px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px; margin-top: 15px; width: auto;">Go to Login</a>
                    </div>
                <?php else: ?>
                    <div style="color: #721c24; background: #f8d7da; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #f5c6cb;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width: 48px; height: 48px; margin-bottom: 10px; color: #dc3545;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <h3 style="margin-top: 0;">Verification Failed</h3>
                        <p><?php echo htmlspecialchars($message); ?></p>
                        <a href="login.php" class="btn-full" style="display: inline-block; padding: 10px 20px; background-color: #6c757d; color: white; text-decoration: none; border-radius: 5px; margin-top: 15px; width: auto;">Return to Login</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
