<?php
session_start();
$token = $_GET['token'] ?? '';
$is_valid = false;
$user_email = '';

if (!empty($token)) {
    try {
        $db = new PDO("sqlite:database.sqlite");
        // Check if token exists and NOT expired
        $stmt = $db->prepare("SELECT email FROM users WHERE reset_token = ? AND token_expiry > datetime('now')");
        $stmt->execute([$token]);
        $user = $stmt->fetch();

        if ($user) {
            $is_valid = true;
            $user_email = $user['email'];
        } else {
            $error = "Invalid or expired reset token. Please request a new one.";
        }
    } catch (Exception $e) {
        $error = "System error.";
    }
} else {
    header("Location: forgot_password.php");
    exit;
}

if (isset($_POST['update_password']) && $is_valid) {
    $new_pass = password_hash($_POST['password'], PASSWORD_DEFAULT);
    
    try {
        // Update password and CLEAR token
        $update = $db->prepare("UPDATE users SET password = ?, reset_token = NULL, token_expiry = NULL WHERE email = ?");
        $update->execute([$new_pass, $user_email]);
        
        $success = "Password updated successfully! You can now <a href='login.php'>Login</a>.";
        $is_valid = false; // Hide form after success
    } catch (Exception $e) {
        $error = "Failed to update password.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Reset Password - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <link rel="stylesheet" href="static/style.css">
    <style>
        .password-wrapper { position: relative; width: 100%; margin: 10px 0; }
        .password-wrapper input { width: 100%; padding: 12px; padding-right: 45px; margin: 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        .btn-reset { width: 100%; background: #10b981; color: white; border: none; padding: 12px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .msg { padding: 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
        .msg-success { background: #d1fae5; color: #065f46; border: 1px solid #10b981; }
        .msg-error { background: #fee2e2; color: #991b1b; border: 1px solid #ef4444; }
        .password-wrapper { position: relative; width: 100%; margin: 10px 0; }
        .password-wrapper input { width: 100%; padding: 12px; padding-right: 45px; margin: 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        .toggle-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6b7280;
            display: flex;
            align-items: center;
        }
    </style>
</head>
<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
        <h2>Reset Password</h2>
        
        <?php if(isset($success)) echo "<div class='msg msg-success'>$success</div>"; ?>
        <?php if(isset($error)) echo "<div class='msg msg-error'>$error</div>"; ?>

        <?php if($is_valid): ?>
            <p style="font-size: 14px; color: #4b5563;">Setting password for: <b><?php echo $user_email; ?></b></p>
            <form method="POST">
                <div class="password-wrapper">
                    <input type="password" name="password" id="new_password" placeholder="New Password" required minlength="6">
                     <span class="toggle-icon" onclick="togglePassword('new_password', this)">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-closed" style="display:none;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                    </span>
                 </div>
                 
                 <div class="password-wrapper">
                    <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm New Password" required minlength="6">
                     <span class="toggle-icon" onclick="togglePassword('confirm_password', this)">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-closed" style="display:none;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                    </span>
                </div>
                <button type="submit" name="update_password" class="btn-reset">Update Password</button>
            </form>
        <?php endif; ?>
    </div>

<script>
function togglePassword(inputId, icon) {
    const input = document.getElementById(inputId);
    const eyeOpen = icon.querySelector('.eye-open');
    const eyeClosed = icon.querySelector('.eye-closed');
    
    if (input.type === "password") {
        input.type = "text";
        eyeOpen.style.display = "none";
        eyeClosed.style.display = "block";
    } else {
        input.type = "password";
        eyeOpen.style.display = "block";
        eyeClosed.style.display = "none";
    }
}
</script>
</body>
</html>