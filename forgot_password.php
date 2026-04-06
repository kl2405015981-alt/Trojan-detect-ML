<?php
session_start();

// 1. Database Connection & Auto-Create Table
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Build password_resets table if not exists
    $db->exec("CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}

$step = 1; 
$error = ""; 
$success = "";

// 2. Step-by-Step Process Logic
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    // PHASE 1: CHECK EMAIL & GENERATE TOKEN
    if (isset($_POST['request_reset'])) {
        $email = trim($_POST['email']);
        
        $user = $db->prepare("SELECT * FROM users WHERE email = ?");
        $user->execute([$email]);
        
        if ($user->fetch()) {
            // Generate unique token (16 chars)
            $token = bin2hex(random_bytes(8)); 
            
            // Save token (Delete old one if exists)
            $db->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);
            $db->prepare("INSERT INTO password_resets (email, token) VALUES (?, ?)")->execute([$email, $token]);
            
            $_SESSION['temp_email'] = $email;
            $success = "Security Token: <strong id='tokenCode' style='cursor:pointer; color:#16a34a; font-size:1.2em;' title='Click to copy'>$token</strong><br><small>(Click the green code above to copy)</small>";
            $step = 2; 
        } else {
            $error = "Email not found in our system!";
        }
    }

    // PHASE 2: VERIFY TOKEN
    if (isset($_POST['verify_token'])) {
        $input_token = trim($_POST['token']);
        $email = $_SESSION['temp_email'];
        
        $check = $db->prepare("SELECT * FROM password_resets WHERE email = ? AND token = ?");
        $check->execute([$email, $input_token]);
        
        if ($check->fetch()) {
            $step = 3; 
        } else {
            $error = "Invalid Token! Please ensure you copied the green code correctly.";
            $step = 2;
        }
    }

    // PHASE 3: SET NEW PASSWORD
    if (isset($_POST['reset_password'])) {
        $new_pass = $_POST['new_password'];
        $confirm_pass = $_POST['confirm_password'];
        $email = $_SESSION['temp_email'];

        if ($new_pass === $confirm_pass) {
            $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
            
            // Update user password
            $db->prepare("UPDATE users SET password = ? WHERE email = ?")->execute([$hashed, $email]);
            // Delete used token
            $db->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);
            
            unset($_SESSION['temp_email']);
            $success = "✅ Password successfully updated! Redirecting to login...";
            header("refresh:2;url=login.php");
        } else {
            $error = "Passwords do not match!";
            $step = 3;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        /* Custom styles for this page only */
        .msg-box { padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9em; line-height: 1.5; text-align: center; }
        .error { background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }
        .success { background: #f0fdf4; color: #16a34a; border: 1px solid #4ade80; }
        input { width: 100%; padding: 14px; margin: 12px 0; border: 1px solid #e5e7eb; border-radius: 8px; box-sizing: border-box; font-size: 1rem; }
        input:focus { border-color: #2563eb; outline: none; ring: 2px solid #bfdbfe; }
        .btn-full { width: 100%; padding: 14px; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1rem; transition: background 0.2s; }
        .btn-full:hover { background: #1d4ed8; }
        .step-indicator { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: #e5e7eb; }
        .dot.active { background: #2563eb; width: 24px; border-radius: 4px; }
        
        /* Password Toggle Styles */
        .password-wrapper { position: relative; width: 100%; }
        .password-wrapper input { padding-right: 45px; } /* Space for icon */
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
        .toggle-icon:hover { color: #374151; }
    </style>
</head>
</head>
<body class="auth-page">

<div class="auth-container">
    <div class="auth-card">
        <h2 style="margin-top:0; text-align:center; color:#1e3a8a; font-size:1.5rem;">Reset Password</h2>
        
        <!-- Step Indicators -->
        <div class="step-indicator">
            <div class="dot <?php echo $step == 1 ? 'active' : ''; ?>"></div>
            <div class="dot <?php echo $step == 2 ? 'active' : ''; ?>"></div>
            <div class="dot <?php echo $step == 3 ? 'active' : ''; ?>"></div>
        </div>

        <?php if($error): ?>
            <div class="msg-box error"><?php echo $error; ?></div>
        <?php endif; ?>

        <?php if($success): ?>
            <div class="msg-box success" id="successMsg"><?php echo $success; ?></div>
        <?php endif; ?>

        <!-- STEP 1: REQUEST -->
        <?php if($step == 1): ?>
            <form method="POST">
                <p style="font-size: 0.9rem; color: #6b7280; text-align: center;">Enter your registered email to receive a security token.</p>
                <input type="email" name="email" placeholder="email@example.com" required>
                <button type="submit" name="request_reset" class="btn-full">Send Token</button>
            </form>

        <!-- STEP 2: VERIFY -->
        <?php elseif($step == 2): ?>
            <form method="POST">
                <p style="font-size: 0.9rem; color: #6b7280; text-align: center;">Copy the green code above and paste it here to verify.</p>
                <input type="text" name="token" id="tokenInput" placeholder="Enter Token" required autocomplete="off">
                <button type="submit" name="verify_token" class="btn-full">Verify Token</button>
            </form>

        <!-- STEP 3: RESET -->
        <?php elseif($step == 3): ?>
            <form method="POST">
                <p style="font-size: 0.9rem; color: #6b7280; text-align: center;">Please enter your new secure password.</p>
                <div class="password-wrapper">
                    <input type="password" name="new_password" id="new_password" placeholder="New Password (Min 8 chars)" required minlength="8">
                    <span class="toggle-icon" onclick="togglePassword('new_password', this)">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-closed" style="display:none;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                    </span>
                </div>
                
                <div class="password-wrapper">
                    <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm New Password" required minlength="8">
                    <span class="toggle-icon" onclick="togglePassword('confirm_password', this)">
                         <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="eye-closed" style="display:none;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
                    </span>
                </div>
                <button type="submit" name="reset_password" class="btn-full">Update Password</button>
            </form>
        <?php endif; ?>

        <div style="text-align:center; margin-top:20px;">
            <a href="login.php" style="font-size:0.85rem; color:#2563eb; text-decoration:none; font-weight: 500;">Back to Login</a>
        </div>
    </div>
</div>

<script>
// Click green code to auto-copy and auto-fill
document.addEventListener('click', function(e) {
    if(e.target && e.target.id == 'tokenCode') {
        const token = e.target.innerText;
        const input = document.getElementById('tokenInput');
        
        // Copy to clipboard
        navigator.clipboard.writeText(token).then(() => {
            // Simple visual notification
            const originalColor = e.target.style.color;
            e.target.innerText = "COPIED!";
            setTimeout(() => {
                e.target.innerText = token;
            }, 1000);

            if(input) {
                input.value = token;
                input.style.background = "#f0fdf4";
            }
        });
    }
});
</script>

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