<?php
// 1. Connect to SQLite database
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 2. UPDATE: Ensure column is named 'email' instead of 'username'
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE, 
        password TEXT,
        user_type TEXT
    )");

    // Add is_verified and verification_token columns if they don't exist
    try {
        $db->exec("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0");
    } catch (PDOException $e) { /* Ignore if exists */ }
    
    try {
        $db->exec("ALTER TABLE users ADD COLUMN verification_token TEXT");
    } catch (PDOException $e) { /* Ignore if exists */ }

    $success_message = "";
    $error_message = "";

    // 3. Process registration when button is pressed
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $fullname = $_POST['full_name'];
        $email = $_POST['email']; // Get data from input name="email"
        $user_type = $_POST['user_type'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm-password'];

        if ($password !== $confirm_password) {
            $error_message = "Passwords do not match!";
        } else {
            // Hash password for security
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            try {
                // Generate verification token
                $verification_token = bin2hex(random_bytes(16));

                // UPDATE: Change 'username' to 'email' in INSERT query
                // Include is_verified and verification_token
                $stmt = $db->prepare("INSERT INTO users (full_name, email, password, user_type, is_verified, verification_token) VALUES (?, ?, ?, ?, 0, ?)");
                $stmt->execute([$fullname, $email, $hashed_password, $user_type, $verification_token]);
                
                // Include PHPMailer 
                require 'PHPMailer/src/Exception.php';
                require 'PHPMailer/src/PHPMailer.php';
                require 'PHPMailer/src/SMTP.php';

                $mail = new PHPMailer\PHPMailer\PHPMailer(true);

                try {
                    // Server settings
                    $mail->isSMTP();
                    $mail->Host       = 'smtp.gmail.com';  // Specify main SMTP server
                    $mail->SMTPAuth   = true;              // Enable SMTP authentication
                    $mail->Username   = 'mmaisarah2212@gmail.com'; // SMTP username
                    $mail->Password   = 'nhhctlstlvmruzdm';              // SMTP App Password
                    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS; 
                    $mail->Port       = 587;

                    // Recipients
                    $mail->setFrom('no-reply@trojandetect.com', 'TrojanDetect ML');
                    $mail->addAddress($email, $fullname);

                    // Content
                    // Important: Determine the correct base URL including the subfolder (for Laragon/XAMPP)
                    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
                    $host = $_SERVER['HTTP_HOST'];
                    
                    // Get the directory containing register.php
                    // $_SERVER['REQUEST_URI'] will be something like "/trojan_detection%20-%20testing/register.php"
                    $uri_parts = explode('/', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
                    array_pop($uri_parts); // Remove the filename (register.php)
                    $base_path = implode('/', $uri_parts); // Will be "/trojan_detection%20-%20testing"
                    
                    $verify_link = $protocol . "://" . $host . $base_path . "/verify.php?email=" . urlencode($email) . "&token=" . $verification_token;
                    
                    $mail->isHTML(true);
                    $mail->Subject = 'Verify your email address - TrojanDetect ML';
                    $mail->Body    = "
                        <h2>Welcome to TrojanDetect ML, $fullname!</h2>
                        <p>Thank you for registering. To complete your registration and activate your account, please click the link below to verify your email address:</p>
                        <p><a href='$verify_link' style='display:inline-block; padding:10px 20px; color:#fff; background-color:#2563eb; text-decoration:none; border-radius:5px;'>Verify Email</a></p>
                        <p>If the button doesn't work, copy and paste this link into your browser:</p>
                        <p>$verify_link</p>
                        <p>Thank you,<br>TrojanDetect ML Team</p>
                    ";
                    $mail->AltBody = "Welcome to TrojanDetect ML, $fullname!\n\nPlease click the following link to verify your email address:\n$verify_link";

                    $mail->send();
                    
                    // Redirect with success message about email verification
                    header("Location: login.php?register=verify_email");
                    exit;
                } catch (Exception $e) {
                    // IMPORTANT: If email fails to send, delete the newly created account
                    // so the user can try to register again
                    $del_stmt = $db->prepare("DELETE FROM users WHERE email = ?");
                    $del_stmt->execute([$email]);
                    
                    $error_message = "Registration successful, but email could not be sent. Mailer Error: {$mail->ErrorInfo}";
                }
            } catch (PDOException $e) {
                if ($e->getCode() == 23000) { 
                    $error_message = "This email is already registered!";
                } else {
                    $error_message = "Error: " . $e->getMessage();
                }
            }
        }
    }
} catch (PDOException $e) {
    die("Failed to connect to database: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
</head>
<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="#2563eb" style="width:50px; height:50px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <h1>Create Account</h1>
                <p>Register for TrojanDetect ML</p>
            </div>

            <div class="auth-form-container">
                <?php if($success_message): ?>
                    <p style="color: #155724; background: #d4edda; padding: 10px; border-radius: 5px; text-align: center;">
                        <?php echo $success_message; ?>
                    </p>
                <?php endif; ?>

                <?php if($error_message): ?>
                    <p style="color: #721c24; background: #f8d7da; padding: 10px; border-radius: 5px; text-align: center;">
                        <?php echo $error_message; ?>
                    </p>
                <?php endif; ?>

                <form class="auth-form" method="POST" action="register.php">
                    <div class="form-group">
                        <label for="fullname">Full Name</label>
                        <input type="text" name="full_name" id="fullname" placeholder="Full Name" required>
                    </div>

                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" placeholder="Email" required>
                    </div>

                    <div class="form-group">
                        <label for="usertype">User Type</label>
                        <select name="user_type" id="usertype" required style="width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #ccc;">
                            <option value="">-- Select User Type --</option>
                            <option value="student">Student</option>
                            <option value="lecturer">Lecturer</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="password">Password</label>
                        <div style="position: relative;">
                            <input type="password" name="password" id="password" placeholder="••••••••" required minlength="8" style="padding-right: 45px;">
                            <button type="button" class="togglePassword" data-target="password" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; padding: 5px; display: flex; align-items: center; justify-content: center;">
                                <svg class="eyeIcon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path class="eyePath" d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                    <circle class="eyeCircle" cx="12" cy="12" r="3"></circle>
                                    <line class="eyeSlash" x1="0" y1="0" x2="0" y2="0" style="display: none;"></line>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="confirm-password">Confirm Password</label>
                        <div style="position: relative;">
                            <input type="password" name="confirm-password" id="confirm-password" placeholder="••••••••" required minlength="8" style="padding-right: 45px;">
                            <button type="button" class="togglePassword" data-target="confirm-password" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; padding: 5px; display: flex; align-items: center; justify-content: center;">
                                <svg class="eyeIcon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path class="eyePath" d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                    <circle class="eyeCircle" cx="12" cy="12" r="3"></circle>
                                    <line class="eyeSlash" x1="0" y1="0" x2="0" y2="0" style="display: none;"></line>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <button type="submit" class="btn-full">Register</button>
                </form>
            </div>

            <div class="auth-link">
                <p>Already have an account? <a href="login.php">Login here</a></p>
            </div>
        </div>
    </div>

    <script>
        // Toggle Password Visibility
        const toggleButtons = document.querySelectorAll('.togglePassword');
        toggleButtons.forEach(button => {
            button.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const passwordInput = document.getElementById(targetId);
                const eyeSlash = this.querySelector('.eyeSlash');
                
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                
                if (type === 'text') {
                    eyeSlash.setAttribute('x1', '3');
                    eyeSlash.setAttribute('y1', '3');
                    eyeSlash.setAttribute('x2', '21');
                    eyeSlash.setAttribute('y2', '21');
                    eyeSlash.style.display = 'block';
                } else {
                    eyeSlash.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>