<?php
session_start();

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $error_message = "";
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $email = $_POST['email'];
        $password = $_POST['password'];

        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            // Check if the user is verified
            if (isset($user['is_verified']) && $user['is_verified'] == 0) {
                // Ignore is_verified check for admin for safety
                if ($user['user_type'] !== 'admin') {
                    $error_message = "Your email has not been verified yet. Please check your email inbox (and spam folder) for the verification link.";
                } else {
                    $_SESSION['is_logged_in'] = true;
                    $_SESSION['user_id'] = $user['user_id'] ?? $user['id'];
                    $_SESSION['full_name'] = $user['full_name'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['user_type'] = $user['user_type']; 
        
                    // --- UPDATE REDIRECT LOGIC HERE ---
                    $_SESSION['login_success'] = true; // Set flag for popup
                    header("Location: admin_dashboard.php");
                    exit;
                }
            } else {
                $_SESSION['is_logged_in'] = true;
                $_SESSION['user_id'] = $user['user_id'] ?? $user['id'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['user_type'] = $user['user_type']; 
    
                // --- UPDATE REDIRECT LOGIC HERE ---
                $_SESSION['login_success'] = true; // Set flag for popup
    
                if ($user['user_type'] === 'admin') {
                    // If admin, send to admin dashboard
                    header("Location: admin_dashboard.php");
                } else {
                    // If student/lecturer, send to user dashboard
                    header("Location: user_dashboard.php");
                }
                exit;
            }
        } else {
            $error_message = "Invalid email or password.";
        }
    }
} catch (PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <!-- SweetAlert2 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
</head>
<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="#2563eb" style="width:50px; height:50px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <h1>TrojanDetect ML</h1>
                <p>Windows-Based Trojan Detection System</p>
            </div>

            <div class="auth-form-container">
                <h2>Login</h2>
                
                <?php if($error_message): ?>
                    <div style="color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 5px; text-align: center; margin-bottom: 15px;">
                        <?php echo $error_message; ?>
                    </div>
                <?php endif; ?>
               
                <form class="auth-form" method="POST" action="login.php">
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" placeholder="Enter your email" required>
                    </div>

                    <div class="form-group">
                        <label for="password">Password</label>
                        <div style="position: relative;">
                            <input type="password" name="password" id="password" placeholder="••••••••" required style="padding-right: 45px;">
                            <button type="button" id="togglePassword" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; padding: 5px; display: flex; align-items: center; justify-content: center;">
                                <svg id="eyeIcon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path id="eyePath" d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                    <circle id="eyeCircle" cx="12" cy="12" r="3"></circle>
                                    <line id="eyeSlash" x1="0" y1="0" x2="0" y2="0" style="display: none;"></line>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <button type="submit" class="btn-full" style="width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top: 10px;">
                        Login
                    </button>
                </form>

                <div class="forgot-password" style="text-align: center; margin-top: 15px;">
                    <a href="forgot_password.php" style="color: #2563eb; text-decoration: none; font-size: 0.9em;">Forgot password?</a>
                </div>
            </div>

            <div class="auth-link" style="text-align: center; margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                <p>Don't have an account? <a href="register.php" style="color: #2563eb; text-decoration: none; font-weight: bold;">Register here</a></p>
            </div>
        </div>
    </div>

    <script>
        const togglePassword = document.getElementById('togglePassword');
        const passwordInput = document.getElementById('password');
        const eyeSlash = document.getElementById('eyeSlash');
        const eyePath = document.getElementById('eyePath');
        const eyeCircle = document.getElementById('eyeCircle');

        togglePassword.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            if (type === 'text') {
                eyeSlash.setAttribute('x1', '3');
                eyeSlash.setAttribute('y1', '3');
                eyeSlash.setAttribute('x2', '21');
                eyeSlash.setAttribute('y2', '21');
                eyeSlash.style.display = 'block';
                eyePath.style.opacity = '0.5';
                eyeCircle.style.opacity = '0.5';
            } else {
                eyeSlash.style.display = 'none';
                eyePath.style.opacity = '1';
                eyeCircle.style.opacity = '1';
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        // Logout Success Popup
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('logout') && urlParams.get('logout') === 'success') {
            Swal.fire({
                title: 'Logged Out!',
                text: 'You have been successfully logged out.',
                icon: 'success',
                timer: 2000,
                showConfirmButton: false
            }).then(() => {
                // Remove the query parameter to prevent popup on refresh
                window.history.replaceState(null, null, window.location.pathname);
            });
        }
        
        // Registration Success Popup
        if (urlParams.has('register')) {
            if (urlParams.get('register') === 'success') {
                 Swal.fire({
                    title: 'Registration Successful!',
                    text: 'Your account has been created. Please log in.',
                    icon: 'success',
                    timer: 3000,
                    showConfirmButton: false
                }).then(() => {
                    window.history.replaceState(null, null, window.location.pathname);
                });
            } else if (urlParams.get('register') === 'verify_email') {
                 Swal.fire({
                    title: 'Registration Successful!',
                    text: 'We have sent a verification link to your email. Please verify your email before logging in.',
                    icon: 'info',
                    showConfirmButton: true,
                    confirmButtonText: 'OK',
                    confirmButtonColor: '#2563eb'
                }).then(() => {
                    window.history.replaceState(null, null, window.location.pathname);
                });
            }
        }
    </script>
</body>
</html>