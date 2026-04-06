<?php
session_start();

// 1. SECURITY: Block access if not Admin
// Note: Ensure your login.php sets $_SESSION['user_type'] correctly
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        // Connect to database
        $db = new PDO("sqlite:database.sqlite");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Get data from form using updated names
        $full_name = trim($_POST['full_name']);
        $email = trim($_POST['email']);
        $user_type = $_POST['user_type'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];

        // 2. Simple Validation
        if ($password !== $confirm_password) {
            $error = "Passwords do not match!";
        } else {
            // Check if email already exists
            $check = $db->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
            $check->execute([$email]);
            
            if ($check->fetchColumn() > 0) {
                $error = "This email is already registered!";
            } else {
                // 3. Insert into Database using NEW ERD column names:
                // user_id is AUTOINCREMENT, so we don't include it.
                // Columns: full_name, email, password, user_type, status
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                
                $stmt = $db->prepare("INSERT INTO users (full_name, email, password, user_type, status) VALUES (?, ?, ?, ?, ?)");
                
                // Execute with 'Active' as default status
                $stmt->execute([$full_name, $email, $hashed_password, $user_type, 'Active']);

                $success = "New user registered successfully!";
                
                // Redirect back to manage users after 2 seconds
                header("refresh:2;url=admin_manageuser.php");
            }
        }
    } catch (PDOException $e) {
        // Catching specific "No such column" errors for easier debugging
        $error = "Database Error: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Add New User - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .form-card { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 1px solid #e5e7eb; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; color: #374151; font-size: 0.9rem; }
        input, select { width: 100%; padding: 12px; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; font-size: 1rem; transition: border-color 0.2s; }
        input:focus, select:focus { border-color: #2563eb; outline: none; }
        .btn-submit { width: 100%; padding: 14px; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; margin-top: 10px; font-size: 1rem; transition: background 0.2s; }
        .btn-submit:hover { background: #1d4ed8; }
        .msg { padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9rem; text-align: center; }
        .msg-error { background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }
        .msg-success { background: #d1fae5; color: #065f46; border: 1px solid #4ade80; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: #6b7280; text-decoration: none; font-size: 0.9rem; }
        .back-link:hover { color: #374151; text-decoration: underline; }
        .password-container { position: relative; }
        .toggle-password { position: absolute; right: 15px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #6b7280; }
        .toggle-password:hover { color: #374151; }
    </style>
</head>
<body class="dashboard-page">
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:30px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <div>
                    <h2 style="font-size: 1.2rem; margin:0;">TrojanDetect</h2>
                    <p style="font-size: 0.7rem; margin:0;"></p>
                </div>
            </div>
        </div>

        <nav class="sidebar-nav">
            <a href="admin_dashboard.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <rect x="3" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Dashboard
            </a>
            <a href="admin_uploadfile.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                File Scanner
            </a>
            <a href="admin_history.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <polyline points="12 6 12 12 16 14" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Scan History
            </a>

            <div class="nav-section" style="margin-top:20px; padding:10px; font-size:0.7rem; opacity:0.5;">ADMIN FUNCTIONS</div>

            <a href="admin_manageuser.php" class="nav-item active">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <circle cx="9" cy="7" r="4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Manage Users
            </a>
            <a href="admin_manage_ml.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <rect x="2" y="3" width="20" height="14" rx="2" stroke-width="2"/>
                    <line x1="8" y1="21" x2="16" y2="21" stroke-width="2" stroke-linecap="round"/>
                    <line x1="12" y1="17" x2="12" y2="21" stroke-width="2"/>
                </svg>
                ML & Dataset
            </a>
            <a href="reports.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="14 2 14 8 20 8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Generate Report
            </a>
            <a href="admin_manual.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Admin Manual
            </a>
        </nav>

        <div class="sidebar-footer" style="padding:20px; border-top:1px solid rgba(255,255,255,0.1);">
            <div class="user-info" style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                <div class="user-avatar" style="background:#2563eb; padding:8px 12px; border-radius:50%; font-weight:600; color:white;"><?php echo substr($_SESSION['full_name'] ?? 'A', 0, 1); ?></div>
                <div class="user-details">
                    <p style="margin:0; font-weight:bold; font-size:0.9rem; color:white;"><?php echo htmlspecialchars($_SESSION['full_name'] ?? 'Admin'); ?></p>
                    <span style="font-size:0.7rem; opacity:0.7; color:#9ca3af;"><?php echo htmlspecialchars($_SESSION['email'] ?? 'admin@system.com'); ?></span>
                </div>
            </div>
            <a href="logout.php" id="logoutBtn" style="background:#dc2626; color:white; text-decoration:none; font-size:0.9rem; display:flex; align-items:center; gap:6px; padding:10px 16px; border-radius:8px;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px;">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="16 17 21 12 16 7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <line x1="21" y1="12" x2="9" y2="12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Logout
            </a>
        </div>
    </div>

    <div class="main-content" style="margin-left: 260px; padding: 2rem;">
        <div class="form-card">
            <h2 style="text-align: center; color: #1e3a8a; margin-bottom: 25px;">Add New User</h2>
            
            <?php if($error): ?>
                <div class="msg msg-error"><?php echo $error; ?></div>
            <?php endif; ?>

            <?php if($success): ?>
                <div class="msg msg-success"><?php echo $success; ?></div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" placeholder="Enter full name" required>
                </div>
                
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" name="email" placeholder="Email" required>
                </div>
                
                <div class="form-group">
                    <label>User Type (Role)</label>
                    <select name="user_type" required>
                        <option value="">-- Select Role --</option>
                        <option value="student">Student</option>
                        <option value="lecturer">Lecturer</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Password</label>
                    <div class="password-container">
                        <input type="password" name="password" id="password" required minlength="6" style="padding-right: 40px;">
                        <i class="fas fa-eye toggle-password" onclick="togglePassword('password', this)"></i>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Confirm Password</label>
                    <div class="password-container">
                        <input type="password" name="confirm_password" id="confirm_password" required minlength="6" style="padding-right: 40px;">
                        <i class="fas fa-eye toggle-password" onclick="togglePassword('confirm_password', this)"></i>
                    </div>
                </div>
                
                <button type="submit" class="btn-submit">Register User</button>
            </form>
            
            <a href="admin_manageuser.php" class="back-link">Cancel & Back to List</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        function togglePassword(inputId, icon) {
            const input = document.getElementById(inputId);
            if (input.type === "password") {
                input.type = "text";
                icon.classList.remove("fa-eye");
                icon.classList.add("fa-eye-slash");
            } else {
                input.type = "password";
                icon.classList.remove("fa-eye-slash");
                icon.classList.add("fa-eye");
            }
        }

        // Logout confirmation
        document.getElementById('logoutBtn').addEventListener('click', function(e) {
            e.preventDefault();
            Swal.fire({
                title: 'Are you sure?',
                text: "You will be logged out of your session.",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#3085d6',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, logout!'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'logout.php';
                }
            });
        });
    </script>
</body>
</html>