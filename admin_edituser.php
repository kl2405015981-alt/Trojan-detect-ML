<?php
session_start();

// 1. SECURITY: Block access if not Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

$db = new PDO("sqlite:database.sqlite");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$success_message = "";
$error_message = "";
$user = null;

// 2. Get user ID from URL
if (isset($_GET['id'])) {
    $user_id = $_GET['id'];
    $stmt = $db->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        die("User not found!");
    }
} else {
    header("Location: admin_manageuser.php");
    exit;
}

// 3. Process Update User
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {
        $id = $_POST['id'];
        $fullname = $_POST['full_name'];
        $email = $_POST['email'];
        $user_type = $_POST['user_type'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm-password'];

        // Check if email already exists for OTHER users
        $check = $db->prepare("SELECT COUNT(*) FROM users WHERE email = ? AND user_id != ?");
        $check->execute([$email, $id]);
        if ($check->fetchColumn() > 0) {
            $error_message = "Email is already registered by another user!";
        } else {
            // Update basic info
            $sql = "UPDATE users SET full_name = ?, email = ?, user_type = ? WHERE user_id = ?";
            $params = [$fullname, $email, $user_type, $id];

            // If password is provided, update it too
            if (!empty($password)) {
                if ($password !== $confirm_password) {
                    $error_message = "Passwords do not match!";
                } else {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    $sql = "UPDATE users SET full_name = ?, email = ?, user_type = ?, password = ? WHERE user_id = ?";
                    $params = [$fullname, $email, $user_type, $hashed_password, $id];
                }
            }

            if (empty($error_message)) {
                $stmt = $db->prepare($sql);
                $stmt->execute($params);
                
                header("Location: admin_manageuser.php?status=updated");
                exit;
            }
        }
    } catch (PDOException $e) {
        $error_message = "Database Error: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit User - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        .form-card {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            max-width: 600px;
            margin: 0 auto;
        }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 500; font-size: 0.9rem; }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            font-size: 0.95rem;
        }
        .btn-submit {
            background: #2563eb;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            width: 100%;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 10px;
        }
        .btn-submit:hover { background: #1d4ed8; }
        .alert { padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9rem; }
        .alert-error { background: #fee2e2; color: #991b1b; }
        .note { font-size: 0.8rem; color: #6b7280; margin-top: 4px; }
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
        <div class="content-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 30px;">
            <div>
                <a href="admin_manageuser.php" style="color: #6b7280; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; margin-bottom: 10px; font-size: 0.9rem;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:16px; height:16px;"><path d="M19 12H5M12 19l-7-7 7-7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    Back to Users
                </a>
                <h1>Edit User</h1>
                <p class="subtitle">Update user details</p>
            </div>
        </div>

        <div class="form-card">
            <?php if ($error_message): ?>
                <div class="alert alert-error">
                    <?php echo htmlspecialchars($error_message); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="admin_edituser.php?id=<?php echo $user['user_id']; ?>">
                <input type="hidden" name="id" value="<?php echo $user['user_id']; ?>">
                
                <div class="form-group">
                    <label for="fullname">Full Name</label>
                    <input type="text" name="full_name" id="fullname" value="<?php echo htmlspecialchars($user['full_name']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" name="email" id="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="usertype">Role</label>
                    <select name="user_type" id="usertype" required>
                        <option value="student" <?php echo ($user['user_type'] == 'student') ? 'selected' : ''; ?>>Student</option>
                        <option value="lecturer" <?php echo ($user['user_type'] == 'lecturer') ? 'selected' : ''; ?>>Lecturer</option>
                        <option value="admin" <?php echo ($user['user_type'] == 'admin') ? 'selected' : ''; ?>>System Admin</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="password">New Password</label>
                    <div class="password-wrapper" style="position: relative;">
                        <input type="password" name="password" id="password" minlength="8" style="padding-right: 40px;">
                        <span class="toggle-password" onclick="togglePassword('password', this)" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #6b7280;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </span>
                    </div>
                    <div class="note">Leave blank to keep current password</div>
                </div>

                <div class="form-group">
                    <label for="confirm-password">Confirm New Password</label>
                    <div class="password-wrapper" style="position: relative;">
                        <input type="password" name="confirm-password" id="confirm-password" minlength="8" style="padding-right: 40px;">
                        <span class="toggle-password" onclick="togglePassword('confirm-password', this)" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #6b7280;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </span>
                    </div>
                </div>

                <button type="submit" class="btn-submit">Update User</button>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        function togglePassword(inputId, iconSpan) {
            const input = document.getElementById(inputId);
            const svg = iconSpan.querySelector('svg');
            
            if (input.type === "password") {
                input.type = "text";
                // Switch to Eye Off icon
                svg.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
            } else {
                input.type = "password";
                // Switch back to Eye icon
                svg.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
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
