<?php
session_start(); // Start session to store temporary user data

// 1. SECURITY: Block access if not a valid user
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] === 'admin') {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$success_msg = "";
$error_msg = "";

try {
    $db = new PDO("sqlite:database.sqlite"); // Connect to database
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Set error mode for debugging

    // 2. Get current user data
    $stmt = $db->prepare("SELECT full_name, email FROM users WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // 3. Profile Update Process (Name Only - Email is usually unique/fixed)
    if (isset($_POST['update_profile'])) {
        $new_name = trim($_POST['full_name']);
        if (!empty($new_name)) {
            $update = $db->prepare("UPDATE users SET full_name = ? WHERE user_id = ?");
            $update->execute([$new_name, $user_id]);
            $_SESSION['full_name'] = $new_name; // Update session
            $user['full_name'] = $new_name;
            $success_msg = "Profile updated successfully!";
        }
    }

    // 4. Change Password Process
    if (isset($_POST['change_password'])) {
        $current_pass = $_POST['current_password'];
        $new_pass = $_POST['new_password'];
        $confirm_pass = $_POST['confirm_password'];

        // Check old password
        $stmt_pass = $db->prepare("SELECT password FROM users WHERE user_id = ?");
        $stmt_pass->execute([$user_id]);
        $stored_hash = $stmt_pass->fetchColumn();

        if (password_verify($current_pass, $stored_hash)) {
            if ($new_pass === $confirm_pass) {
                if (strlen($new_pass) >= 8) {
                    $new_hash = password_hash($new_pass, PASSWORD_DEFAULT);
                    $update_pass = $db->prepare("UPDATE users SET password = ? WHERE user_id = ?");
                    $update_pass->execute([$new_hash, $user_id]);
                    $success_msg = "Password changed successfully!";
                } else {
                    $error_msg = "New password must be at least 8 characters.";
                }
            } else {
                $error_msg = "New password confirmation does not match.";
            }
        } else {
            $error_msg = "Current password is incorrect.";
        }
    }

} catch (PDOException $e) {
    $error_msg = "System Error: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        .main-content { margin-left: 260px; padding: 30px; background: #f9fafb; min-height: 100vh; }
        .settings-grid { display: grid; grid-template-columns: 1fr; gap: 2rem; max-width: 800px; }
        .card { background: white; border-radius: 12px; padding: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #f0f0f0; }
        .card-title { font-size: 1.1rem; font-weight: 700; color: #1f2937; margin-bottom: 1.5rem; border-bottom: 1px solid #f3f4f6; padding-bottom: 1rem; display: flex; align-items: center; gap: 10px; }
        
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; font-size: 0.85rem; font-weight: 600; color: #6b7280; margin-bottom: 0.5rem; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 8px; font-size: 0.9rem; box-sizing: border-box; }
        input:focus { outline: none; border-color: #2563eb; ring: 2px solid #bfdbfe; }
        input[readonly] { background: #f3f4f6; cursor: not-allowed; }

        /* Password toggle wrapper */
        .password-wrapper { position: relative; }
        .password-wrapper input { padding-right: 2.75rem; }
        .toggle-password {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            padding: 0;
            color: #9ca3af;
            display: flex;
            align-items: center;
            transition: color 0.2s;
        }
        .toggle-password:hover { color: #2563eb; }
        .toggle-password svg { width: 18px; height: 18px; pointer-events: none; }

        .btn-save { background: #2563eb; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        .btn-save:hover { background: #1d4ed8; }
        
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.9rem; font-weight: 500; }
        .alert-success { background: #d1fae5; color: #065f46; border: 1px solid #10b981; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    </style>
</head>
<body class="dashboard-page">
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:30px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" />
                </svg>
                <div>
                    <h2>TrojanDetect</h2>
                    <p></p>
                </div>
            </div>
        </div>

        <nav class="sidebar-nav">
            <a href="user_dashboard.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <rect x="3" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Dashboard
            </a>
            <a href="user_upload.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                File Scanner
            </a>
            <a href="user_history.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Scan History
            </a>
            <a href="user_settings.php" class="nav-item active">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <circle cx="12" cy="12" r="3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Settings
            </a>
            <a href="user_manual.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                User Manual
            </a>
        </nav>

        <div class="sidebar-footer">
            <div class="user-profile" style="background:transparent; padding:0; margin-bottom:1rem; display:flex; align-items:center; gap:0.75rem;">
                <div class="user-avatar" style="background:#3b82f6; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-weight:bold;"><?php echo htmlspecialchars(substr($user['full_name'] ?? 'U', 0, 1)); ?></div>
                <div class="user-info" style="flex:1; min-width:0;">
                    <div class="user-name" style="color:white; font-size:0.875rem; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?php echo htmlspecialchars($user['full_name'] ?? 'User'); ?></div>
                    <div class="user-email" style="color:#9ca3af; font-size:0.75rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?php echo htmlspecialchars($user['email'] ?? ''); ?></div>
                </div>
            </div>
            <a href="#" onclick="logout(); return false;" id="logoutBtn" class="logout-btn" style="width:100%; padding:0.75rem; background:#dc2626; color:white; border:none; border-radius:0.5rem; cursor:pointer; font-size:0.875rem; font-weight:600; display:flex; align-items:center; justify-content:center; gap:0.5rem; text-decoration:none; transition:all 0.3s;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px; flex-shrink:0;">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Logout
            </a>
        </div>
    </div>

    <!-- Main Content -->
    <main class="main-content">
        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">Account Settings</h1>
            <p style="color: #6b7280; margin-top: 5px;">Manage your profile information and account security.</p>
        </div>

        <?php if($success_msg): ?>
            <div class="alert alert-success">✅ <?php echo $success_msg; ?></div>
        <?php endif; ?>

        <?php if($error_msg): ?>
            <div class="alert alert-error">❌ <?php echo $error_msg; ?></div>
        <?php endif; ?>

        <div class="settings-grid">
            <!-- Profile Information -->
            <div class="card">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    Profile Information
                </div>
                <form method="POST">
                    <div class="form-group">
                        <label>Email Address (Account ID)</label>
                        <input type="text" value="<?php echo htmlspecialchars($user['email']); ?>" readonly>
                    </div>
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="full_name" value="<?php echo htmlspecialchars($user['full_name']); ?>" required>
                    </div>
                    <button type="submit" name="update_profile" class="btn-save">Update Name</button>
                </form>
            </div>

            <!-- Security / Password -->
            <div class="card">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Security & Password
                </div>
                <form method="POST">
                    <div class="form-group">
                        <label>Current Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="current_password" name="current_password" placeholder="••••••••" required>
                            <button type="button" class="toggle-password" onclick="togglePassword('current_password', this)" aria-label="Show/hide password">
                                <svg id="eye-current" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                    <circle cx="12" cy="12" r="3"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>New Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="new_password" name="new_password" placeholder="Min 8 characters" required minlength="8">
                            <button type="button" class="toggle-password" onclick="togglePassword('new_password', this)" aria-label="Show/hide password">
                                <svg id="eye-new" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                    <circle cx="12" cy="12" r="3"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="confirm_password" name="confirm_password" placeholder="Re-type new password" required minlength="8">
                            <button type="button" class="toggle-password" onclick="togglePassword('confirm_password', this)" aria-label="Show/hide password">
                                <svg id="eye-confirm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                    <circle cx="12" cy="12" r="3"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <button type="submit" name="change_password" class="btn-save" style="background: #10b981;">Change Password</button>
                </form>
            </div>
        </div>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        // Toggle show/hide password
        function togglePassword(fieldId, btn) {
            const input = document.getElementById(fieldId);
            const svg = btn.querySelector('svg');
            if (input.type === 'password') {
                input.type = 'text';
                btn.style.color = '#2563eb';
                // Change to eye-off icon
                svg.innerHTML = `
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                    <line x1="1" y1="1" x2="23" y2="23"/>
                `;
            } else {
                input.type = 'password';
                btn.style.color = '';
                // Change back to eye icon
                svg.innerHTML = `
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                `;
            }
        }

        function logout() {
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
        }
    </script>
</body>
</html>