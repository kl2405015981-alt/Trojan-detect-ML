<?php
session_start();

// 1. SECURITY: Block access if not logged in or if the user is an Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] === 'admin') {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'] ?? 0; 
$full_name = (string)($_SESSION['full_name'] ?? 'User'); 
$email = (string)($_SESSION['email'] ?? ''); 
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Manual - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
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
            <a href="user_settings.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <circle cx="12" cy="12" r="3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Settings
            </a>
            <a href="user_manual.php" class="nav-item active">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                User Manual
            </a>
        </nav>

        <div class="sidebar-footer">
            <div class="user-profile" style="background:transparent; padding:0; margin-bottom:1rem; display:flex; align-items:center; gap:0.75rem;">
                <div class="user-avatar" style="background:#3b82f6; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-weight:bold;"><?= htmlspecialchars(substr($full_name, 0, 1)) ?></div>
                <div class="user-info" style="flex:1; min-width:0;">
                    <div class="user-name" style="color:white; font-size:0.875rem; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?= htmlspecialchars($full_name) ?></div>
                    <div class="user-email" style="color:#9ca3af; font-size:0.75rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?= htmlspecialchars($email) ?></div>
                </div>
            </div>
            <a href="#" onclick="logout(); return false;" class="logout-btn" style="width:100%; padding:0.75rem; background:#dc2626; color:white; border:none; border-radius:0.5rem; cursor:pointer; font-size:0.875rem; font-weight:600; display:flex; align-items:center; justify-content:center; gap:0.5rem; text-decoration:none; transition:all 0.3s;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px; flex-shrink:0;">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Logout
            </a>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content" style="margin-left: 260px; padding: 30px; background: #f9fafb; min-height: 100vh;">
        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">User Manual</h1>
            <p style="color: #6b7280; margin-top: 5px;">Guide on how to use TrojanDetect ML for basic users.</p>
        </div>

        <div style="background: white; padding: 30px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); line-height: 1.6;">
            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 0;">1. Dashboard Overview</h2>
            <p style="color: #4b5563;">
                The dashboard gives you a quick summary of your activities. You can see the total number of files you've scanned, how many threats were detected, how many were safe, and the average accuracy of the engine.
            </p>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">2. How to Scan a File</h2>
            <p style="color: #4b5563;">
                Our core feature is the File Scanner powered by a Machine Learning model. Here's how to use it:
            </p>
            <ol style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 10px;">Click on <strong>File Scanner</strong> from the left menu.</li>
                <li style="margin-bottom: 10px;">Click on the upload area or the <strong>Choose File</strong> button.</li>
                <li style="margin-bottom: 10px;">Select the executable file (such as .exe or .dll) or any supported file you want to check.</li>
                <li style="margin-bottom: 10px;">Click <strong>Scan File</strong> and wait for the ML engine to analyze it.</li>
                <li style="margin-bottom: 10px;">Once complete, you will see the prediction result along with the confidence score.</li>
            </ol>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">3. Viewing Scan History & Reports</h2>
            <p style="color: #4b5563;">
                You can always look back at your previous scans and download official reports.
            </p>
            <ul style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 10px;">Go to <strong>Scan History</strong> to view a table of your past activities.</li>
                <li style="margin-bottom: 10px;">Click the <strong>Download</strong> link beside any record to get a PDF report of that specific scan.</li>
            </ul>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">4. Account Settings</h2>
            <p style="color: #4b5563;">
                Need to change your name or update your password? 
                Go to the <strong>Settings</strong> page from the side menu. Remember to click <strong>Update Profile</strong> or <strong>Update Password</strong> to save your changes.
            </p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
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
