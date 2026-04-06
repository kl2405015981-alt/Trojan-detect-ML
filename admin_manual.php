<?php
session_start();

// SECURITY: Block access if not Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Manual - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
</head>

<body class="dashboard-page">
    
    <!-- SIDEBAR INLINE -->
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
                    <rect x="3" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2"/>
                </svg>
                Dashboard
            </a>
            <a href="admin_uploadfile.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2"/>
                </svg>
                File Scanner
            </a>
            <a href="admin_history.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <polyline points="12 6 12 12 16 14" stroke-width="2"/>
                </svg>
                Scan History
            </a>

            <div class="nav-section" style="margin-top:20px; padding:10px; font-size:0.7rem; opacity:0.5;">ADMIN FUNCTIONS</div>

            <a href="admin_manageuser.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2"/>
                    <circle cx="9" cy="7" r="4" stroke-width="2"/>
                </svg>
                Manage Users
            </a>
            <a href="admin_manage_ml.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <rect x="2" y="3" width="20" height="14" rx="2" stroke-width="2"/>
                    <line x1="8" y1="21" x2="16" y2="21" stroke-width="2"/>
                    <line x1="12" y1="17" x2="12" y2="21" stroke-width="2"/>
                </svg>
                ML & Dataset
            </a>
            <a href="reports.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-width="2"/>
                    <polyline points="14 2 14 8 20 8" stroke-width="2"/>
                </svg>
                Generate Report
            </a>
            <a href="admin_manual.php" class="nav-item active">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Admin Manual
            </a>
        </nav>

        <div class="sidebar-footer" style="padding:20px; border-top:1px solid rgba(255,255,255,0.1);">
            <div class="user-info" style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                <div class="user-avatar" style="background:#2563eb; padding:8px 12px; border-radius:50%; font-weight:600; color:white;">
                    <?= substr($_SESSION['full_name'] ?? 'A', 0, 1) ?>
                </div>
                <div class="user-details">
                    <p style="margin:0; font-weight:bold; font-size:0.9rem; color:white;">
                        <?= htmlspecialchars($_SESSION['full_name'] ?? 'Admin') ?>
                    </p>
                    <span style="font-size:0.7rem; opacity:0.7; color:#9ca3af;">
                        <?= htmlspecialchars($_SESSION['email'] ?? 'admin@system.com') ?>
                    </span>
                </div>
            </div>
            <a href="logout.php" id="logoutBtn" style="background:#dc2626; color:white; text-decoration:none; font-size:0.9rem; display:flex; align-items:center; gap:6px; padding:10px 16px; border-radius:8px;">
                Logout
            </a>
        </div>
    </div>

    <div class="main-content" style="margin-left: 260px; padding: 30px; background: #f9fafb; min-height: 100vh;">
        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">Admin Manual</h1>
            <p style="color: #6b7280; margin-top: 5px;">Guide on how to use TrojanDetect ML for administrators.</p>
        </div>

        <div style="background: white; padding: 30px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); line-height: 1.6;">
            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 0;">1. System Monitoring (Dashboard)</h2>
            <p style="color: #4b5563;">
                The <strong>Admin Dashboard</strong> gives you a system-wide view of all activities.
            </p>
            <ul style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 5px;">View total system-wide scans and detected threats.</li>
                <li style="margin-bottom: 5px;">Observe the latest model accuracy and user count.</li>
                <li style="margin-bottom: 5px;">Check the "Recent System Activity Table" for a chronological list of actions taken by all users.</li>
            </ul>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">2. User Management</h2>
            <p style="color: #4b5563;">
                Go to <strong>Manage Users</strong> to control who has access to the application.
            </p>
            <ul style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 5px;">Click <strong>Add New User</strong> to create a new student or admin account manually.</li>
                <li style="margin-bottom: 5px;">Click <strong>Edit</strong> on a user to update their credentials or reset their password.</li>
                <li style="margin-bottom: 5px;">Click <strong>Delete</strong> to permanently remove a user and all their associated scan data from the database.</li>
            </ul>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">3. ML Engine & Dataset</h2>
            <p style="color: #4b5563;">
                Go to <strong>ML & Dataset</strong> to manage the data used to train the machine learning algorithm.
            </p>
            <ol style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 10px;">You can upload a new CSV file containing new test data or training malware dataset here.</li>
                <li style="margin-bottom: 10px;">The system might automatically retrain or use the updated dataset moving forward.</li>
                <li style="margin-bottom: 10px;">Make sure the CSV format strictly matches the predefined feature list.</li>
            </ol>

            <h2 style="color: #1f2937; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; margin-top: 30px;">4. Generating Reports</h2>
            <p style="color: #4b5563;">
                Go to <strong>Generate Report</strong> to extract analytical data for external use.
            </p>
            <ul style="color: #4b5563; margin-left: 20px;">
                <li style="margin-bottom: 5px;">Select the date range (Start Date and End Date).</li>
                <li style="margin-bottom: 5px;">Filter by specific user or result (Safe/Trojan).</li>
                <li style="margin-bottom: 5px;">Click <strong>Download PDF</strong> or view the summary immediately.</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
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
                if (result.isConfirmed) window.location.href = 'logout.php';
            });
        });
    </script>
</body>
</html>
