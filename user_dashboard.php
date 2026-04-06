<?php
session_start(); // Start session to store temporary user data

// 1. SECURITY: Block access if not logged in or if the user is an Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] === 'admin') {
    header("Location: login.php");
    exit;
}

// Use null coalescing to prevent "Passing null" errors if session keys are missing
$user_id = $_SESSION['user_id'] ?? 0; // Get User ID
$full_name = $_SESSION['full_name'] ?? 'User'; // Get Full Name
$email = $_SESSION['email'] ?? ''; // Get User Email

// Initialize variables to avoid "Undefined variable" error if DB fails
$total_scans = 0;
$threats = 0;
$clean_files = 0;
$avg_acc = 0;
$recent_scans = [];
$error_msg = "";

try {
    // 2. Connect to Database
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 3. Fetch Statistics for this specific user (Sync with 9-table ERD)
    
    // Total Scans - Use 'scans' table
    $stmt = $db->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $total_scans = $stmt->fetchColumn() ?: 0;

    // Threats Detected - Use 'scan_result' column
    $stmt = $db->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ? AND scan_result LIKE '%Trojan%'");
    $stmt->execute([$user_id]);
    $threats = $stmt->fetchColumn() ?: 0;

    // Clean Files (Result is 'Safe')
    $stmt = $db->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ? AND scan_result = 'Safe'");
    $stmt->execute([$user_id]);
    $clean_files = $stmt->fetchColumn() ?: 0;

    // Average Accuracy/Confidence - Use 'accuracy_score' column
    $stmt = $db->prepare("SELECT AVG(accuracy_score) FROM scans WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $avg_acc = $stmt->fetchColumn() ?: 0;

    // 4. Fetch Recent Scans (Limit 5)
    $stmt = $db->prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC LIMIT 5");
    $stmt->execute([$user_id]);
    $recent_scans = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    // Graceful error display
    $error_msg = "Database Connection Error. Please ensure you have run reset_db.php.";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <!-- SweetAlert2 CSS -->
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
            <a href="user_dashboard.php" class="nav-item active">
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
                <div class="user-avatar" style="background:#3b82f6; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-weight:bold;"><?php echo htmlspecialchars(substr((string)$full_name, 0, 1)); ?></div>
                <div class="user-info" style="flex:1; min-width:0;">
                    <div class="user-name" style="color:white; font-size:0.875rem; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?php echo htmlspecialchars((string)$full_name); ?></div>
                    <div class="user-email" style="color:#9ca3af; font-size:0.75rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;"><?php echo htmlspecialchars((string)$email); ?></div>
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
        <?php if(!empty($error_msg)): ?>
            <div style="background: #fee2e2; color: #b91c1c; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #f87171;">
                <?php echo $error_msg; ?>
            </div>
        <?php endif; ?>

        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">User Dashboard</h1>
            <p style="color: #6b7280; margin-top: 5px;">Welcome back, <strong><?php echo htmlspecialchars((string)$full_name); ?></strong>! Monitor your recent trojan detection activities.</p>
        </div>

        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span>Total Scans</span>
                    <div class="stat-icon icon-blue">📊</div>
                </div>
                <div class="stat-value"><?php echo $total_scans; ?></div>
                <div class="stat-label">Files analyzed by you</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Threats Detected</span>
                    <div class="stat-icon icon-red">⚠️</div>
                </div>
                <div class="stat-value"><?php echo $threats; ?></div>
                <div class="stat-label stat-danger">Malicious files found</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Clean Files</span>
                    <div class="stat-icon icon-green">✅</div>
                </div>
                <div class="stat-value"><?php echo $clean_files; ?></div>
                <div class="stat-label">Files marked as safe</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Avg Confidence</span>
                    <div class="stat-icon icon-purple">🎯</div>
                </div>
                <div class="stat-value"><?php echo number_format((float)$avg_acc, 1); ?>%</div>
                <div class="stat-label">Model detection accuracy</div>
            </div>
        </div>

        <!-- PROMINENT ACTION CARDS (Blue & Green) -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 30px;">
            <div style="background: #2563eb; color: white; padding: 30px; border-radius: 12px; display: flex; flex-direction: column; justify-content: space-between; min-height: 220px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <div>
                    <div style="margin-bottom: 20px;">
                        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                    </div>
                    <h3 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 10px;">Upload File for Scanning</h3>
                    <p style="color: #bfdbfe; font-size: 1rem; margin-bottom: 25px;">Scan your Windows files for trojan malware detection</p>
                </div>
                <a href="user_upload.php" style="display: inline-block; background: rgba(255, 255, 255, 0.2); color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; width: fit-content;">Start Scanning</a>
            </div>

            <div style="background: #10b981; color: white; padding: 30px; border-radius: 12px; display: flex; flex-direction: column; justify-content: space-between; min-height: 220px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <div>
                     <div style="margin-bottom: 20px;">
                        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="16" y1="13" x2="8" y2="13"></line>
                            <line x1="16" y1="17" x2="8" y2="17"></line>
                            <polyline points="10 9 9 9 8 9"></polyline>
                        </svg>
                    </div>
                    <h3 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 10px;">View Scan Reports</h3>
                    <p style="color: #d1fae5; font-size: 1rem; margin-bottom: 25px;">Access your scanning history and download reports</p>
                </div>
                <a href="user_history.php" style="display: inline-block; background: rgba(255, 255, 255, 0.2); color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; width: fit-content;">View History</a>
            </div>
        </div>

        <!-- Recent Scans Table -->
        <div class="table-card" style="background: white; padding: 25px; border-radius: 12px; margin-top: 30px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <div class="table-header">
                <h2 style="margin-bottom: 20px;">Your Recent Scans</h2>
            </div>
            <table width="100%" style="border-collapse: collapse; text-align: left;">
                <thead>
                    <tr style="border-bottom: 2px solid #f3f4f6; color: #6b7280; font-size: 0.85rem;">
                        <th style="padding: 10px;">FILE NAME</th>
                        <th>NETWORK INFO</th>
                        <th>SCAN DATE</th>
                        <th>RESULT</th>
                        <th>ACCURACY</th>
                        <th style="text-align: right;">ACTION</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(empty($recent_scans)): ?>
                        <tr><td colspan="5" style="text-align: center; padding: 30px; color: #9ca3af;">No scans found yet.</td></tr>
                    <?php else: ?>
                        <?php foreach($recent_scans as $scan): 
                            $res_text = $scan['scan_result'] ?? 'Unknown';
                            $isTrojan = (strpos(strtolower((string)$res_text), 'trojan') !== false);
                        ?>
                        <tr style="border-bottom: 1px solid #f3f4f6;">
                            <td style="padding: 15px; font-weight: 500;">
                                <?php 
                                    $display_name = $scan['file_name'] ?? 'Unknown';
                                    if(strpos($display_name, '_') !== false) $display_name = substr($display_name, strpos($display_name, '_') + 1);
                                    echo htmlspecialchars((string)$display_name); 
                                ?>
                            </td>
                            <td>
                                <div style="font-size:0.8rem; font-family:monospace; color:#374151;"><?= htmlspecialchars($scan['ip_address'] ?? 'N/A') ?></div>
                                <div style="font-size:0.75rem; color:#6b7280;"><?= htmlspecialchars($scan['pc_name'] ?? 'Unknown') ?></div>
                            </td>
                            <td style="color: #6b7280; font-size: 0.9rem;"><?php echo date('d M Y', strtotime($scan['scan_date'] ?? 'now')); ?></td>
                            <td>
                                <span class="badge" style="padding: 4px 10px; border-radius: 5px; font-size: 0.75rem; font-weight: bold; background: <?php echo $isTrojan ? '#fee2e2' : '#d1fae5'; ?>; color: <?php echo $isTrojan ? '#b91c1c' : '#065f46'; ?>;">
                                    <?php echo htmlspecialchars((string)$res_text); ?>
                                </span>
                            </td>
                            <td><strong><?php echo $scan['accuracy_score'] ?? 0; ?>%</strong></td>
                            <td style="text-align: right;">
                                <a href="generate_pdf.php?id=<?php echo $scan['scan_id'] ?? 0; ?>&download=1" download="TrojanDetect_Report_Scan_<?php echo $scan['scan_id'] ?? 0; ?>.pdf" style="color: #2563eb; text-decoration: none; font-weight: 600; font-size: 0.85rem;">PDF Report</a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
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

        <?php if(isset($_SESSION['login_success']) && $_SESSION['login_success']): ?>
            Swal.fire({
                title: 'Welcome Back!',
                text: 'You have successfully logged in.',
                icon: 'success',
                timer: 2000,
                showConfirmButton: false
            });
            <?php unset($_SESSION['login_success']); ?>
        <?php endif; ?>
    </script>
</body>
</html>