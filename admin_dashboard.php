<?php
session_start();

// 1. SECURITY: Block access if not Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 2. Fetch Real Statistics
    $total_scans = $db->query("SELECT count(*) FROM scans")->fetchColumn() ?: 0;
    $total_threats = $db->query("SELECT count(*) FROM scans WHERE scan_result LIKE '%Trojan%'")->fetchColumn() ?: 0;
    $total_users = $db->query("SELECT count(*) FROM users")->fetchColumn() ?: 0;
    $model_accuracy = $db->query("SELECT accuracy FROM ml_models WHERE is_active = 1 LIMIT 1")->fetchColumn() ?: 94.5;

    // Count training samples from CSV
    $training_samples = 0;
    if (file_exists('malware_dataset.csv')) {
        $file_handle = fopen('malware_dataset.csv', 'r');
        while (!feof($file_handle)) {
            if (fgets($file_handle) !== false) $training_samples++;
        }
        fclose($file_handle);
        if ($training_samples > 0) $training_samples--;
    }

    // 3. Fetch Recent Activities
    $query_recent = "SELECT s.*, u.full_name as uploader_name 
                     FROM scans s 
                     JOIN users u ON s.user_id = u.user_id 
                     ORDER BY s.scan_id DESC LIMIT 5";
    $recent_activities = $db->query($query_recent)->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css">
    <style>
        .stat-card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); position: relative; border: 1px solid #f0f0f0; }
        .stat-card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
        .stat-label { font-size: 0.875rem; color: #6b7280; font-weight: 500; }
        .stat-icon { width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }
        .stat-value { font-size: 2.25rem; font-weight: 700; margin-bottom: 8px; line-height: 1; }
        .stat-description { font-size: 0.8rem; color: #9ca3af; }
        .action-cards-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; margin-top: 30px; }
        .action-card { background: white; padding: 30px 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid #f0f0f0; cursor: pointer; transition: all 0.3s ease; text-decoration: none; display: block; }
        .action-card:hover { transform: translateY(-4px); box-shadow: 0 8px 16px rgba(0,0,0,0.12); }
        .action-card-icon { width: 48px; height: 48px; border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-bottom: 16px; }
        .action-card-title { font-size: 1.1rem; font-weight: 700; color: #1f2937; margin-bottom: 8px; }
        .action-card-description { font-size: 0.875rem; color: #6b7280; line-height: 1.5; margin-bottom: 16px; }
        .action-card-link { font-size: 0.875rem; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; }
        .table-card { background: white; margin-top: 30px; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid #f0f0f0; }
        .table-card h2 { font-size: 1.25rem; font-weight: 700; color: #1f2937; margin-bottom: 20px; }
        .activity-table { width: 100%; border-collapse: collapse; }
        .activity-table thead th { text-align: left; padding: 12px 16px; font-size: 0.75rem; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb; }
        .activity-table tbody td { padding: 16px; border-bottom: 1px solid #f3f4f6; font-size: 0.875rem; }
        .activity-table tbody tr:hover { background-color: #f9fafb; }
        .user-column { font-weight: 600; color: #2563eb; }
        .time-column { color: #6b7280; font-size: 0.8rem; }
        .result-badge { padding: 6px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
        .result-clean { background: #d1fae5; color: #065f46; }
        .result-trojan { background: #fee2e2; color: #991b1b; }
        .action-links { display: flex; gap: 12px; }
        .action-link { color: #2563eb; text-decoration: none; font-size: 0.875rem; font-weight: 500; }
        .action-link:hover { text-decoration: underline; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal { background: white; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .badge-danger { background: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: 600; }
        .badge-success { background: #d1fae5; color: #065f46; padding: 4px 8px; border-radius: 4px; font-weight: 600; }
        .confidence-bar { width: 100%; background: #e5e7eb; height: 6px; border-radius: 3px; margin-top: 4px; }
        .confidence-fill { height: 100%; border-radius: 3px; }
        .bg-danger { background: #ef4444; }
        .bg-success { background: #10b981; }
    </style>
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
            <a href="admin_dashboard.php" class="nav-item active">
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
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">Admin Dashboard</h1>
            <p style="color: #6b7280; margin-top: 5px;">Welcome back, Administrator! Monitor and manage the entire system.</p>
        </div>

        <!-- Statistics Cards -->
        <div class="stats-grid" style="display:grid; grid-template-columns: repeat(4, 1fr); gap:20px; margin-top:30px;">
            <div class="stat-card">
                <div class="stat-card-header">
                    <span class="stat-label">Total Scans</span>
                    <div class="stat-icon" style="background: #dbeafe; color: #2563eb;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:24px; height:24px;">
                            <path d="M9 11l3 3L22 4" stroke-width="2"/>
                            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" stroke-width="2"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value" style="color: #2563eb;"><?= number_format($total_scans) ?></div>
                <div class="stat-description">System wide scans</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <span class="stat-label">Threats Detected</span>
                    <div class="stat-icon" style="background: #fee2e2; color: #dc2626;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:24px; height:24px;">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke-width="2"/>
                            <line x1="12" y1="9" x2="12" y2="13" stroke-width="2"/>
                            <line x1="12" y1="17" x2="12.01" y2="17" stroke-width="2"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value" style="color: #dc2626;"><?= number_format($total_threats) ?></div>
                <div class="stat-description">Identified malware patterns</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <span class="stat-label">Total Users</span>
                    <div class="stat-icon" style="background: #e9d5ff; color: #9333ea;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:24px; height:24px;">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2"/>
                            <circle cx="9" cy="7" r="4" stroke-width="2"/>
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke-width="2"/>
                            <path d="M16 3.13a4 4 0 0 1 0 7.75" stroke-width="2"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value" style="color: #9333ea;"><?= number_format($total_users) ?></div>
                <div class="stat-description">Registered in system</div>
            </div>

            <div class="stat-card">
                <div class="stat-card-header">
                    <span class="stat-label">Model Accuracy</span>
                    <div class="stat-icon" style="background: #d1fae5; color: #16a34a;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:24px; height:24px;">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" stroke-width="2"/>
                        </svg>
                    </div>
                </div>
                <div class="stat-value" style="color: #16a34a;"><?= $model_accuracy ?>%</div>
                <div class="stat-description">Based on <?= number_format($training_samples) ?> samples</div>
            </div>
        </div>

        <!-- Action Cards -->
        <div class="action-cards-grid">
            <a href="admin_manageuser.php" class="action-card">
                <div class="action-card-icon" style="background: #dbeafe; color: #2563eb;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:26px; height:26px;">
                        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2"/>
                        <circle cx="9" cy="7" r="4" stroke-width="2"/>
                        <path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke-width="2"/>
                        <path d="M16 3.13a4 4 0 0 1 0 7.75" stroke-width="2"/>
                    </svg>
                </div>
                <div class="action-card-title">Manage Users</div>
                <div class="action-card-description">Add, edit, or remove user accounts and manage permissions</div>
                <div class="action-card-link" style="color: #2563eb;">Manage Users →</div>
            </a>

            <a href="admin_manage_ml.php" class="action-card">
                <div class="action-card-icon" style="background: #d1fae5; color: #16a34a;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:26px; height:26px;">
                        <rect x="2" y="3" width="20" height="14" rx="2" stroke-width="2"/>
                        <line x1="8" y1="21" x2="16" y2="21" stroke-width="2"/>
                        <line x1="12" y1="17" x2="12" y2="21" stroke-width="2"/>
                    </svg>
                </div>
                <div class="action-card-title">ML Model & Dataset</div>
                <div class="action-card-description">Update machine learning models and training datasets</div>
                <div class="action-card-link" style="color: #16a34a;">Manage ML →</div>
            </a>

            <a href="reports.php" class="action-card">
                <div class="action-card-icon" style="background: #e9d5ff; color: #9333ea;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:26px; height:26px;">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-width="2"/>
                        <polyline points="14 2 14 8 20 8" stroke-width="2"/>
                        <line x1="16" y1="13" x2="8" y2="13" stroke-width="2"/>
                        <line x1="16" y1="17" x2="8" y2="17" stroke-width="2"/>
                        <polyline points="10 9 9 9 8 9" stroke-width="2"/>
                    </svg>
                </div>
                <div class="action-card-title">Generate Reports</div>
                <div class="action-card-description">Create comprehensive reports for analysis and documentation</div>
                <div class="action-card-link" style="color: #9333ea;">Generate →</div>
            </a>
        </div>

        <!-- Recent System Activity Table -->
        <div class="table-card">
            <h2>Recent System Activity</h2>
            <table class="activity-table">
                <thead>
                    <tr>
                        <th>USER</th>
                        <th>FILE NAME</th>
                        <th>SOURCE IP</th>
                        <th>SCAN TIME</th>
                        <th>RESULT</th>
                        <th>ACCURACY</th>
                        <th>ACTION</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(empty($recent_activities)): ?>
                        <tr><td colspan="6" style="text-align:center; padding:20px; color:#9ca3af;">No recent activities found.</td></tr>
                    <?php else: ?>
                        <?php foreach($recent_activities as $log): 
                            $res_val = $log['scan_result'] ?? 'Unknown';
                            $isTrojan = (strpos(strtolower((string)$res_val), 'trojan') !== false);
                            $displayDate = date('d M Y, H:i', strtotime($log['scan_date'] ?? 'now'));
                        ?>
                        <tr>
                            <td class="user-column"><?= htmlspecialchars($log['uploader_name'] ?? 'Unknown') ?></td>
                            <td style="font-family: monospace;"><?= htmlspecialchars($log['file_name'] ?? 'N/A') ?></td>
                            <td>
                                <div style="font-size:0.8rem; font-family:monospace; color:#374151;"><?= htmlspecialchars($log['ip_address'] ?? 'N/A') ?></div>
                                <div style="font-size:0.75rem; color:#6b7280;"><?= htmlspecialchars($log['pc_name'] ?? 'Unknown') ?></div>
                            </td>
                            <td class="time-column">
                                <?php 
                                $timestamp = !empty($log['scan_date']) ? strtotime($log['scan_date']) : time();
                                $diff = time() - $timestamp;
                                if($diff < 3600) echo floor($diff / 60) . ' mins ago';
                                elseif($diff < 86400) echo floor($diff / 3600) . ' hours ago';
                                else echo floor($diff / 86400) . ' days ago';
                                ?>
                            </td>
                            <td>
                                <span class="result-badge <?= ($isTrojan ? 'result-trojan' : 'result-clean') ?>">
                                    <?= htmlspecialchars((string)$res_val) ?>
                                </span>
                            </td>
                            <td><strong><?= number_format((float)($log['accuracy_score'] ?? 0), 1) ?>%</strong></td>
                            <td>
                                <div class="action-links">
                                    <button onclick="viewScan(this)" 
                                        data-id="<?= $log['scan_id'] ?>"
                                        data-date="<?= $displayDate ?>"
                                        data-user="<?= htmlspecialchars($log['uploader_name'] ?? 'N/A') ?>"
                                        data-file="<?= htmlspecialchars($log['file_name'] ?? 'N/A') ?>"
                                        data-result="<?= htmlspecialchars((string)$res_val) ?>"
                                        data-score="<?= (float)($log['accuracy_score'] ?? 0) ?>" 
                                        data-ip="<?= htmlspecialchars($log['ip_address'] ?? 'N/A') ?>"
                                        data-pc="<?= htmlspecialchars($log['pc_name'] ?? 'Unknown') ?>"
                                        data-istrojan="<?= $isTrojan ? 'true' : 'false' ?>"
                                        class="action-link" style="background:none; border:none; cursor:pointer; padding:0; font-family:inherit;">
                                        View
                                    </button>
                                    <a href="generate_pdf.php?id=<?= $log['scan_id'] ?>&download=1" download="TrojanDetect_Report_Scan_<?= $log['scan_id'] ?>.pdf" class="action-link">Download</a>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- View Modal -->
    <div id="viewModal" class="modal-overlay" onclick="if(event.target === this) closeViewModal()">
        <div class="modal">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:1px solid #e5e7eb; padding-bottom:10px;">
                <h2 style="margin:0; font-size:1.25rem; color:#1f2937;">Scan Details</h2>
                <button onclick="closeViewModal()" style="background:none; border:none; font-size:1.5rem; cursor:pointer; color:#6b7280;">&times;</button>
            </div>
            <div id="modalContent"></div>
            <div style="margin-top:20px; text-align:right;">
                <button onclick="closeViewModal()" style="padding:8px 16px; background:#e5e7eb; color:#374151; border:none; border-radius:6px; cursor:pointer; font-weight:500;">Close</button>
            </div>
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

        <?php if(isset($_SESSION['login_success']) && $_SESSION['login_success']): ?>
            Swal.fire({ title: 'Welcome Back!', text: 'You have successfully logged in.', icon: 'success', timer: 2000, showConfirmButton: false });
            <?php unset($_SESSION['login_success']); ?>
        <?php endif; ?>

        function viewScan(btn) {
            const modal = document.getElementById('viewModal');
            const content = document.getElementById('modalContent');
            const data = btn.dataset;
            const isTrojan = data.istrojan === 'true';
            
            content.innerHTML = `
                <div style="margin-bottom:15px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Scan ID</label><div style="font-weight:bold; color:#2563eb;">#SCAN-${data.id}</div></div>
                    <div><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Date</label><div>${data.date}</div></div>
                </div>
                <div style="margin-bottom:15px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">User</label><div>${data.user}</div></div>
                    <div><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Network Info</label><div style="font-size:0.85rem;"><span style="font-family:monospace; color:#2563eb;">${data.ip}</span> (${data.pc})</div></div>
                </div>
                <div style="margin-bottom:15px;"><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">File Name</label><div style="word-break:break-all; font-family:monospace;">${data.file}</div></div>
                <div style="margin-bottom:15px;"><label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Result</label><div><span class="${isTrojan ? 'badge-danger' : 'badge-success'}">${data.result}</span></div></div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Confidence Score</label>
                    <div><strong>${data.score}%</strong></div>
                    <div class="confidence-bar"><div class="confidence-fill ${isTrojan ? 'bg-danger' : 'bg-success'}" style="width:${data.score}%"></div></div>
                </div>
                <div style="margin-top:20px; padding-top:20px; border-top:1px solid #e5e7eb;">
                    <a href="generate_pdf.php?id=${data.id}&download=1" download="TrojanDetect_Report_Scan_${data.id}.pdf" style="display:flex; align-items:center; justify-content:center; gap:8px; padding:10px; background:white; border:1px solid #d1d5db; border-radius:6px; color:#374151; text-decoration:none; font-weight:500;">📄 Download Report</a>
                </div>
            `;
            modal.style.display = 'flex';
        }

        function closeViewModal() { document.getElementById('viewModal').style.display = 'none'; }
    </script>
</body>
</html>