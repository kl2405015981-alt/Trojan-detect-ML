<?php
session_start();

// 1. SECURITY: Ensure only Admin can access
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

try {
    // 2. Connect to database
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 3. Process DELETE if request exists
    if (isset($_GET['delete_id'])) {
        $stmt = $db->prepare("DELETE FROM scans WHERE scan_id = ?");
        $stmt->execute([$_GET['delete_id']]);
        header("Location: admin_history.php?status=deleted");
        exit;
    }

    // 3.5. Process CLEAR ALL if request exists
    if (isset($_GET['clear_all']) && $_GET['clear_all'] == '1') {
        $db->exec("PRAGMA foreign_keys = OFF;");
        $db->exec("DELETE FROM audit_history;");
        $db->exec("DELETE FROM threat_logs;");
        $db->exec("DELETE FROM reports;");
        $db->exec("DELETE FROM scans;");
        $db->exec("DELETE FROM files;");
        $db->exec("UPDATE sqlite_sequence SET seq = 0 WHERE name IN ('audit_history', 'threat_logs', 'reports', 'scans', 'files');");
        $db->exec("PRAGMA foreign_keys = ON;");

        // Clear uploads folder
        $upload_dir = 'uploads/';
        if (is_dir($upload_dir)) {
            $files = array_diff(scandir($upload_dir), array('.', '..'));
            foreach ($files as $file) {
                $file_path = "$upload_dir/$file";
                if (is_file($file_path)) {
                    @unlink($file_path);
                }
            }
        }
        header("Location: admin_history.php?status=cleared");
        exit;
    }

    // 4. Filtering Parameters
    $search = isset($_GET['search']) ? $_GET['search'] : '';
    $result_filter = isset($_GET['result']) ? $_GET['result'] : 'all';
    $timeframe = isset($_GET['timeframe']) ? $_GET['timeframe'] : 'all'; 
    
    date_default_timezone_set('Asia/Kuala_Lumpur');

    // Pagination
    $per_page = 10;
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;

    // 5. Build WHERE Clause
    $where_clause = "WHERE 1=1";
    $params = [];

    if (!empty($search)) {
        $where_clause .= " AND (u.full_name LIKE ? OR s.file_name LIKE ? OR s.scan_id LIKE ?)";
        $params[] = "%$search%"; $params[] = "%$search%"; $params[] = "%$search%";
    }

    if ($result_filter !== 'all') {
        if ($result_filter === 'safe') {
            $where_clause .= " AND s.scan_result = 'Safe'";
        } elseif ($result_filter === 'trojan') {
            $where_clause .= " AND s.scan_result LIKE '%Trojan%'";
        }
    }

    if ($timeframe !== 'all') {
        $days = (int)$timeframe;
        $cutoff_date = date('Y-m-d H:i:s', strtotime("-$days days"));
        $where_clause .= " AND s.scan_date >= ?";
        $params[] = $cutoff_date;
    }

    // 6. Total Records
    $count_sql = "SELECT COUNT(*) FROM scans s JOIN users u ON s.user_id = u.user_id " . $where_clause;
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total_records = $count_stmt->fetchColumn();
    $total_pages = max(1, ceil($total_records / $per_page));
    $page = min($page, $total_pages);
    $offset = ($page - 1) * $per_page;

    // Pagination display values
    $start_showing = $total_records > 0 ? $offset + 1 : 0;
    $end_showing = min($offset + $per_page, $total_records);

    // 7. Get Records
    $sql = "SELECT s.*, u.full_name as fullname, u.user_type as user_role 
            FROM scans s 
            JOIN users u ON s.user_id = u.user_id  
            " . $where_clause . " 
            ORDER BY s.scan_date DESC 
            LIMIT $per_page OFFSET $offset";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $scans = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Build base URL for pagination (preserve filters)
    $pagination_params = [];
    if (!empty($search)) $pagination_params['search'] = $search;
    if ($result_filter !== 'all') $pagination_params['result'] = $result_filter;
    if ($timeframe !== 'all') $pagination_params['timeframe'] = $timeframe;
    $base_query = http_build_query($pagination_params);
    $base_url = 'admin_history.php?' . ($base_query ? $base_query . '&' : '');

} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan History - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        .badge-danger { background: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: 600; }
        .badge-success { background: #d1fae5; color: #065f46; padding: 4px 8px; border-radius: 4px; font-weight: 600; }
        .confidence-bar { width: 100%; background: #e5e7eb; height: 6px; border-radius: 3px; margin-top: 4px; }
        .confidence-fill { height: 100%; border-radius: 3px; }
        .bg-danger { background: #ef4444; }
        .bg-success { background: #10b981; }
        .filter-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
        .search-wrapper { flex: 1; position: relative; min-width: 300px; }
        .search-input { width: 100%; padding: 12px 16px 12px 40px; border: 1px solid #e5e7eb; border-radius: 8px; outline: none; }
        .segmented-control { background: #f3f4f6; padding: 4px; border-radius: 8px; display: inline-flex; }
        .segment-btn { padding: 8px 16px; border: none; background: transparent; cursor: pointer; border-radius: 6px; font-weight: 600; font-size: 0.85rem; color: #6b7280; text-decoration: none; }
        .segment-btn.active { background: #2563eb; color: white; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal { background: white; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .actions-cell { display: flex; justify-content: center; gap: 8px; }
        .action-btn { display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 6px; text-decoration: none; font-size: 0.8rem; font-weight: 500; transition: all 0.2s ease; border: none; background: transparent; cursor: pointer; }
        .action-btn svg { width: 16px; height: 16px; margin-right: 4px; }
        .action-btn.view { color: #2563eb; }
        .action-btn.view:hover { background-color: #eff6ff; }
        .action-btn.download { color: #059669; }
        .action-btn.download:hover { background-color: #ecfdf5; }
        .action-btn.delete { color: #dc2626; }
        .action-btn.delete:hover { background-color: #fef2f2; }
        .latest-scan-card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 24px; border-left: 5px solid #10b981; }
        .latest-scan-card.trojan { border-left-color: #ef4444; }
        .status-pill { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
        .status-pill.safe { background: #d1fae5; color: #065f46; }
        .status-pill.trojan { background: #fee2e2; color: #991b1b; }
        .status-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
        .status-pill.safe .status-dot { background: #059669; }
        .status-pill.trojan .status-dot { background: #dc2626; }
        .history-table { width: 100%; border-collapse: separate; border-spacing: 0; background: white; border-radius: 12px; }
        .history-table th { background: #f9fafb; padding: 16px 24px; text-align: left; font-size: 0.75rem; font-weight: 700; color: #6b7280; text-transform: uppercase; border-bottom: 1px solid #e5e7eb; }
        .history-table td { padding: 16px 24px; border-bottom: 1px solid #f3f4f6; color: #374151; font-size: 0.875rem; }

        /* Pagination Styles */
        .pagination-wrapper {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding: 1rem 1.5rem;
            border-top: 1px solid #e5e7eb;
            gap: 0.4rem;
            flex-wrap: wrap;
        }
        .pagination-info {
            font-size: 0.875rem;
            color: #6b7280;
            margin-right: 0.75rem;
        }
        .page-btn {
            padding: 6px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            background: white;
            color: #374151;
            font-size: 0.875rem;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 36px;
            transition: all 0.2s;
            cursor: pointer;
        }
        .page-btn:hover:not(.disabled):not(.active) {
            background: #f3f4f6;
        }
        .page-btn.active {
            background: #2563eb;
            border-color: #2563eb;
            color: white;
            font-weight: 600;
            cursor: default;
        }
        .page-btn.disabled {
            background: #f9fafb;
            color: #9ca3af;
            cursor: not-allowed;
        }
    </style>
</head>

<body class="dashboard-page">

    <?php $active_page = 'history'; ?>
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:30px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <div>
                    <h2 style="font-size:1.2rem; margin:0;">TrojanDetect</h2>
                    <p style="font-size:0.7rem; margin:0;"></p>
                </div>
            </div>
        </div>

        <nav class="sidebar-nav">
            <a href="admin_dashboard.php" class="nav-item <?= ($active_page === 'dashboard') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <rect x="3" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2"/>
                </svg>
                Dashboard
            </a>
            <a href="admin_uploadfile.php" class="nav-item <?= ($active_page === 'scanner') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2"/>
                </svg>
                File Scanner
            </a>
            <a href="admin_history.php" class="nav-item <?= ($active_page === 'history') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <polyline points="12 6 12 12 16 14" stroke-width="2"/>
                </svg>
                Scan History
            </a>

            <div class="nav-section" style="margin-top:20px;padding:10px;font-size:0.7rem;opacity:0.5;">ADMIN FUNCTIONS</div>

            <a href="admin_manageuser.php" class="nav-item <?= ($active_page === 'manageuser') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2"/>
                    <circle cx="9" cy="7" r="4" stroke-width="2"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke-width="2"/>
                </svg>
                Manage Users
            </a>
            <a href="admin_manage_ml.php" class="nav-item <?= ($active_page === 'ml') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <rect x="2" y="3" width="20" height="14" rx="2" stroke-width="2"/>
                    <line x1="8" y1="21" x2="16" y2="21" stroke-width="2"/>
                    <line x1="12" y1="17" x2="12" y2="21" stroke-width="2"/>
                </svg>
                ML &amp; Dataset
            </a>
            <a href="reports.php" class="nav-item <?= ($active_page === 'reports') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-width="2"/>
                    <polyline points="14 2 14 8 20 8" stroke-width="2"/>
                </svg>
                Generate Report
            </a>
            <a href="admin_manual.php" class="nav-item <?= ($active_page === 'manual') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Admin Manual
            </a>
        </nav>

        <div class="sidebar-footer" style="padding:20px; border-top:1px solid rgba(255,255,255,0.1);">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                <div style="background:#2563eb;padding:8px 12px;border-radius:50%;font-weight:600;color:white;">
                    <?= substr($_SESSION['full_name'] ?? 'A', 0, 1) ?>
                </div>
                <div>
                    <p style="margin:0;font-weight:bold;font-size:0.9rem;color:white;">
                        <?= htmlspecialchars($_SESSION['full_name'] ?? 'Admin') ?>
                    </p>
                    <span style="font-size:0.7rem;opacity:0.7;color:#9ca3af;">
                        <?= htmlspecialchars($_SESSION['email'] ?? 'admin@system.com') ?>
                    </span>
                </div>
            </div>
            <a href="logout.php" id="logoutBtn" style="background:#dc2626;color:white;text-decoration:none;font-size:0.9rem;display:flex;align-items:center;gap:6px;padding:10px 16px;border-radius:8px;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:16px;height:16px;">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Logout
            </a>
        </div>
    </div>

    <div id="sidebarOverlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:99;" onclick="document.getElementById('sidebar').classList.remove('open'); this.style.display='none';"></div>

    <div class="main-content" style="margin-left: 260px; padding: 30px; background: #f9fafb; min-height: 100vh;">
        <div class="page-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px;">
            <div>
                <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0;">Scan History</h1>
                <p style="color: #6b7280; margin-top: 5px;">Monitor all system security activities and ML results across all users.</p>
            </div>
            <button onclick="confirmClearAll()" style="padding: 10px 20px; background: #dc2626; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 8px; transition: background 0.2s;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Clear All History
            </button>
        </div>

        <?php if($page == 1 && !empty($scans)): 
            $latest = $scans[0];
            $l_result = $latest['scan_result'] ?? 'Unknown';
            $l_isTrojan = (strpos(strtolower($l_result), 'trojan') !== false);
            $l_displayDate = date('d M Y, h:i A', strtotime($latest['scan_date'] ?? 'now'));
        ?>
        <div class="latest-scan-card <?= $l_isTrojan ? 'trojan' : '' ?>">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                <div>
                    <div style="font-size: 0.75rem; color: #6b7280; font-weight: 700; text-transform: uppercase;">Latest System Scan</div>
                    <div style="font-size: 1.5rem; font-weight: 800; color: #111827; display: flex; align-items: center; gap: 10px;">
                        #SCAN-<?= $latest['scan_id'] ?>
                        <span class="status-pill <?= $l_isTrojan ? 'trojan' : 'safe' ?>">
                            <span class="status-dot"></span><?= htmlspecialchars($l_result) ?>
                        </span>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size: 0.75rem; color: #6b7280; font-weight: 700; text-transform: uppercase;">Timestamp</div>
                    <div style="font-size:1.1rem; font-weight:600; color:#374151;"><?= $l_displayDate ?></div>
                </div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 24px;">
                <div>
                    <label style="display: block; font-size: 0.75rem; color: #6b7280; margin-bottom: 6px;">File Name</label>
                    <div style="font-weight: 600; color: #1f2937;"><?= htmlspecialchars($latest['file_name'] ?? 'N/A') ?></div>
                </div>
                <div>
                    <label style="display: block; font-size: 0.75rem; color: #6b7280; margin-bottom: 6px;">Uploader</label>
                    <div style="font-weight: 600; color: #1f2937;"><?= htmlspecialchars($latest['fullname'] ?? 'System') ?></div>
                </div>
                <div>
                    <label style="display: block; font-size: 0.75rem; color: #6b7280; margin-bottom: 6px;">Accuracy Level</label>
                    <div style="font-weight: 600; color: #1f2937;">
                        <span><?= $latest['accuracy_score'] ?? 0 ?>%</span>
                        <div class="confidence-bar"><div class="confidence-fill <?= $l_isTrojan ? 'bg-danger' : 'bg-success' ?>" style="width:<?= $latest['accuracy_score'] ?? 0 ?>%"></div></div>
                    </div>
                </div>
                <div style="display:flex; flex-direction:column; gap:8px;">
                    <a href="generate_pdf.php?id=<?= $latest['scan_id'] ?>&download=1" download="TrojanDetect_Report_Scan_<?= $latest['scan_id'] ?>.pdf" style="text-align:center; padding:10px; background:#2563eb; color:white; text-decoration:none; border-radius:6px; font-weight:600; font-size:0.85rem;">Download Full Report</a>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <form method="GET">
            <div class="filter-card">
                <div class="search-wrapper">
                    <input type="text" name="search" class="search-input" placeholder="Search Scan ID, User, or Filename..." value="<?= htmlspecialchars($search) ?>">
                    <svg style="position:absolute; left:12px; top:12px; width:20px; color:#9ca3af;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                </div>
                <div class="segmented-control">
                    <a href="?result=all&search=<?= urlencode($search) ?>&timeframe=<?= $timeframe ?>" class="segment-btn <?= $result_filter == 'all' ? 'active' : '' ?>">All</a>
                    <a href="?result=safe&search=<?= urlencode($search) ?>&timeframe=<?= $timeframe ?>" class="segment-btn <?= $result_filter == 'safe' ? 'active' : '' ?>">Safe</a>
                    <a href="?result=trojan&search=<?= urlencode($search) ?>&timeframe=<?= $timeframe ?>" class="segment-btn <?= $result_filter == 'trojan' ? 'active' : '' ?>">Trojan</a>
                </div>
                <select name="timeframe" onchange="this.form.submit()" style="padding:10px; border-radius:8px; border:1px solid #e5e7eb; outline:none;">
                    <option value="all" <?= $timeframe == 'all' ? 'selected' : '' ?>>All Time</option>
                    <option value="1" <?= $timeframe == '1' ? 'selected' : '' ?>>Last 24 Hours</option>
                    <option value="7" <?= $timeframe == '7' ? 'selected' : '' ?>>Last 7 Days</option>
                    <option value="30" <?= $timeframe == '30' ? 'selected' : '' ?>>Last 30 Days</option>
                </select>
                <button type="submit" class="btn-primary" style="padding: 12px 24px; border:none; background:#2563eb; color:white; border-radius:8px; cursor:pointer; font-weight:600;">Apply Filters</button>
            </div>
        </form>

        <div style="background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden;">
            <table class="history-table">
                <thead>
                    <tr>
                        <th width="10%">ID</th>
                        <th width="15%">Date & Time</th>
                        <th width="12%">Uploader</th>
                        <th width="15%">File Name</th>
                        <th width="12%">IP / PC Name</th>
                        <th width="12%">Result</th>
                        <th width="8%">Accuracy</th>
                        <th width="12%" style="text-align:center;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(empty($scans)): ?>
                        <tr><td colspan="7" style="text-align:center; padding:40px; color:#6b7280;">No scan records found.</td></tr>
                    <?php else: ?>
                        <?php foreach($scans as $row): 
                            $row_result = $row['scan_result'] ?? 'Unknown';
                            $isTrojan = (strpos(strtolower($row_result), 'trojan') !== false);
                            $displayDate = date('d M Y, H:i', strtotime($row['scan_date'] ?? 'now'));
                        ?>
                        <tr>
                            <td style="font-weight:600; color:#2563eb;">#SCAN-<?= $row['scan_id'] ?></td>
                            <td style="color:#6b7280;"><?= $displayDate ?></td>
                            <td><strong><?= htmlspecialchars($row['fullname'] ?? 'N/A') ?></strong></td>
                            <td style="font-family:monospace;" title="<?= htmlspecialchars($row['file_name'] ?? 'Unknown') ?>">
                                <?= htmlspecialchars(strlen($row['file_name']) > 20 ? substr($row['file_name'],0,20).'...' : $row['file_name']) ?>
                            </td>
                            <td>
                                <div style="font-size:0.8rem; font-family:monospace; color:#374151;"><?= htmlspecialchars($row['ip_address'] ?? 'N/A') ?></div>
                                <div style="font-size:0.75rem; color:#6b7280;"><?= htmlspecialchars($row['pc_name'] ?? 'Unknown') ?></div>
                            </td>
                            <td>
                                <span class="status-pill <?= $isTrojan ? 'trojan' : 'safe' ?>">
                                    <span class="status-dot"></span><?= htmlspecialchars($row_result) ?>
                                </span>
                            </td>
                            <td><?= $row['accuracy_score'] ?? 0 ?>%</td>
                            <td>
                                <div class="actions-cell">
                                    <button onclick="viewScan(this)" 
                                        data-id="<?= $row['scan_id'] ?>"
                                        data-date="<?= $displayDate ?>"
                                        data-user="<?= htmlspecialchars($row['fullname'] ?? 'N/A') ?>"
                                        data-file="<?= htmlspecialchars($row['file_name'] ?? 'Unknown') ?>"
                                        data-result="<?= htmlspecialchars($row_result) ?>"
                                        data-score="<?= $row['accuracy_score'] ?? 0 ?>"
                                        data-ip="<?= htmlspecialchars($row['ip_address'] ?? 'N/A') ?>"
                                        data-pc="<?= htmlspecialchars($row['pc_name'] ?? 'Unknown') ?>"
                                        data-istrojan="<?= $isTrojan ? 'true' : 'false' ?>"
                                        class="action-btn view" title="Quick View">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                        View
                                    </button>
                                    <a href="generate_pdf.php?id=<?= $row['scan_id'] ?>&download=1" download="TrojanDetect_Report_Scan_<?= $row['scan_id'] ?>.pdf" class="action-btn download" title="Download PDF">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                        Download
                                    </a>
                                    <button onclick="confirmDelete(<?= $row['scan_id'] ?>)" class="action-btn delete" title="Delete">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                        Delete
                                    </button>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>

            <!-- ===== PAGINATION ===== -->
            <div class="pagination-wrapper">
                <!-- Showing X to Y of Z results -->
                <span class="pagination-info">
                    <?php if ($total_records > 0): ?>
                        Showing <?= $start_showing ?> to <?= $end_showing ?> of <?= $total_records ?> results
                    <?php else: ?>
                        No results found
                    <?php endif; ?>
                </span>

                <!-- Prev Button -->
                <?php if ($page <= 1): ?>
                    <span class="page-btn disabled">Prev</span>
                <?php else: ?>
                    <a href="<?= $base_url ?>page=<?= $page - 1 ?>" class="page-btn">Prev</a>
                <?php endif; ?>

                <!-- Page Number Buttons -->
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <?php if ($i === $page): ?>
                        <span class="page-btn active"><?= $i ?></span>
                    <?php else: ?>
                        <a href="<?= $base_url ?>page=<?= $i ?>" class="page-btn"><?= $i ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <!-- Next Button -->
                <?php if ($page >= $total_pages): ?>
                    <span class="page-btn disabled">Next</span>
                <?php else: ?>
                    <a href="<?= $base_url ?>page=<?= $page + 1 ?>" class="page-btn">Next</a>
                <?php endif; ?>
            </div>
            <!-- ===== END PAGINATION ===== -->

        </div>
    </div>

    <!-- Quick View Modal -->
    <div id="viewModal" class="modal-overlay" onclick="if(event.target === this) closeViewModal()">
        <div class="modal">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:1px solid #e5e7eb; padding-bottom:10px;">
                <h2 style="margin:0; font-size:1.25rem; color:#1f2937;">Scan Technical Details</h2>
                <button onclick="closeViewModal()" style="background:none; border:none; font-size:1.5rem; cursor:pointer; color:#6b7280;">&times;</button>
            </div>
            <div id="modalContent"></div>
            <div style="margin-top:20px; text-align:right;">
                <button onclick="closeViewModal()" style="padding:10px 20px; background:#f3f4f6; color:#374151; border:none; border-radius:8px; cursor:pointer; font-weight:600;">Close Preview</button>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        function viewScan(btn) {
            const modal = document.getElementById('viewModal');
            const content = document.getElementById('modalContent');
            const data = btn.dataset;
            const isTrojan = data.istrojan === 'true';
            const badgeClass = isTrojan ? 'badge-danger' : 'badge-success';
            const fillClass = isTrojan ? 'bg-danger' : 'bg-success';
            
            content.innerHTML = `
                <div style="margin-bottom:15px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div>
                        <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">Reference ID</label>
                        <div style="font-weight:bold; color:#2563eb;">#SCAN-${data.id}</div>
                    </div>
                    <div>
                        <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">Date Processed</label>
                        <div>${data.date}</div>
                    </div>
                </div>
                <div style="margin-bottom:15px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div>
                        <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">Performed By</label>
                        <div style="font-weight:600;">${data.user}</div>
                    </div>
                    <div>
                        <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">Network Source</label>
                        <div style="font-size:0.85rem;"><span style="font-family:monospace; color:#2563eb;">${data.ip}</span> (${data.pc})</div>
                    </div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">File Name</label>
                    <div style="word-break:break-all; font-family:monospace;">${data.file}</div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">Analysis Result</label>
                    <div><span class="${badgeClass}" style="font-size:1rem;">${data.result}</span></div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.7rem; color:#6b7280; font-weight:700; text-transform:uppercase; margin-bottom:4px;">ML Accuracy</label>
                    <div>
                        <div style="margin-bottom:4px;"><strong>${data.score}%</strong> Confidence</div>
                        <div class="confidence-bar" style="height:10px;"><div class="confidence-fill ${fillClass}" style="width:${data.score}%"></div></div>
                    </div>
                </div>
                <div style="margin-top:20px; padding-top:15px; border-top:1px solid #eee; display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                    <a href="generate_pdf.php?id=${data.id}&download=1" download="TrojanDetect_Report_Scan_${data.id}.pdf" style="text-align:center; padding:10px; background:white; border:1px solid #d1d5db; border-radius:8px; text-decoration:none; color:#374151; font-weight:600; font-size:0.85rem;">📄 Download PDF</a>
                    <a href="admin_uploadfile.php" style="text-align:center; padding:10px; background:#2563eb; color:white; border-radius:8px; text-decoration:none; font-weight:600; font-size:0.85rem;">🔄 New Scan</a>
                </div>
            `;
            modal.style.display = 'flex';
        }

        function closeViewModal() {
            document.getElementById('viewModal').style.display = 'none';
        }

        function confirmDelete(id) {
            Swal.fire({
                text: "Permanently delete this scan record? This cannot be undone.",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'admin_history.php?delete_id=' + id;
                }
            });
        }

        function confirmClearAll() {
            Swal.fire({
                title: 'Clear ALL History?',
                text: "This will permanently delete all scan records, threats logs, reports, and uploaded files. You won't be able to revert this!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, clear everything!'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'admin_history.php?clear_all=1';
                }
            });
        }

        document.addEventListener('DOMContentLoaded', function() {
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('status') === 'cleared') {
                Swal.fire({
                    title: 'Cleared!',
                    text: 'All history, reports, and files have been deleted.',
                    icon: 'success',
                    timer: 2000,
                    showConfirmButton: false
                });
                window.history.replaceState({}, document.title, "admin_history.php");
            } else if (urlParams.get('status') === 'deleted') {
                Swal.fire({
                    title: 'Deleted!',
                    text: 'The scan record has been deleted.',
                    icon: 'success',
                    timer: 2000,
                    showConfirmButton: false
                });
                window.history.replaceState({}, document.title, "admin_history.php");
            }
        });

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