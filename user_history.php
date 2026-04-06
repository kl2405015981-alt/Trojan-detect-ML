<?php
session_start();

// 1. SECURITY: Block access if not a valid user
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] === 'admin') {
    header("Location: login.php");
    exit;
}

$user_id   = $_SESSION['user_id'] ?? 0;
$full_name = $_SESSION['full_name'] ?? 'User';
$email     = $_SESSION['email'] ?? 'user@gmail.com';

// 2. Search & Filter
$search        = $_GET['search'] ?? '';
$filter_result = $_GET['result'] ?? 'All';

// Pagination setup
$records_per_page = 10;
$current_page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $query = "SELECT * FROM scans WHERE user_id = :user_id";
    
    if ($search !== '') {
        $query .= " AND file_name LIKE :search";
    }
    
    if ($filter_result !== 'All') {
        if ($filter_result === 'Safe') {
            $query .= " AND scan_result = 'Safe'";
        } else {
            $query .= " AND scan_result LIKE '%Trojan%'";
        }
    }

    $query .= " ORDER BY scan_date DESC";
    
    $stmt = $db->prepare($query);
    $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
    
    if ($search !== '') {
        $stmt->bindValue(':search', "%$search%", PDO::PARAM_STR);
    }
    
    $stmt->execute();
    $all_scans = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Pagination calculation
    $total_records = count($all_scans);
    $total_pages = max(1, ceil($total_records / $records_per_page));
    $current_page = min($current_page, $total_pages);
    $start_index = ($current_page - 1) * $records_per_page;
    $scans = array_slice($all_scans, $start_index, $records_per_page);

    // For display "Showing X to Y of Z"
    $start_showing = $total_records > 0 ? $start_index + 1 : 0;
    $end_showing = min($start_index + $records_per_page, $total_records);

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
        .main-content { margin-left: 260px; padding: 30px; background: #f9fafb; min-height: 100vh; }
        .filter-section { background: white; padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #f0f0f0; }
        .filter-grid { display: grid; grid-template-columns: 1fr 1fr 1.5fr; gap: 1.5rem; align-items: flex-end; }
        .filter-item label { display: block; font-size: 0.8rem; font-weight: 600; color: #6b7280; margin-bottom: 0.5rem; }
        select, input[type="text"] { width: 100%; padding: 0.6rem; border: 1px solid #d1d5db; border-radius: 8px; font-size: 0.9rem; }
        .table-section { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #f0f0f0; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        thead { background: #f8fafc; border-bottom: 2px solid #f1f5f9; }
        th { padding: 1rem; font-size: 0.75rem; font-weight: 700; color: #64748b; text-transform: uppercase; }
        td { padding: 1rem; font-size: 0.9rem; border-bottom: 1px solid #f1f5f9; color: #334155; }
        .badge { padding: 4px 12px; border-radius: 20px; font-weight: 700; font-size: 0.75rem; display: inline-block; }
        .badge-safe { background: #d1fae5; color: #065f46; }
        .badge-trojan { background: #fee2e2; color: #991b1b; }
        .empty-state { text-align: center; padding: 4rem 2rem; color: #94a3b8; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal { background: white; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .actions-cell { display: flex; justify-content: flex-end; gap: 8px; }
        .action-btn { display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 6px; text-decoration: none; font-size: 0.8rem; font-weight: 500; transition: all 0.2s ease; border: 1px solid transparent; background: transparent; cursor: pointer; }
        .action-btn svg { width: 16px; height: 16px; margin-right: 4px; }
        .action-btn.view { color: #2563eb; border-color: #dbeafe; background: #eff6ff; }
        .action-btn.view:hover { background-color: #dbeafe; }
        .action-btn.download { color: #059669; border-color: #d1fae5; background: #ecfdf5; }
        .action-btn.download:hover { background-color: #d1fae5; }
        .confidence-bar { width: 100%; background: #e5e7eb; height: 6px; border-radius: 3px; margin-top: 4px; }
        .confidence-fill { height: 100%; border-radius: 3px; }
        .bg-danger { background: #ef4444; }
        .bg-success { background: #10b981; }
        .badge-danger { background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; }
        .badge-success { background: #d1fae5; color: #065f46; padding: 2px 8px; border-radius: 4px; }

        /* Pagination Styles */
        .pagination-wrapper {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding: 1rem 1.5rem;
            border-top: 1px solid #f1f5f9;
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
                    <h2>TrojanDetect</h2>
                    <p></p>
                </div>
            </div>
        </div>

        <nav class="sidebar-nav">
            <a href="user_dashboard.php" class="nav-item <?= ($active_page === 'dashboard') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <rect x="3" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Dashboard
            </a>
            <a href="user_upload.php" class="nav-item <?= ($active_page === 'scanner') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                File Scanner
            </a>
            <a href="user_history.php" class="nav-item <?= ($active_page === 'history') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Scan History
            </a>
            <a href="user_settings.php" class="nav-item <?= ($active_page === 'settings') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <circle cx="12" cy="12" r="3" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Settings
            </a>
            <a href="user_manual.php" class="nav-item <?= ($active_page === 'manual') ? 'active' : '' ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                User Manual
            </a>
        </nav>

        <div class="sidebar-footer">
            <div class="user-profile" style="background:transparent; padding:0; margin-bottom:1rem; display:flex; align-items:center; gap:0.75rem;">
                <div class="user-avatar" style="background:#3b82f6; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-weight:bold; flex-shrink:0;">
                    <?= htmlspecialchars(substr((string)$full_name, 0, 1)) ?>
                </div>
                <div class="user-info" style="flex:1; min-width:0;">
                    <div class="user-name" style="color:white; font-size:0.875rem; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        <?= htmlspecialchars((string)$full_name) ?>
                    </div>
                    <div class="user-email" style="color:#9ca3af; font-size:0.75rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        <?= htmlspecialchars((string)$email) ?>
                    </div>
                </div>
            </div>
            <a href="#" id="logoutBtn" onclick="logout(); return false;" class="logout-btn" style="width:100%; padding:0.75rem; background:#dc2626; color:white; border:none; border-radius:0.5rem; cursor:pointer; font-size:0.875rem; font-weight:600; display:flex; align-items:center; justify-content:center; gap:0.5rem; text-decoration:none; transition:all 0.3s;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px; flex-shrink:0;">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Logout
            </a>
        </div>
    </div>

    <div id="sidebarOverlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:99;" onclick="document.getElementById('sidebar').classList.remove('open'); this.style.display='none';"></div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">Scan History</h1>
            <p style="color: #6b7280; margin-top: 5px;">View all your previous machine learning analysis reports</p>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <form method="GET" action="user_history.php" class="filter-grid">
                <div class="filter-item">
                    <label>Filter by Result</label>
                    <select name="result" onchange="this.form.submit()">
                        <option value="All" <?= $filter_result === 'All' ? 'selected' : '' ?>>All Results</option>
                        <option value="Safe" <?= $filter_result === 'Safe' ? 'selected' : '' ?>>Safe</option>
                        <option value="Trojan" <?= $filter_result === 'Trojan' ? 'selected' : '' ?>>Trojan Detected</option>
                    </select>
                </div>
                <div class="filter-item">
                    <label>Search Filename</label>
                    <input type="text" name="search" placeholder="e.g. setup.exe" value="<?= htmlspecialchars((string)$search) ?>">
                </div>
                <div class="filter-item">
                    <button type="submit" class="btn-primary" style="padding: 0.7rem 1.5rem; width: 100%;">Apply Filters</button>
                </div>
            </form>
        </div>

        <!-- Table Section -->
        <div class="table-section">
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">No.</th>
                        <th style="width: 25%;">File Name</th>
                        <th style="width: 15%;">Scan Date</th>
                        <th style="width: 15%;">IP / PC Name</th>
                        <th style="width: 15%;">Result</th>
                        <th style="width: 15%;">Accuracy</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($scans)): ?>
                        <tr>
                            <td colspan="6" class="empty-state">
                                <p>No records found matching your criteria.</p>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php 
                            $counter = $start_index + 1;
                            foreach ($scans as $scan): 
                            $res_val = $scan['scan_result'] ?? 'Unknown';
                            $isTrojan = (strpos(strtolower((string)$res_val), 'trojan') !== false);
                            $displayDate = date('d M Y, H:i', strtotime($scan['scan_date'] ?? 'now'));
                            $display_name = $scan['file_name'] ?? 'Unknown';
                            if(strpos($display_name, '_') !== false) $display_name = substr($display_name, strpos($display_name, '_') + 1);
                        ?>
                            <tr>
                                <td style="font-weight: 600; color: #64748b;"><?= $counter++ ?></td>
                                <td style="font-weight: 600; word-break: break-all;" title="<?= htmlspecialchars((string)$display_name) ?>">
                                    <?= htmlspecialchars(strlen((string)$display_name) > 25 ? substr((string)$display_name,0,25).'...' : (string)$display_name) ?>
                                </td>
                                <td><?= $displayDate ?></td>
                                <td>
                                    <div style="font-size:0.85rem; font-family:monospace; color:#334155;"><?= htmlspecialchars($scan['ip_address'] ?? 'N/A') ?></div>
                                    <div style="font-size:0.75rem; color:#64748b;"><?= htmlspecialchars($scan['pc_name'] ?? 'Unknown') ?></div>
                                </td>
                                <td>
                                    <span class="badge <?= $isTrojan ? 'badge-trojan' : 'badge-safe' ?>">
                                        <?= htmlspecialchars((string)$res_val) ?>
                                    </span>
                                </td>
                                <td><strong><?= number_format((float)($scan['accuracy_score'] ?? 0), 1) ?>%</strong></td>
                                <td style="text-align: right;">
                                    <div class="actions-cell">
                                        <button type="button" onclick="viewScan(this)" 
                                            data-id="<?= $scan['scan_id'] ?>"
                                            data-date="<?= $displayDate ?>"
                                            data-user="<?= htmlspecialchars((string)$full_name) ?>"
                                            data-file="<?= htmlspecialchars((string)$display_name) ?>"
                                            data-result="<?= htmlspecialchars((string)$res_val) ?>"
                                            data-score="<?= (float)($scan['accuracy_score'] ?? 0) ?>"
                                            data-ip="<?= htmlspecialchars($scan['ip_address'] ?? 'N/A') ?>"
                                            data-pc="<?= htmlspecialchars($scan['pc_name'] ?? 'Unknown') ?>"
                                            data-istrojan="<?= $isTrojan ? 'true' : 'false' ?>"
                                            class="action-btn view" title="View Detail">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                                            </svg>
                                            View Detail
                                        </button>
                                        <a href="generate_pdf.php?id=<?= $scan['scan_id'] ?>&download=1" download="TrojanDetect_Report_Scan_<?= $scan['scan_id'] ?>.pdf" class="action-btn download" title="Download Report">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                                            </svg>
                                            Report
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>

            <!-- ===== PAGINATION ===== -->
            <?php
                // Build base URL preserving search/filter params
                $pagination_params = [];
                if ($search !== '') $pagination_params['search'] = $search;
                if ($filter_result !== 'All') $pagination_params['result'] = $filter_result;
                $base_query = http_build_query($pagination_params);
                $base_url = 'user_history.php?' . ($base_query ? $base_query . '&' : '');
            ?>
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
                <?php if ($current_page <= 1): ?>
                    <span class="page-btn disabled">Prev</span>
                <?php else: ?>
                    <a href="<?= $base_url ?>page=<?= $current_page - 1 ?>" class="page-btn">Prev</a>
                <?php endif; ?>

                <!-- Page Number Buttons -->
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <?php if ($i === $current_page): ?>
                        <span class="page-btn active"><?= $i ?></span>
                    <?php else: ?>
                        <a href="<?= $base_url ?>page=<?= $i ?>" class="page-btn"><?= $i ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <!-- Next Button -->
                <?php if ($current_page >= $total_pages): ?>
                    <span class="page-btn disabled">Next</span>
                <?php else: ?>
                    <a href="<?= $base_url ?>page=<?= $current_page + 1 ?>" class="page-btn">Next</a>
                <?php endif; ?>
            </div>
            <!-- ===== END PAGINATION ===== -->

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
                if (result.isConfirmed) window.location.href = 'logout.php';
            });
        }

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
                        <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">Scan ID</label>
                        <div style="font-weight:bold; color:#2563eb;">#SCAN-${data.id}</div>
                    </div>
                    <div>
                        <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">Date</label>
                        <div>${data.date}</div>
                    </div>
                </div>
                <div style="margin-bottom:15px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div>
                        <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">User</label>
                        <div style="font-weight:600;">${data.user}</div>
                    </div>
                    <div>
                        <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">Network Info</label>
                        <div style="font-size:0.85rem;"><span style="font-family:monospace; color:#2563eb;">${data.ip}</span> (${data.pc})</div>
                    </div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">File Name</label>
                    <div style="word-break:break-all; font-family:monospace;">${data.file}</div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">Result</label>
                    <div><span class="${badgeClass}">${data.result}</span></div>
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:4px;">Confidence Score</label>
                    <div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                            <strong>${data.score}%</strong>
                        </div>
                        <div class="confidence-bar"><div class="confidence-fill ${fillClass}" style="width:${data.score}%"></div></div>
                    </div>
                </div>
                <div style="margin-top:20px; padding-top:20px; border-top:1px solid #e5e7eb;">
                    <a href="generate_pdf.php?id=${data.id}&download=1" download="TrojanDetect_Report_Scan_${data.id}.pdf" 
                       style="display:flex; align-items:center; justify-content:center; gap:8px; padding:10px; background:white; border:1px solid #d1d5db; border-radius:6px; color:#374151; text-decoration:none; font-weight:500;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px;" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Download Report
                    </a>
                </div>
            `;
            modal.style.display = 'flex';
        }

        function closeViewModal() {
            document.getElementById('viewModal').style.display = 'none';
        }
    </script>
</body>
</html>