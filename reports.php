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

    // 2. Handle Delete Request
    if (isset($_GET['delete_id'])) {
        $stmt = $db->prepare("DELETE FROM reports WHERE report_id = ?");
        $stmt->execute([$_GET['delete_id']]);
        header("Location: reports.php?status=deleted");
        exit;
    }

    // Set Timezone
    date_default_timezone_set('Asia/Kuala_Lumpur');

    // Pagination setup
    $per_page = 10;
    $current_page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;

    // 3. Count total records
    $count_stmt = $db->query("SELECT COUNT(*) FROM reports r 
                               JOIN scans s ON r.scan_id = s.scan_id 
                               JOIN users u ON r.user_id = u.user_id");
    $total_records = $count_stmt->fetchColumn();
    $total_pages = max(1, ceil($total_records / $per_page));
    $current_page = min($current_page, $total_pages);
    $offset = ($current_page - 1) * $per_page;

    // Pagination display values
    $start_showing = $total_records > 0 ? $offset + 1 : 0;
    $end_showing = min($offset + $per_page, $total_records);

    // 4. Fetch data with pagination
    $query = "SELECT r.report_id, r.generated_date, r.report_path, 
                     s.scan_id, s.file_name, s.scan_result, s.accuracy_score, 
                     u.full_name, u.email
              FROM reports r 
              JOIN scans s ON r.scan_id = s.scan_id 
              JOIN users u ON r.user_id = u.user_id 
              ORDER BY r.generated_date DESC
              LIMIT $per_page OFFSET $offset";
    
    $stmt = $db->query($query);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reports Management - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        .modal-overlay { 
            display: none; position: fixed; top: 0; left: 0; 
            width: 100%; height: 100%; background: rgba(0,0,0,0.5); 
            z-index: 1000; justify-content: center; align-items: center; 
        }
        .modal { 
            background: white; padding: 30px; border-radius: 12px; 
            width: 90%; max-width: 600px; max-height: 85vh; overflow-y: auto;
        }
        .actions-cell { display: flex; justify-content: flex-start; gap: 8px; flex-wrap: wrap; }
        .action-btn { 
            display: inline-flex; align-items: center; padding: 7px 12px; 
            border-radius: 6px; text-decoration: none; font-size: 0.8rem; 
            font-weight: 500; transition: all 0.2s ease; border: none; 
            background: transparent; cursor: pointer; white-space: nowrap;
        }
        .action-btn svg { width: 16px; height: 16px; margin-right: 4px; }
        .action-btn.view-btn { color: #2563eb; background: #eff6ff; border: 1px solid #bfdbfe; }
        .action-btn.view-btn:hover { background-color: #dbeafe; }
        .action-btn.view-pdf { color: #7c3aed; background: #faf5ff; border: 1px solid #e9d5ff; }
        .action-btn.view-pdf:hover { background-color: #f3e8ff; }
        .action-btn.download { color: #059669; background: #ecfdf5; border: 1px solid #a7f3d0; }
        .action-btn.download:hover { background-color: #d1fae5; }
        .action-btn.delete { color: #dc2626; background: #fef2f2; border: 1px solid #fecaca; }
        .action-btn.delete:hover { background-color: #fee2e2; }
        .badge-danger { background: #fee2e2; color: #991b1b; padding: 5px 10px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
        .badge-success { background: #d1fae5; color: #065f46; padding: 5px 10px; border-radius: 6px; font-weight: 600; font-size: 0.75rem; }
        .badge-core { background: #1d4ed8; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.7rem; font-weight: 600; }
        .badge-extended { background: #7c3aed; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.7rem; font-weight: 600; }
        .confidence-bar { width: 100%; background: #e5e7eb; height: 6px; border-radius: 3px; margin-top: 4px; }
        .confidence-fill { height: 100%; border-radius: 3px; }
        .bg-danger { background: #ef4444; }
        .bg-success { background: #10b981; }
        .main-content { margin-left: 260px; padding: 2rem; background: #f9fafb; min-height: 100vh; }
        .dataset-table { width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .info-section { background: #eff6ff; border: 1px solid #bfdbfe; border-left: 4px solid #3b82f6; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; }
        .info-section h4 { margin: 0 0 0.5rem 0; color: #1e40af; font-size: 0.9rem; display: flex; align-items: center; gap: 6px; }
        .info-section p { margin: 0; color: #1f2937; font-size: 0.85rem; line-height: 1.6; }

        /* Pagination Styles */
        .pagination-wrapper {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding: 1rem 1.5rem;
            border-top: 1px solid #e5e7eb;
            gap: 0.4rem;
            flex-wrap: wrap;
            background: white;
            border-radius: 0 0 12px 12px;
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

    <?php if(isset($_GET['status']) && $_GET['status'] == 'deleted'): ?>
        <script>
            Swal.fire({
                icon: 'success',
                title: 'Deleted!',
                text: 'Report record successfully deleted.',
                timer: 2000,
                showConfirmButton: false
            });
        </script>
    <?php endif; ?>

    <?php $active_page = 'reports'; ?>
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:30px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/>
                </svg>
                <div>
                    <h2 style="font-size:1.2rem; margin:0;">TrojanDetect</h2>
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

    <div class="main-content">
        <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">
            📄 Scan Reports
        </h1>
        <p style="color: #6b7280; margin-bottom: 20px;">
            View, download and manage PDF reports for all completed scans.
        </p>

        <div class="info-section">
            <h4>ℹ️ Report Actions</h4>
            <p>
                <strong>View Details:</strong> Quick preview of scan info • 
                <strong>View Report:</strong> Open PDF in new tab • 
                <strong>Download PDF:</strong> Save report directly to your device
            </p>
        </div>

        <div style="background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden;">
            <table class="dataset-table" style="border-radius: 0; box-shadow: none;">
                <thead>
                    <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0;">
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Report ID</th>
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Generated</th>
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">User</th>
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">File Name</th>
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Result</th>
                        <th style="padding:15px; text-align:center; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Confidence</th>
                        <th style="padding:15px; text-align:left; font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(empty($logs)): ?>
                        <tr><td colspan="7" style="text-align:center; padding:30px; color:#9ca3af;">No report records found.</td></tr>
                    <?php else: ?>
                        <?php foreach ($logs as $log): 
                             $scan_result_val = $log['scan_result'] ?? 'Unknown';
                             $file_name_val = $log['file_name'] ?? 'Unknown';
                             $full_name_val = $log['full_name'] ?? 'N/A';
                             $email_val = $log['email'] ?? '';
                             $scan_id = $log['scan_id'] ?? 0;
                             $confidence = round((float)($log['accuracy_score'] ?? 0), 2);
                             $isTrojan = (strpos(strtolower((string)$scan_result_val), 'trojan') !== false);
                             $displayDate = date('d M Y, H:i', strtotime($log['generated_date'] ?? 'now'));
                             $file_ext = strtolower(pathinfo($file_name_val, PATHINFO_EXTENSION));
                             $pe_exts = ['exe','dll','bin','sys','bat','com','scr','pif'];
                             $isCore = in_array($file_ext, $pe_exts);
                             $scanCategory = $isCore ? 'Core' : 'Extended';
                             $scanMethod = $isCore ? 'ML-Based Analysis' : 'Heuristic Analysis';
                        ?>
                        <tr style="border-bottom:1px solid #f3f4f6;">
                            <td style="padding:15px; font-weight: 600; color: #2563eb;">#REP-<?= $log['report_id'] ?></td>
                            <td style="padding:15px; font-size:0.85rem; color:#64748b;"><?= $displayDate ?></td>
                            <td style="padding:15px;">
                                <strong style="display:block; margin-bottom:2px;"><?= htmlspecialchars((string)$full_name_val) ?></strong>
                                <span style="font-size:0.75rem; color:#9ca3af;"><?= htmlspecialchars((string)$email_val) ?></span>
                            </td>
                            <td style="padding:15px; font-family:monospace; font-size:0.85rem;"><?= htmlspecialchars((string)$file_name_val) ?></td>
                            <td style="padding:15px;">
                                <span class="<?= $isTrojan ? 'badge-danger' : 'badge-success' ?>">
                                    <?= htmlspecialchars((string)$scan_result_val) ?>
                                </span>
                            </td>
                            <td style="padding:15px; text-align:center;">
                                <strong style="font-size:1.1rem; color:<?= $isTrojan ? '#dc2626' : '#059669' ?>;">
                                    <?= $confidence ?>%
                                </strong>
                            </td>
                            <td style="padding:15px;">
                                <div class="actions-cell">
                                    <button onclick="viewScan(this)" 
                                        data-id="<?= $scan_id ?>"
                                        data-date="<?= $displayDate ?>"
                                        data-user="<?= htmlspecialchars((string)$full_name_val) ?>"
                                        data-email="<?= htmlspecialchars((string)$email_val) ?>"
                                        data-file="<?= htmlspecialchars((string)$file_name_val) ?>"
                                        data-result="<?= htmlspecialchars((string)$scan_result_val) ?>"
                                        data-score="<?= $confidence ?>"
                                        data-istrojan="<?= $isTrojan ? 'true' : 'false' ?>"
                                        data-category="<?= $scanCategory ?>"
                                        data-method="<?= $scanMethod ?>"
                                        class="action-btn view-btn" title="View Details">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                                        Details
                                    </button>
                                    <a href="generate_pdf.php?id=<?= $scan_id ?>" target="_blank" class="action-btn view-pdf" title="View PDF in new tab">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                        View
                                    </a>
                                    <a href="generate_pdf.php?id=<?= $scan_id ?>&download=1" download="TrojanDetect_Report_Scan_<?= $scan_id ?>.pdf" class="action-btn download" title="Download PDF">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                        Download
                                    </a>
                                    <button onclick="confirmDelete(<?= $log['report_id'] ?>)" class="action-btn delete" title="Delete Report">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
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
                <?php if ($current_page <= 1): ?>
                    <span class="page-btn disabled">Prev</span>
                <?php else: ?>
                    <a href="reports.php?page=<?= $current_page - 1 ?>" class="page-btn">Prev</a>
                <?php endif; ?>

                <!-- Page Number Buttons -->
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <?php if ($i === $current_page): ?>
                        <span class="page-btn active"><?= $i ?></span>
                    <?php else: ?>
                        <a href="reports.php?page=<?= $i ?>" class="page-btn"><?= $i ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <!-- Next Button -->
                <?php if ($current_page >= $total_pages): ?>
                    <span class="page-btn disabled">Next</span>
                <?php else: ?>
                    <a href="reports.php?page=<?= $current_page + 1 ?>" class="page-btn">Next</a>
                <?php endif; ?>
            </div>
            <!-- ===== END PAGINATION ===== -->

        </div>
    </div>

    <!-- View Modal -->
    <div id="viewModal" class="modal-overlay" onclick="if(event.target === this) closeViewModal()">
        <div class="modal">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:2px solid #e5e7eb; padding-bottom:12px;">
                <h2 style="margin:0; font-size:1.4rem; color:#1f2937; font-weight:700;">📊 Scan Details</h2>
                <button onclick="closeViewModal()" style="background:none; border:none; font-size:1.8rem; cursor:pointer; color:#6b7280; line-height:1;">&times;</button>
            </div>
            <div id="modalContent"></div>
            <div style="margin-top:24px; padding-top:20px; border-top:1px solid #e5e7eb; display:flex; gap:10px; justify-content:flex-end;">
                <button onclick="closeViewModal()" style="padding:10px 20px; background:#e5e7eb; color:#374151; border:none; border-radius:8px; cursor:pointer; font-weight:600;">Close</button>
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
            const isCore = data.category === 'Core';
            const badgeCategoryClass = isCore ? 'badge-core' : 'badge-extended';
            const badgeCategoryLabel = isCore ? '⚙️ Core ML Feature' : '🔬 Extended Feature';
            
            content.innerHTML = `
                <div style="background:#f9fafb; border-radius:8px; padding:16px; margin-bottom:20px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <span style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Scan Reference</span>
                        <strong style="font-size:1.1rem; color:#2563eb;">#SCAN-${data.id}</strong>
                    </div>
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Date Generated</span>
                        <span style="font-size:0.9rem; color:#1f2937;">${data.date}</span>
                    </div>
                </div>

                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">Uploader</label>
                    <div style="font-weight: 600; font-size:0.95rem;">${data.user}</div>
                    <div style="font-size:0.8rem; color:#9ca3af;">${data.email}</div>
                </div>
                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">File Name</label>
                    <div style="word-break:break-all; font-family:monospace; background:#f3f4f6; padding:8px 12px; border-radius:6px; font-size:0.85rem;">${data.file}</div>
                </div>
                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">Analysis Result</label>
                    <span class="${badgeClass}" style="font-size:0.9rem; padding:8px 14px;">${data.result}</span>
                </div>
                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:0.75rem; color:#6b7280; font-weight:600; text-transform:uppercase; margin-bottom:6px;">ML Confidence Score</label>
                    <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                        <strong style="font-size:1.3rem; color:${isTrojan ? '#dc2626' : '#059669'};">${data.score}%</strong>
                    </div>
                    <div class="confidence-bar"><div class="confidence-fill ${fillClass}" style="width:${data.score}%"></div></div>
                </div>
                <div style="margin-top:24px; padding-top:20px; border-top:1px solid #e5e7eb; display:flex; gap:10px;">
                    <a href="generate_pdf.php?id=${data.id}" target="_blank" 
                       style="flex:1; display:flex; align-items:center; justify-content:center; gap:8px; padding:12px; background:#7c3aed; border-radius:8px; color:white; text-decoration:none; font-weight:600;">
                        👁️ View Report
                    </a>
                    <a href="generate_pdf.php?id=${data.id}&download=1" 
                       download="TrojanDetect_Report_Scan_${data.id}.pdf"
                       style="flex:1; display:flex; align-items:center; justify-content:center; gap:8px; padding:12px; background:#2563eb; border-radius:8px; color:white; text-decoration:none; font-weight:600;">
                        ⬇️ Download PDF
                    </a>
                </div>
            `;
            modal.style.display = 'flex';
        }

        function closeViewModal() {
            document.getElementById('viewModal').style.display = 'none';
        }

        function confirmDelete(id) {
            Swal.fire({
                title: 'Are you sure?',
                text: "Permanently delete this report? This action cannot be undone.",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'reports.php?delete_id=' + id;
                }
            });
        }

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