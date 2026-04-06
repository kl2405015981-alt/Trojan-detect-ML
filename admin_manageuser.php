<?php
session_start();

// 1. SECURITY: Block access if not Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

try {
    // 2. Connect to database (Root location)
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // 3. Process DELETE if request exists
    if (isset($_GET['delete_id'])) {
        $delete_id = $_GET['delete_id'];
        // Prevent deleting own admin account
        $stmt = $db->prepare("DELETE FROM users WHERE user_id = ? AND user_type != 'admin'");
        $stmt->execute([$delete_id]);
        header("Location: admin_manageuser.php?status=deleted");
        exit;
    }

    // 4. Overall Statistics
    $total_users = $db->query("SELECT count(*) FROM users")->fetchColumn();
    $total_students = $db->query("SELECT count(*) FROM users WHERE user_type = 'student'")->fetchColumn();
    $total_lecturers = $db->query("SELECT count(*) FROM users WHERE user_type = 'lecturer'")->fetchColumn();

    // 5. Search & Pagination Configuration
    $search = isset($_GET['search']) ? $_GET['search'] : '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $per_page = 4;
    $offset = ($page - 1) * $per_page;

    // 6. Main Query (Combine Search & Scan Count from scans)
    // Note: Ensure you have run reset_db.php to add user_id column
    $sql = "SELECT u.*, (SELECT COUNT(*) FROM scans WHERE user_id = u.user_id) as scan_count 
            FROM users u";
    
    if ($search) {
        $sql .= " WHERE full_name LIKE :search OR email LIKE :search";
    }
    
    $sql .= " ORDER BY user_id DESC LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    if ($search) {
        $search_param = "%$search%";
        $stmt->bindValue(':search', $search_param, PDO::PARAM_STR);
    }
    $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 7. Count total records for pagination
    if ($search) {
        $count_stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE full_name LIKE ? OR email LIKE ?");
        $count_stmt->execute(["%$search%", "%$search%"]);
        $total_records = $count_stmt->fetchColumn();
    } else {
        $total_records = $total_users;
    }
    $total_pages = $total_records > 0 ? ceil($total_records / $per_page) : 1;

} catch (PDOException $e) {
    // If error 'no such column: user_id' appears, you need to run reset_db.php
    die("Database Error: " . $e->getMessage() . ". <br>Please ensure you have run reset_db.php to update the database structure.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Users - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        /* Combined Styles from your code */
        .btn-primary { background: #2563eb; color: white; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; }
        .search-container { display: flex; gap: 10px; margin-bottom: 20px; align-items: center; }
        .search-input { flex: 1; padding: 10px 15px; border: 1px solid #e5e7eb; border-radius: 8px; font-size: 14px; }
        .btn-search { background: #2563eb; color: white; padding: 10px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
        .status-badge { padding: 5px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
        .status-active { background: #d1fae5; color: #065f46; }
        .action-btn { border: none; background: none; cursor: pointer; padding: 5px 10px; margin: 0 5px; display: inline-flex; align-items: center; gap: 5px; font-weight: 500; transition: opacity 0.2s; }
        .btn-delete { color: #dc2626; font-weight: bold; }
        .pagination { display: flex; justify-content: flex-end; align-items: center; gap: 10px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
        .pagination button { padding: 8px 12px; border: 1px solid #e5e7eb; background: white; border-radius: 6px; cursor: pointer; }
        .pagination button.active { background: #2563eb; color: white; border-color: #2563eb; }
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
                <h1>User Management</h1>
                <p class="subtitle">Manage user accounts and permissions</p>
            </div>
        </div>

        <?php if(isset($_GET['status'])): ?>
            <?php if($_GET['status'] == 'deleted'): ?>
                <div style="background:#fee2e2; color:#991b1b; padding:12px 16px; border-radius:8px; margin-bottom:20px; border-left: 4px solid #ef4444;">
                    🗑️ User successfully deleted!
                </div>
            <?php elseif($_GET['status'] == 'added'): ?>
                <div style="background:#d1fae5; color:#065f46; padding:12px 16px; border-radius:8px; margin-bottom:20px; border-left: 4px solid #10b981;">
                    ✅ New user successfully added!
                </div>
            <?php elseif($_GET['status'] == 'updated'): ?>
                <div style="background:#dbeafe; color:#1e40af; padding:12px 16px; border-radius:8px; margin-bottom:20px; border-left: 4px solid #3b82f6;">
                    ✅ User details successfully updated!
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <div class="stats-grid" style="display:grid; grid-template-columns: repeat(3, 1fr); gap:20px; margin-bottom:30px;">
            <div class="stat-card" style="background:white; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <div class="stat-label" style="color:#6b7280; font-size:14px;">Total Users</div>
                <div class="stat-value" style="font-size:2.5rem; font-weight:bold;"><?php echo $total_users; ?></div>
            </div>
            <div class="stat-card" style="background:white; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <div class="stat-label" style="color:#6b7280; font-size:14px;">Students</div>
                <div class="stat-value" style="color:#2563eb; font-size:2.5rem; font-weight:bold;"><?php echo $total_students; ?></div>
            </div>
            <div class="stat-card" style="background:white; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <div class="stat-label" style="color:#6b7280; font-size:14px;">Lecturers</div>
                <div class="stat-value" style="color:#16a34a; font-size:2.5rem; font-weight:bold;"><?php echo $total_lecturers; ?></div>
            </div>
        </div>

        <div class="card" style="background:white; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <form method="GET" action="admin_manageuser.php" class="search-container" style="margin-bottom: 0;">
                    <input type="text" name="search" class="search-input" placeholder="Search name or email..." value="<?php echo htmlspecialchars($search); ?>">
                    <button type="submit" class="btn-search">Search</button>
                </form>
                <a href="admin_adduser.php" class="btn-primary" style="text-decoration: none;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px; height:20px;">
                        <path d="M12 5v14M5 12h14" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    Add New User
                </a>
            </div>

            <div class="table-container">
                <table class="data-table" width="100%" style="border-collapse:collapse; text-align:left;">
                    <thead>
                        <tr style="border-bottom:2px solid #f3f4f6; height:50px;">
                            <th>NAME</th>
                            <th>EMAIL</th>
                            <th>ROLE</th>
                            <th>STATUS</th>
                            <th>SCANS</th>
                            <th style="text-align: center;">ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(empty($users)): ?>
                            <tr><td colspan="6" style="text-align: center; padding: 40px;">No users found.</td></tr>
                        <?php else: ?>
                            <?php foreach($users as $user): ?>
                            <tr style="border-bottom:1px solid #f3f4f6; height:60px;">
                                <td style="font-weight: 500;"><?php echo htmlspecialchars($user['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td>
                                    <span style="padding:5px 12px; border-radius:6px; font-size:0.75rem; font-weight: 600; background: <?php echo ($user['user_type'] == 'admin' ? '#fef3c7' : ($user['user_type'] == 'lecturer' ? '#dcfce7' : '#dbeafe')); ?>; color: <?php echo ($user['user_type'] == 'admin' ? '#92400e' : ($user['user_type'] == 'lecturer' ? '#065f46' : '#1e40af')); ?>;">
                                        <?php echo ucfirst($user['user_type']); ?>
                                    </span>
                                </td>
                                <td><span class="status-badge status-active">Active</span></td>
                                <td><?php echo $user['scan_count']; ?></td>
                                <td style="text-align: center;">
                                    <?php if($user['user_type'] !== 'admin'): ?>
                                        <div style="display: flex; justify-content: center; gap: 10px; align-items: center;">
                                            <a href="admin_edituser.php?id=<?php echo $user['user_id']; ?>" class="action-btn" style="color: #2563eb; text-decoration: none;" title="Edit">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px; display: block;">
                                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                </svg>
                                                <span style="line-height: 1;">Edit</span>
                                            </a>
                                            <button class="action-btn btn-delete" onclick="confirmDelete(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['full_name']); ?>')" title="Delete">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:18px; height:18px; display: block;">
                                                    <polyline points="3 6 5 6 21 6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                </svg>
                                                <span style="line-height: 1;">Delete</span>
                                            </button>
                                        </div>
                                    <?php else: ?>
                                        <small style="color:#9ca3af;">System Admin</small>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="pagination">
                <div class="showing-text">Showing <?php echo $total_records > 0 ? ($offset + 1) : 0; ?> to <?php echo min($offset + $per_page, $total_records); ?> of <?php echo $total_records; ?> results</div>
                <div style="display: flex; gap: 5px;">
                    <button onclick="window.location.href='?page=<?php echo max(1, $page-1); ?>&search=<?php echo urlencode($search); ?>'" <?php echo $page <= 1 ? 'disabled' : ''; ?>>Prev</button>
                    <?php for($i = 1; $i <= $total_pages; $i++): ?>
                        <button class="<?php echo $i == $page ? 'active' : ''; ?>" onclick="window.location.href='?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>'"><?php echo $i; ?></button>
                    <?php endfor; ?>
                    <button onclick="window.location.href='?page=<?php echo min($total_pages, $page+1); ?>&search=<?php echo urlencode($search); ?>'" <?php echo $page >= $total_pages ? 'disabled' : ''; ?>>Next</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script> 
        function confirmDelete(id, name) {
             Swal.fire({
                title: 'Are you sure?',
                text: 'Are you sure you want to delete user "' + name + '"?',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete user!'
            }).then((result) => {
                if (result.isConfirmed) {
                    window.location.href = 'admin_manageuser.php?delete_id=' + id;
                }
            });
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