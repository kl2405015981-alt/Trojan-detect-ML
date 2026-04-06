<?php
session_start();

// 1. SECURITY: Block if not Admin
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

// ═══════════════════════════════════════════════════════════════
// 2. CONNECT DATABASE
// ═══════════════════════════════════════════════════════════════
try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}

// ═══════════════════════════════════════════════════════════════
// 3. HANDLE ACTIONS (Rebuild/Retrain)
//    PRG pattern + UTF-8 encoding + save output to session
// ═══════════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    putenv('PYTHONIOENCODING=utf-8');

    if ($action === 'rebuild_dataset') {
        $result = shell_exec('python generate_dataset.py 2>&1');
        $_SESSION['ml_output']   = "<b style='color:#34d399;'>SYSTEM ></b> " . nl2br(htmlspecialchars((string)$result));
        $_SESSION['ml_msg']      = "Dataset rebuild completed. Check malware_dataset.csv for results.";
        $_SESSION['ml_msg_type'] = 'success';
        header("Location: admin_manage_ml.php?status=processed");
        exit;

    } elseif ($action === 'retrain_model') {
        $result = shell_exec('python train_model.py 2>&1');
        $_SESSION['ml_output']   = "<b style='color:#34d399;'>TRAINER ></b> " . nl2br(htmlspecialchars((string)$result));
        $_SESSION['ml_msg']      = "Model retraining completed. Check classifier.pkl for the latest model.";
        $_SESSION['ml_msg_type'] = 'success';
        header("Location: admin_manage_ml.php?status=processed");
        exit;
    }
}

// Retrieve output & message from session (after redirect)
$console_output = $_SESSION['ml_output'] ?? '';
$action_message = $_SESSION['ml_msg']    ?? '';
$action_type    = $_SESSION['ml_msg_type'] ?? '';
unset($_SESSION['ml_output'], $_SESSION['ml_msg'], $_SESSION['ml_msg_type']);

// ═══════════════════════════════════════════════════════════════
// 4. FETCH ML MODEL INFO (Dynamic — ORDER BY model_id DESC from Code 2)
// ═══════════════════════════════════════════════════════════════
$stmt = $db->query("SELECT * FROM ml_models WHERE is_active = 1 ORDER BY model_id DESC LIMIT 1");
$model = $stmt->fetch(PDO::FETCH_ASSOC);

$model_accuracy  = $model ? round($model['accuracy'], 1) : 0;
$model_name      = $model ? $model['model_name'] : 'No Active Model';
$model_algorithm = $model ? $model['algorithm']  : 'Random Forest';

// ═══════════════════════════════════════════════════════════════
// 5. PARSE test_results.txt (Confusion Matrix & Metrics)
// ═══════════════════════════════════════════════════════════════
$precision = 0; $recall = 0; $f1_score = 0;
$tn = 0; $fp = 0; $fn = 0; $tp = 0;
$last_test_date  = 'Not tested yet';
$has_test_results = false;

if (file_exists('test_results.txt')) {
    $results = file_get_contents('test_results.txt');
    $has_test_results = true;

    if (preg_match('/Precision:\s+([\d.]+)%/', $results, $m))  $precision = round((float)$m[1], 1);
    if (preg_match('/Recall:\s+([\d.]+)%/', $results, $m))     $recall    = round((float)$m[1], 1);
    if (preg_match('/F1-Score:\s+([\d.]+)%/', $results, $m))   $f1_score  = round((float)$m[1], 1);

    if (preg_match('/True Negatives \(TN\):\s+(\d+)/', $results, $m))  $tn = (int)$m[1];
    if (preg_match('/False Positives \(FP\):\s+(\d+)/', $results, $m)) $fp = (int)$m[1];
    if (preg_match('/False Negatives \(FN\):\s+(\d+)/', $results, $m)) $fn = (int)$m[1];
    if (preg_match('/True Positives \(TP\):\s+(\d+)/', $results, $m))  $tp = (int)$m[1];

    if (preg_match('/Timestamp:\s+(.+)/', $results, $m)) $last_test_date = trim($m[1]);
} else {
    if ($model) {
        $precision = $recall = $f1_score = $model_accuracy;
    }
}

// ═══════════════════════════════════════════════════════════════
// 6. COUNT CSV ROWS — fgets() method (fast for large files)
// ═══════════════════════════════════════════════════════════════
$dataset_rows = 0;
$dataset_file = 'malware_dataset.csv';
if (file_exists($dataset_file)) {
    $fh = fopen($dataset_file, 'r');
    while (!feof($fh)) {
        if (fgets($fh) !== false) $dataset_rows++;
    }
    fclose($fh);
    if ($dataset_rows > 0) $dataset_rows--; // subtract header row
}

// ═══════════════════════════════════════════════════════════════
// 7. TRAINING SAMPLES COUNT (dari scans table)
// ═══════════════════════════════════════════════════════════════
$training_count = $db->query("SELECT COUNT(*) FROM scans")->fetchColumn() ?? 0;

// ═══════════════════════════════════════════════════════════════
// 8. LAST TRAINING DATE (Dinamik dari DB)
// ═══════════════════════════════════════════════════════════════
$last_training_date = ($model && !empty($model['created_at']))
    ? date('M d, Y', strtotime($model['created_at']))
    : 'Never trained';

// ═══════════════════════════════════════════════════════════════
// 8.5 FETCH CHART DATA (Moved from Dashboard)
// ═══════════════════════════════════════════════════════════════
$chart_safe = $db->query("SELECT count(*) FROM scans WHERE scan_result = 'Safe'")->fetchColumn() ?: 0;
$chart_trojan = $db->query("SELECT count(*) FROM scans WHERE scan_result LIKE '%Trojan%'")->fetchColumn() ?: 0;

$last_7_days = ['labels' => [], 'data' => []];
$today = new DateTime('now', new DateTimeZone('Asia/Kuala_Lumpur'));
for ($i = 6; $i >= 0; $i--) {
    $date = clone $today;
    $date->modify("-{$i} days");
    $date_str = $date->format('Y-m-d');
    $display_date = $date->format('M d');
    $count = $db->query("SELECT count(*) FROM scans WHERE date(scan_date) = '$date_str'")->fetchColumn() ?: 0;
    $last_7_days['labels'][] = $display_date;
    $last_7_days['data'][] = (int)$count;
}

// ═══════════════════════════════════════════════════════════════
// 9. DATASET INVENTORY — list all CSV files
// ═══════════════════════════════════════════════════════════════
$dataset_files = [];
foreach (glob('*.csv') ?: [] as $csv_file) {
    if (!is_file($csv_file)) continue;

    $line_count = 0;
    if (($fh = fopen($csv_file, 'r')) !== false) {
        while (fgets($fh) !== false) $line_count++;
        fclose($fh);
    }

    $dataset_files[] = [
        'name'     => $csv_file,
        'records'  => max(0, $line_count - 1),
        'status'   => (strpos($csv_file, 'malware_dataset') !== false) ? 'ACTIVE' : 'ARCHIVED',
        'size'     => filesize($csv_file),
        'modified' => filemtime($csv_file),
    ];
}
usort($dataset_files, fn($a, $b) => $b['modified'] - $a['modified']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ML & Dataset Management - TrojanDetect</title>
    <link rel="stylesheet" href="static/style.css">
    <style>
        body { background: #f9fafb; font-family: 'Inter', sans-serif; margin: 0; }
        .main-content { margin-left: 260px; padding: 30px; min-height: 100vh; }

        /* ── Buttons ── */
        .btn-primary {
            background: #2563eb; color: white; padding: 10px 20px;
            border-radius: 8px; border: none; font-weight: 600;
            cursor: pointer; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; transition: all 0.2s;
        }
        .btn-primary:hover { background: #1d4ed8; }
        .btn-secondary {
            background: #10b981; color: white; padding: 10px 20px;
            border-radius: 8px; border: none; font-weight: 600;
            cursor: pointer; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; transition: all 0.2s;
        }
        .btn-secondary:hover { background: #059669; }

        /* ── Console Box ── */
        .console-box {
            background: #1e293b; color: #34d399; padding: 1.5rem;
            border-radius: 12px; margin-bottom: 2rem;
            font-family: 'Courier New', monospace; font-size: 0.85rem;
            border-left: 5px solid #2563eb; max-height: 250px; overflow-y: auto;
        }

        /* ── Metric cards ── */
        .metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2rem; }
        .metric-card {
            background: white; padding: 1.5rem; border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #f0f0f0;
        }
        .metric-label { font-size: 0.75rem; color: #6b7280; font-weight: 600; text-transform: uppercase; margin-bottom: 0.5rem; }
        .metric-value { font-size: 2.5rem; font-weight: 800; color: #1f2937; margin: 0.5rem 0; }
        .metric-subtitle { font-size: 0.85rem; color: #10b981; font-weight: 500; }

        /* ── Content grid ── */
        .content-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
        .section-card {
            background: white; padding: 1.5rem; border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid #f0f0f0;
        }
        .section-title { font-size: 1.125rem; font-weight: 700; color: #1f2937; margin: 0 0 1rem 0; }

        .progress-bar { width: 100%; background: #e5e7eb; height: 8px; border-radius: 10px; margin: 0.5rem 0; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 10px; transition: width 0.3s; }
        .progress-green { background: #10b981; }
        .progress-blue  { background: #2563eb; }

        .metric-row { display: flex; justify-content: space-between; margin-bottom: 1rem; }
        .metric-row-label { font-size: 0.9rem; color: #6b7280; }
        .metric-row-value { font-size: 0.9rem; font-weight: 700; color: #1f2937; }

        .info-box { background: #f3f4f6; border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.85rem; color: #4b5563; }

        /* ── Dataset table ── */
        .dataset-table { width: 100%; border-collapse: collapse; }
        .dataset-table th {
            background: #f8fafc; padding: 12px; text-align: left;
            font-size: 0.75rem; color: #64748b; font-weight: 600;
            text-transform: uppercase; border-bottom: 2px solid #e2e8f0;
        }
        .dataset-table td { padding: 12px; border-bottom: 1px solid #f3f4f6; font-size: 0.9rem; }

        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-active   { background: #d1fae5; color: #065f46; }
        .badge-archived { background: #e5e7eb; color: #6b7280; }

        /* ── Alert ── */
        .alert { padding: 1rem 1.25rem; border-radius: 8px; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }
        .alert-success { background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }

        /* ── Confusion Matrix ── */
        .confusion-matrix {
            display: grid; grid-template-columns: auto 1fr 1fr;
            gap: 1px; background: #e5e7eb; border-radius: 8px;
            overflow: hidden; margin-top: 1rem;
        }
        .cm-cell   { background: white; padding: 12px; text-align: center; font-weight: 600; font-size: 0.9rem; }
        .cm-header { background: #f8fafc; color: #64748b; font-size: 0.75rem; text-transform: uppercase; }
        .cm-label  { background: #f8fafc; color: #64748b; }
        .cm-value  { font-size: 1.5rem; color: #1f2937; }
        .cm-tn { background: #d1fae5; color: #065f46; }
        .cm-fp { background: #fee2e2; color: #991b1b; }
        .cm-fn { background: #fef3c7; color: #92400e; }
        .cm-tp { background: #d1fae5; color: #065f46; }

        /* ── Workflow ── */
        .workflow-card { background: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }
        .workflow-steps { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
        .workflow-step { border: 2px solid #e5e7eb; border-radius: 8px; padding: 1.25rem; transition: all 0.2s; }
        .workflow-step:hover { border-color: #2563eb; }
        .step-number { background: #2563eb; color: white; width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; margin-bottom: 0.75rem; }
        .step-title  { font-size: 1rem; font-weight: 700; color: #1f2937; margin-bottom: 0.5rem; }
        .step-desc   { font-size: 0.85rem; color: #6b7280; line-height: 1.5; }
    </style>
</head>

<body class="dashboard-page">
    <!-- ═══ SIDEBAR ═══ -->
    <div class="sidebar">
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
            <a href="admin_dashboard.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <rect x="3" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="3" width="7" height="7" stroke-width="2"/>
                    <rect x="14" y="14" width="7" height="7" stroke-width="2"/>
                    <rect x="3" y="14" width="7" height="7" stroke-width="2"/>
                </svg>
                Dashboard
            </a>
            <a href="admin_uploadfile.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke-width="2"/>
                </svg>
                File Scanner
            </a>
            <a href="admin_history.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <circle cx="12" cy="12" r="10" stroke-width="2"/>
                    <polyline points="12 6 12 12 16 14" stroke-width="2"/>
                </svg>
                Scan History
            </a>

            <div class="nav-section" style="margin-top:20px;padding:10px;font-size:0.7rem;opacity:0.5;">ADMIN FUNCTIONS</div>

            <a href="admin_manageuser.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" stroke-width="2"/>
                    <circle cx="9" cy="7" r="4" stroke-width="2"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87" stroke-width="2"/>
                </svg>
                Manage Users
            </a>
            <a href="admin_manage_ml.php" class="nav-item active">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <rect x="2" y="3" width="20" height="14" rx="2" stroke-width="2"/>
                    <line x1="8" y1="21" x2="16" y2="21" stroke-width="2"/>
                    <line x1="12" y1="17" x2="12" y2="21" stroke-width="2"/>
                </svg>
                ML & Dataset
            </a>
            <a href="reports.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-width="2"/>
                    <polyline points="14 2 14 8 20 8" stroke-width="2"/>
                </svg>
                Generate Report
            </a>
            <a href="admin_manual.php" class="nav-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:20px;height:20px;">
                    <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Admin Manual
            </a>
        </nav>

        <div class="sidebar-footer" style="padding:20px;border-top:1px solid rgba(255,255,255,0.1);">
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
                Logout
            </a>
        </div>
    </div>

    <!-- ═══ MAIN CONTENT ═══ -->
    <main class="main-content">

        <!-- Header -->
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:2rem;">
            <div>
                <h1 style="font-size:1.875rem;font-weight:700;color:#1f2937;margin:0 0 6px 0;">ML & Dataset Management</h1>
                <p style="color:#6b7280;margin:0;">Configure models and manage training data resources.</p>
            </div>
            <div style="display:flex;gap:12px;">
                <form method="POST" onsubmit="return confirm('Rebuild dataset from scans table?');">
                    <input type="hidden" name="action" value="rebuild_dataset">
                    <button type="submit" class="btn-primary">🔄 Rebuild Dataset</button>
                </form>
                <form method="POST" onsubmit="return confirm('Retrain ML model? This may take several minutes.');">
                    <input type="hidden" name="action" value="retrain_model">
                    <button type="submit" class="btn-secondary">⚡ Retrain Model</button>
                </form>
            </div>
        </div>

        <!-- Console output box — only display if there is output -->
        <?php if ($console_output): ?>
            <div class="console-box"><?= $console_output ?></div>
        <?php endif; ?>

        <!-- Action message alert -->
        <?php if ($action_message): ?>
            <div class="alert alert-<?= $action_type ?>">
                <strong>✓</strong> <?= htmlspecialchars($action_message) ?>
            </div>
        <?php endif; ?>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Model Accuracy</div>
                <div class="metric-value"><?= $model_accuracy ?>%</div>
                <div class="metric-subtitle"><?= htmlspecialchars($model_name) ?></div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Training Samples</div>
                <div class="metric-value"><?= number_format($dataset_rows) ?></div>
                <div class="metric-subtitle">Records detected in CSV</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Last Training</div>
                <div class="metric-value" style="font-size:1.5rem;"><?= $last_training_date ?></div>
                <div class="metric-subtitle">TrojanDetector v2.5 — System Status: Active</div>
            </div>
        </div>

        <!-- System Activity Analytics Charts -->
        <h3 class="section-title">System Activity Analytics</h3>
        <div class="charts-grid" style="display:grid; grid-template-columns: 1fr 2fr; gap:24px; margin-bottom:2rem;">
            <div class="chart-card" style="background:white; padding:24px; border-radius:12px; border:1px solid #f0f0f0; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin-top:0; color:#1f2937; margin-bottom:15px; font-size:1rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Overall Distribution</h3>
                <div style="position:relative; height:220px;">
                    <canvas id="barChart"></canvas>
                </div>
            </div>
            <div class="chart-card" style="background:white; padding:24px; border-radius:12px; border:1px solid #f0f0f0; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin-top:0; color:#1f2937; margin-bottom:15px; font-size:1rem; color:#6b7280; font-weight:600; text-transform:uppercase;">Scan Trends (Last 7 Days)</h3>
                <div style="position:relative; height:220px;">
                    <canvas id="lineChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Content Grid -->
        <div class="content-grid">
            <!-- Performance Metrics -->
            <div class="section-card">
                <h3 class="section-title">Performance Metrics</h3>

                <div class="metric-row">
                    <span class="metric-row-label">Precision</span>
                    <span class="metric-row-value"><?= $precision ?>%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill progress-blue" style="width:<?= $precision ?>%"></div>
                </div>

                <div class="metric-row">
                    <span class="metric-row-label">Recall</span>
                    <span class="metric-row-value"><?= $recall ?>%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill progress-blue" style="width:<?= $recall ?>%"></div>
                </div>

                <div class="metric-row">
                    <span class="metric-row-label">F1-Score</span>
                    <span class="metric-row-value"><?= $f1_score ?>%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill progress-green" style="width:<?= $f1_score ?>%"></div>
                </div>

                <div class="info-box">
                    <strong>Algorithm:</strong> <?= htmlspecialchars($model_algorithm) ?><br>
                    <strong>Input Features:</strong> 23 PE Header Features
                </div>
            </div>

            <!-- Dataset Inventory -->
            <div class="section-card">
                <h3 class="section-title">Dataset Inventory</h3>
                <table class="dataset-table">
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Records</th>
                            <th>Status</th>
                            <th>Modified</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($dataset_files)): ?>
                            <tr>
                                <td colspan="4" style="text-align:center;color:#9ca3af;padding:2rem;">
                                    No dataset files found. Click "Rebuild Dataset" to regenerate.
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($dataset_files as $file): ?>
                                <tr>
                                    <td style="font-family:monospace;font-size:0.85rem;">
                                        <?= htmlspecialchars($file['name']) ?>
                                    </td>
                                    <td><?= number_format($file['records']) ?></td>
                                    <td>
                                        <span class="badge badge-<?= strtolower($file['status']) ?>">
                                            <?= $file['status'] ?>
                                        </span>
                                    </td>
                                    <td style="color:#6b7280;font-size:0.85rem;">
                                        <?= date('M d, H:i', $file['modified']) ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
                <div class="info-box" style="margin-top:1rem;">
                    The dataset contains a mix of safe (Legitimate) and malicious (Trojan) files for balanced model training.
                </div>
            </div>
        </div>

        <!-- Confusion Matrix (only display if data exists) -->
        <?php if ($has_test_results && ($tn + $fp + $fn + $tp) > 0): ?>
        <div class="section-card" style="margin-bottom:1.5rem;">
            <h3 class="section-title">Confusion Matrix</h3>
            <p style="color:#6b7280;font-size:0.9rem;margin-bottom:1rem;">
                Last tested: <?= htmlspecialchars($last_test_date) ?>
            </p>
            <div class="confusion-matrix">
                <div class="cm-cell cm-header"></div>
                <div class="cm-cell cm-header">Predicted Safe</div>
                <div class="cm-cell cm-header">Predicted Trojan</div>
                <div class="cm-cell cm-label">Actual Safe</div>
                <div class="cm-cell cm-value cm-tn"><?= $tn ?></div>
                <div class="cm-cell cm-value cm-fp"><?= $fp ?></div>
                <div class="cm-cell cm-label">Actual Trojan</div>
                <div class="cm-cell cm-value cm-fn"><?= $fn ?></div>
                <div class="cm-cell cm-value cm-tp"><?= $tp ?></div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-top:1rem;font-size:0.85rem;">
                <div><strong>True Negatives (TN):</strong> <?= $tn ?> — Safe files correctly identified</div>
                <div><strong>False Positives (FP):</strong> <?= $fp ?> — Safe files incorrectly flagged</div>
                <div><strong>False Negatives (FN):</strong> <?= $fn ?> — Trojan missed</div>
                <div><strong>True Positives (TP):</strong> <?= $tp ?> — Trojan correctly detected</div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Training Workflow -->
        <div class="workflow-card">
            <h3 class="section-title">Training Workflow</h3>
            <div class="workflow-steps">
                <div class="workflow-step">
                    <div class="step-number">1</div>
                    <div class="step-title">Rebuild Dataset</div>
                    <div class="step-desc">
                        Run generate_dataset.py to extract PE Headers and build the training CSV file.
                    </div>
                </div>
                <div class="workflow-step">
                    <div class="step-number">2</div>
                    <div class="step-title">Retrain Model</div>
                    <div class="step-desc">
                        Run train_model.py to retrain the latest Random Forest model.
                    </div>
                </div>
            </div>
        </div>

    </main>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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

        // Initialize Charts
        document.addEventListener('DOMContentLoaded', function() {
            // Horizontal Bar Chart
            const ctxBar = document.getElementById('barChart').getContext('2d');
            new Chart(ctxBar, {
                type: 'bar',
                data: {
                    labels: ['Safe Files', 'Threats'],
                    datasets: [{
                        label: 'Total Count',
                        data: [<?= $chart_safe ?>, <?= $chart_trojan ?>],
                        backgroundColor: ['rgba(16, 185, 129, 0.8)', 'rgba(239, 68, 68, 0.8)'],
                        borderColor: ['#10b981', '#ef4444'],
                        borderWidth: 1,
                        borderRadius: 4
                    }]
                },
                options: { 
                    indexAxis: 'y', // Makes it horizontal
                    responsive: true, 
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
                }
            });

            // Area Line Chart
            const ctxLine = document.getElementById('lineChart').getContext('2d');
            new Chart(ctxLine, {
                type: 'line',
                data: {
                    labels: <?= json_encode($last_7_days['labels']) ?>,
                    datasets: [{
                        label: 'Total Scans',
                        data: <?= json_encode($last_7_days['data']) ?>,
                        backgroundColor: 'rgba(37, 99, 235, 0.2)', // Light Blue (fill)
                        borderColor: '#2563eb', // Blue (line)
                        borderWidth: 2,
                        fill: true, // Creates the 'area' effect
                        tension: 0.4, // Smooths the line
                        pointBackgroundColor: '#2563eb',
                        pointBorderColor: '#fff',
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: { 
                    responsive: true, 
                    maintainAspectRatio: false, 
                    plugins: { legend: { display:false } },
                    scales: { 
                        y: { 
                            beginAtZero: true, 
                            ticks: { precision: 0 },
                            grid: { color: 'rgba(0,0,0,0.05)' } 
                        },
                        x: { grid: { display: false } }
                    } 
                }
            });
        });
    </script>
</body>
</html>