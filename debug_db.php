<?php
/**
 * File: debug_db.php
 * Purpose: Diagnostic tool and quick data management.
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    $db_file = "database.sqlite";
    $db = new PDO("sqlite:" . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // --- DATA MANAGEMENT LOGIC ---
    if (isset($_GET['action'])) {
        $target = $_GET['table'] ?? '';
        
        // 1. Delete specific records
        if ($_GET['action'] === 'clear' && !empty($target)) {
            $db->exec("DELETE FROM $target");
            header("Location: debug_db.php?status=cleared&table=$target");
            exit;
        }
        
        // 2. WIPE ALL LOGS (Delete Scans, Reports, and Files - Except Users)
        if ($_GET['action'] === 'wipe_logs') {
            $db->exec("DELETE FROM reports");
            $db->exec("DELETE FROM scans");
            $db->exec("DELETE FROM files");
            $db->exec("DELETE FROM threat_logs");
            header("Location: debug_db.php?status=wiped");
            exit;
        }
    }

    $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")->fetchAll(PDO::FETCH_COLUMN);

    echo "<!DOCTYPE html>
    <html>
    <head>
        <title>Database Manager - TrojanDetect</title>
        <style>
            body { font-family: 'Inter', sans-serif; padding: 30px; background: #f4f7f9; color: #334155; }
            .container { max-width: 1000px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 15px; margin-bottom: 20px; }
            .btn { padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 0.9rem; cursor: pointer; border: none; }
            .btn-danger { background: #ef4444; color: white; }
            .btn-danger:hover { background: #dc2626; }
            .btn-outline { border: 1px solid #d1d5db; color: #4b5563; background: white; }
            .table-card { border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
            .table-header { background: #f8fafc; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 12px 20px; text-align: left; font-size: 0.85rem; border-bottom: 1px solid #f1f5f9; }
            th { color: #64748b; text-transform: uppercase; font-size: 0.7rem; }
            .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; background: #d1fae5; color: #065f46; }
            .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: 600; text-align: center; }
            .alert-success { background: #d1fae5; color: #065f46; border: 1px solid #10b981; }
        </style>
    </head>
    <body>
    <div class='container'>
        <div class='header'>
            <h1>🛠️ Database Manager</h1>
            <div style='display:flex; gap:10px;'>
                <a href='reset_db.php' class='btn btn-outline'>Factory Reset System</a>
                <a href='?action=wipe_logs' class='btn btn-danger' onclick='return confirm(\"Delete ALL scan history and reports?\")'>🔥 Wipe All Logs</a>
            </div>
        </div>";

    if (isset($_GET['status'])) {
        $msg = $_GET['status'] == 'wiped' ? "All scan logs and reports have been cleared!" : "Table data has been emptied.";
        echo "<div class='alert alert-success'>✅ $msg</div>";
    }

    foreach (['users', 'scans', 'reports', 'files'] as $table) {
        if (in_array($table, $tables)) {
            $count = $db->query("SELECT count(*) FROM $table")->fetchColumn();
            echo "<div class='table-card'>
                    <div class='table-header'>
                        <strong>Table: $table</strong>
                        <span><span class='badge'>$count Records</span> | <a href='?action=clear&table=$table' style='color:#ef4444; font-size:0.8rem;' onclick='return confirm(\"Clear data for $table?\")'>Clear Data</a></span>
                    </div>";
            
            $data = $db->query("SELECT * FROM $table LIMIT 3")->fetchAll(PDO::FETCH_ASSOC);
            if ($data) {
                echo "<table><thead><tr>";
                foreach (array_keys($data[0]) as $k) echo "<th>$k</th>";
                echo "</tr></thead><tbody>";
                foreach ($data as $row) {
                    echo "<tr>";
                    foreach ($row as $v) echo "<td>" . htmlspecialchars(substr((string)$v, 0, 30)) . (strlen((string)$v) > 30 ? '...' : '') . "</td>";
                    echo "</tr>";
                }
                echo "</tbody></table>";
            } else {
                echo "<div style='padding:20px; color:#9ca3af; font-style:italic; text-align:center;'>Table empty</div>";
            }
            echo "</div>";
        }
    }
    echo "</div></body></html>";

} catch (PDOException $e) { echo "Error: " . $e->getMessage(); }