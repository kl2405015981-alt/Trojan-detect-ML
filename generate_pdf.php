<?php
/**
 * generate_pdf.php - Full Version with Database Integration
 * Supports tables: scans, users, threat_logs, reports
 */

// 1. Suppress any output before processing begins
if (ob_get_level()) ob_end_clean();
ob_start();

require_once 'dompdf/autoload.inc.php';
use Dompdf\Dompdf;
use Dompdf\Options;

session_start();

// 2. SECURITY: Ensure user is logged in
if (!isset($_SESSION['is_logged_in'])) {
    header("HTTP/1.1 401 Unauthorized");
    die("Access denied. Please log in.");
}

if (!isset($_GET['id'])) {
    die("Error: Scan ID not specified.");
}

$scan_id = (int)$_GET['id'];
$user_id = (int)$_SESSION['user_id'];

try {
    $db = new PDO("sqlite:database.sqlite");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // ── 3. Ambil data SCANS + USERS ────────────────────────────
    $stmt = $db->prepare("
        SELECT s.*, u.full_name, u.email
        FROM scans s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.scan_id = :sid
    ");
    $stmt->execute([':sid' => $scan_id]);
    $data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$data) {
        die("Error: Scan record #$scan_id not found.");
    }

    // ── 4. Fetch THREAT_LOGS data (if Trojan detected) ─────────
    $stmt2 = $db->prepare("
        SELECT threat_name, severity_level, action_taken, detected_at
        FROM threat_logs
        WHERE scan_id = :sid
        LIMIT 1
    ");
    $stmt2->execute([':sid' => $scan_id]);
    $threat = $stmt2->fetch(PDO::FETCH_ASSOC);

    // ── 5. Fetch ML Model name used ────────────────────────────
    $stmt3 = $db->prepare("
        SELECT model_name, algorithm, accuracy
        FROM ml_models
        WHERE model_id = :mid
        LIMIT 1
    ");
    $stmt3->execute([':mid' => $data['model_id'] ?? 1]);
    $model_info = $stmt3->fetch(PDO::FETCH_ASSOC);

    // ── 5b. Fetch scan method from audit_history ─────────────
    $scan_method   = 'ML-Based Analysis';
    $scan_category = 'Core';
    $scan_desc     = 'Analysed using trained Random Forest ML model with 23 PE Header features.';

    $stmt_audit = $db->prepare("
        SELECT details FROM audit_history
        WHERE user_id = :uid AND details LIKE :pattern
        ORDER BY timestamp DESC LIMIT 1
    ");
    $stmt_audit->execute([
        ':uid'     => $user_id,
        ':pattern' => "%Scan #$scan_id%"
    ]);
    $audit_row = $stmt_audit->fetch(PDO::FETCH_ASSOC);

    // Parse from details string (format: "... | Method: X | Category: Y | ...")
    if ($audit_row) {
        if (preg_match('/Method: ([^|]+)/', $audit_row['details'], $m))
            $scan_method = trim($m[1]);
        if (preg_match('/Category: ([^|]+)/', $audit_row['details'], $m))
            $scan_category = trim($m[1]);
    }

    // Fallback: determine based on file extension
    $file_ext_pdf = strtolower(pathinfo($data['file_name'], PATHINFO_EXTENSION));
    $pe_exts      = ['exe','dll','bin','sys','bat','com','scr','pif'];
    if (!in_array($file_ext_pdf, $pe_exts)) {
        $scan_method   = 'Heuristic Analysis';
        $scan_category = 'Extended';
        $scan_desc     = match($file_ext_pdf) {
            'pdf'                         => 'Extended feature: PDF scanned for embedded JavaScript, auto-actions and suspicious streams.',
            'docx','doc','xlsx','xlsm'    => 'Extended feature: Office file scanned for VBA macros and auto-execute commands.',
            'zip','rar','7z'              => 'Extended feature: Archive scanned for encryption and double extensions.',
            default                       => 'Extended feature: File analysed using byte entropy and pattern detection.'
        };
    }

    // Badge color based on category
    $badgeBg    = ($scan_category === 'Core') ? '#1d4ed8' : '#7c3aed';
    $badgeLabel = ($scan_category === 'Core') ? '[ML] Core Feature' : '[H] Extended Feature';

    // ── 6. Color & Status Logic ────────────────────────────────
    $res_text  = (string)($data['scan_result'] ?? 'Unknown');
    $isTrojan  = (bool)preg_match('/trojan/i', $res_text);

    $themeColor    = $isTrojan ? '#ef4444' : '#22c55e';
    $bgColor       = $isTrojan ? '#fef2f2' : '#f0fdf4';
    $statusIcon    = $isTrojan ? '[!]' : '[OK]';
    $statusLabel   = $isTrojan ? 'THREAT DETECTED' : 'FILE IS SAFE';

    // Severity color
    $severityColor = '#6b7280';
    if (!empty($threat['severity_level'])) {
        $severityColor = match($threat['severity_level']) {
            'High'   => '#ef4444',
            'Medium' => '#f97316',
            'Low'    => '#eab308',
            default  => '#6b7280'
        };
    }

    // ── 7. Dompdf Configuration ────────────────────────────────
    $options = new Options();
    $options->set('isHtml5ParserEnabled', true);
    $options->set('isRemoteEnabled', true);
    $options->set('defaultFont', 'Helvetica');
    $dompdf = new Dompdf($options);

    // ── 8. Build Report HTML ────────────────────────────────────
    $threat_section = '';
    if ($isTrojan && $threat) {
        $threat_section = "
        <h3 style='color:#991b1b; margin-top:30px;'>[!] Threat Details</h3>
        <table class='meta-table' style='border:1px solid #fca5a5;'>
            <tr style='background:#fef2f2;'>
                <td class='label'>Threat Name:</td>
                <td style='color:#dc2626; font-weight:bold;'>" . htmlspecialchars($threat['threat_name']) . "</td>
            </tr>
            <tr>
                <td class='label'>Severity Level:</td>
                <td style='color:{$severityColor}; font-weight:bold;'>" . htmlspecialchars($threat['severity_level']) . "</td>
            </tr>
            <tr style='background:#fef2f2;'>
                <td class='label'>Action Taken:</td>
                <td>" . htmlspecialchars($threat['action_taken']) . "</td>
            </tr>
            <tr>
                <td class='label'>Detected At:</td>
                <td>" . date('d F Y, H:i A', strtotime($threat['detected_at'])) . "</td>
            </tr>
        </table>

        <div style='background:#fef2f2; border-left:4px solid #ef4444; padding:15px; margin-top:20px; border-radius:5px;'>
            <strong style='color:#991b1b;'>⚠ Security Recommendation:</strong><br>
            <span style='font-size:13px; color:#7f1d1d;'>
                Do NOT open or execute this file. Delete it immediately and run a full system scan.
                Contact your IT administrator if this file was received from an unknown source.
            </span>
        </div>";
    }

    $model_section = '';
    if ($model_info) {
        $model_section = "
        <h3 style='color:#1e3a8a; margin-top:30px;'>[AI] ML Model Information</h3>
        <table class='meta-table'>
            <tr>
                <td class='label'>Model Name:</td>
                <td>" . htmlspecialchars($model_info['model_name'] ?? 'TrojanDetector') . "</td>
            </tr>
            <tr style='background:#f9fafb;'>
                <td class='label'>Algorithm:</td>
                <td>" . htmlspecialchars($model_info['algorithm'] ?? 'Random Forest') . "</td>
            </tr>
            <tr>
                <td class='label'>Model Accuracy:</td>
                <td>" . number_format((float)($model_info['accuracy'] ?? 0), 2) . "%</td>
            </tr>
        </table>";
    }

    $html = "
    <html>
    <head>
        <style>
            body        { font-family: 'Helvetica', sans-serif; color: #1f2937; padding: 30px; line-height: 1.6; }
            .report-header { border-bottom: 4px solid #2563eb; padding-bottom: 10px; margin-bottom: 30px; text-align: center; }
            .result-box {
                background-color: $bgColor;
                border: 2px solid $themeColor;
                padding: 35px;
                border-radius: 15px;
                text-align: center;
                margin-bottom: 30px;
            }
            .status-text  { color: $themeColor; font-size: 38px; font-weight: 900; margin: 8px 0; }
            .meta-table   { width: 100%; border-collapse: collapse; margin-top: 10px; }
            .meta-table td { padding: 11px 15px; border-bottom: 1px solid #f3f4f6; font-size: 13px; }
            .meta-table tr:nth-child(even) { background: #f9fafb; }
            .label        { font-weight: bold; color: #6b7280; width: 180px; font-size: 11px; text-transform: uppercase; }
            .footer       { margin-top: 60px; text-align: center; font-size: 11px; color: #9ca3af; border-top: 1px solid #eee; padding-top: 20px; }
            .badge        { display:inline-block; padding:3px 10px; border-radius:20px; font-size:12px; font-weight:bold; }
        </style>
    </head>
    <body>

        <!-- HEADER -->
        <div class='report-header'>
            <h1 style='color:#2563eb; margin:0;'>TrojanDetect ML Analysis</h1>
            <p style='color:#6b7280; font-size:12px; margin:5px 0 0;'>
                Official Security Audit Report &nbsp;|&nbsp; ID: #SCAN-{$data['scan_id']}
            </p>
        </div>

        <!-- RESULT BOX -->
        <div class='result-box'>
            <p style='margin:0; font-weight:bold; color:#6b7280; text-transform:uppercase; font-size:12px;'>
                {$statusIcon} Detection Result
            </p>
            <h1 class='status-text'>{$statusLabel}</h1>
            <p style='font-size:16px; margin:5px 0 0;'>
                Model Confidence: <strong>{$data['accuracy_score']}%</strong>
            </p>
        </div>

        <!-- SCAN METHOD BADGE REMOVED -->

        <!-- FILE INFORMATION -->
        <h3 style='color:#1e3a8a;'>[+] File Information</h3>
        <table class='meta-table'>
            <tr>
                <td class='label'>File Name:</td>
                <td>" . htmlspecialchars($data['file_name']) . "</td>
            </tr>
            <tr>
                <td class='label'>File Size:</td>
                <td>" . number_format($data['file_size'] / 1024, 2) . " KB</td>
            </tr>
            <tr>
                <td class='label'>Scan Date:</td>
                <td>" . date('d F Y, H:i A', strtotime($data['scan_date'])) . "</td>
            </tr>
            <tr>
                <td class='label'>Analyzed By:</td>
                <td>" . htmlspecialchars($data['full_name']) . "</td>
            </tr>
            <tr>
                <td class='label'>User Email:</td>
                <td>" . htmlspecialchars($data['email']) . "</td>
            </tr>
            <tr>
                <td class='label'>Network Source:</td>
                <td>
                    <span style='font-family:monospace; color:#2563eb; font-weight:bold;'>" . htmlspecialchars($data['ip_address'] ?? 'N/A') . "</span> 
                    <span style='color:#6b7280; font-size:11px;'>(" . htmlspecialchars($data['pc_name'] ?? 'Unknown PC') . ")</span>
                </td>
            </tr>

        </table>

        <!-- THREAT DETAILS (only if Trojan) -->
        {$threat_section}

        <!-- ML MODEL INFO -->
        {$model_section}

        <!-- FOOTER -->
        <div class='footer'>
            Generated by TrojanDetect ML System &nbsp;|&nbsp; FYP Edition<br>
            &copy; " . date('Y') . " Universiti Poly-Tech Malaysia (UPTM). All Rights Reserved.
        </div>

    </body>
    </html>";

    // ── 9. Generate PDF ─────────────────────────────────────────
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4', 'portrait');
    $dompdf->render();
    $pdf_content = $dompdf->output();

    // ── 10. Save record in REPORTS table ──────────────────────
    // Check first — avoid duplicates if already exists
    $check = $db->prepare("SELECT report_id FROM reports WHERE scan_id = :sid AND user_id = :uid");
    $check->execute([':sid' => $scan_id, ':uid' => $user_id]);

    if (!$check->fetch()) {
        $report_path = "generate_pdf.php?id=" . $scan_id;
        $stmt4 = $db->prepare("
            INSERT INTO reports (user_id, scan_id, report_path, generated_date)
            VALUES (:uid, :sid, :path, datetime('now'))
        ");
        $stmt4->execute([
            ':uid'  => $user_id,
            ':sid'  => $scan_id,
            ':path' => $report_path
        ]);
    }

    // ── 11. Save log in AUDIT_HISTORY ───────────────────────────
    $stmt5 = $db->prepare("
        INSERT INTO audit_history (user_id, action, details, timestamp)
        VALUES (:uid, 'Report Generated', :details, datetime('now'))
    ");
    $stmt5->execute([
        ':uid'     => $user_id,
        ':details' => "PDF report generated for Scan ID #" . $scan_id . " | File: " . $data['file_name']
    ]);

    // ── 12. Send PDF to browser ─────────────────────────────────
    if (ob_get_length()) ob_end_clean();

    $filename = "TrojanDetect_Report_Scan_" . $scan_id . ".pdf";

    header('Content-Type: application/pdf');
    // If ?download=1 → force download, otherwise → view in browser
    $disposition = isset($_GET['download']) && $_GET['download'] == '1' ? 'attachment' : 'inline';
    header('Content-Disposition: ' . $disposition . '; filename="' . $filename . '"');
    header('Content-Transfer-Encoding: binary');
    header('Accept-Ranges: bytes');
    header('Content-Length: ' . strlen($pdf_content));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');

    echo $pdf_content;
    exit();

} catch (Exception $e) {
    if (ob_get_level()) ob_end_clean();
    die("Report Generation Error: " . $e->getMessage());
}
?>