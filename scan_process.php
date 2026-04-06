<?php
// scan_process.php
header('Content-Type: application/json');

// Start session
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'error' => 'User not authenticated'
    ]);
    exit;
}

$user_id = $_SESSION['user_id'];

// Set Timezone Malaysia
date_default_timezone_set('Asia/Kuala_Lumpur');
$timestamp = date('Y-m-d H:i:s');

// Database connection (adjust your DB credentials)
try {
    $db = new PDO('sqlite:database.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database connection failed'
    ]);
    exit;
}

// Check if file was uploaded
if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    echo json_encode([
        'success' => false,
        'error' => 'No file uploaded or upload error'
    ]);
    exit;
}

$file = $_FILES['file'];
$file_name = basename($file['name']);
$file_size = $file['size'];
$file_tmp = $file['tmp_name'];

// Validate file size (16MB max)
$max_size = 16 * 1024 * 1024; // 16MB in bytes
if ($file_size > $max_size) {
    echo json_encode([
        'success' => false,
        'error' => 'File size exceeds 16MB limit'
    ]);
    exit;
}

// Create uploads directory if not exists
$upload_dir = 'uploads/';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// Generate unique filename
$unique_name = time() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $file_name);
$upload_path = $upload_dir . $unique_name;

// Move uploaded file
if (!move_uploaded_file($file_tmp, $upload_path)) {
    echo json_encode([
        'success' => false,
        'error' => 'Failed to save uploaded file'
    ]);
    exit;
}

// Calculate file hash
$file_hash = hash_file('sha256', $upload_path);

// Call Python scanner
$python_command = "python scanner.py " . escapeshellarg($upload_path) . " 2>&1";
exec($python_command, $output, $return_code);

// Parse Python output
$scan_result = null;
foreach ($output as $line) {
    $decoded = json_decode($line, true);
    if ($decoded !== null) {
        $scan_result = $decoded;
        break;
    }
}

if ($scan_result === null || !isset($scan_result['success'])) {
    echo json_encode([
        'success' => false,
        'error' => 'Failed to parse scanner output',
        'debug' => implode("\n", $output)
    ]);
    exit;
}

if (!$scan_result['success']) {
    echo json_encode([
        'success' => false,
        'error' => $scan_result['error'] ?? 'Scan failed'
    ]);
    exit;
}

// Prepare scan data for database
$is_malicious = $scan_result['is_malicious'] ? 1 : 0;
$confidence = $scan_result['confidence'];
$result_text = $scan_result['result'];
$threat_name = $scan_result['threat_name'];
$threat_type = $scan_result['threat_type'];
$severity = $scan_result['severity'];
$threat_level = $scan_result['threat_level'];
$detection_method = $scan_result['detection_method'];
$whitelist_reason = $scan_result['whitelist_reason'];

try {
    // Start transaction
    $db->beginTransaction();
    
    // Insert into scans table
    $stmt = $db->prepare("
        INSERT INTO scans (
            user_id, 
            scan_status, 
            threat_detected, 
            threat_count,
            clean_count,
            total_files,
            scan_type,
            accuracy_score,
            scan_date
        ) VALUES (?, 'completed', ?, ?, ?, 1, 'quick', ?, :scan_date)
    ");
    
    $threat_count = $is_malicious ? 1 : 0;
    $clean_count = $is_malicious ? 0 : 1;
    
    $stmt->execute([
        $user_id,
        $is_malicious,
        $threat_count,
        $clean_count,
        $confidence,
        $timestamp
    ]);
    
    $scan_id = $db->lastInsertId();
    
    // Insert into files table
    $stmt = $db->prepare("
        INSERT INTO files (
            scan_id,
            file_name,
            file_path,
            file_hash,
            file_size,
            is_malicious,
            threat_type,
            threat_name,
            severity_level,
            detection_confidence,
            upload_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, :upload_date)
    ");
    
    $stmt->execute([
        $scan_id,
        $file_name,
        $upload_path,
        $file_hash,
        $file_size,
        $is_malicious,
        $threat_type,
        $threat_name,
        $severity,
        $confidence,
        $timestamp
    ]);
    
    $file_id = $db->lastInsertId();
    
    // If malicious, insert into threat_logs table
    if ($is_malicious) {
        $stmt = $db->prepare("
            INSERT INTO threat_logs (
                scan_id,
                file_id,
                threat_name,
                threat_type,
                threat_category,
                severity_level,
                detection_method,
                confidence_score,
                action_taken,
                detected_at
            ) VALUES (?, ?, ?, ?, 'trojan', ?, ?, ?, 'pending', :detected_at)
        ");
        
        $stmt->execute([
            $scan_id,
            $file_id,
            $threat_name,
            $threat_type,
            $severity,
            $detection_method,
            $confidence,
            $timestamp
        ]);
    }
    
    // Insert into audit_history
    $stmt = $db->prepare("
        INSERT INTO audit_history (
            scan_id,
            action,
            action_by,
            status_after,
            details,
            timestamp
        ) VALUES (?, 'scan_completed', ?, 'completed', ?, :timestamp)
    ");
    
    $details = json_encode([
        'file_name' => $file_name,
        'result' => $result_text,
        'confidence' => $confidence,
        'detection_method' => $detection_method,
        'whitelist_reason' => $whitelist_reason
    ]);
    
    $stmt->execute([$scan_id, $user_id, $details, $timestamp]);
    
    // Commit transaction
    $db->commit();
    
    // Return success response
    echo json_encode([
        'success' => true,
        'scan_id' => $scan_id,
        'file_id' => $file_id,
        'file_name' => $file_name,
        'is_malicious' => $is_malicious,
        'confidence' => $confidence,
        'result' => $result_text,
        'threat_name' => $threat_name,
        'threat_type' => $threat_type,
        'severity' => $severity,
        'threat_level' => $threat_level,
        'detection_method' => $detection_method,
        'whitelist_reason' => $whitelist_reason,
        'scan_time' => date('d M Y, H:i')
    ]);
    
} catch (PDOException $e) {
    $db->rollBack();
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>