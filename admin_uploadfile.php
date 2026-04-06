<?php
session_start(); // Start session to store user data temporarily

// 1. SECURITY: Block access if not a valid user (Role: admin)
if (!isset($_SESSION['is_logged_in']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit;
}

// Get session data with fallback (prevent null errors - PHP 8.1 compatibility)
$user_id = $_SESSION['user_id'] ?? 0; 
$full_name = (string)($_SESSION['full_name'] ?? 'User'); 
$email = (string)($_SESSION['email'] ?? 'user@gmail.com'); 
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Scanner - TrojanDetect ML</title>
    <link rel="stylesheet" href="static/style.css">

    <style>
        body { background: #f9fafb; font-family: 'Inter', sans-serif; margin: 0; }
        .main-content { margin-left: 260px; padding: 30px; min-height: 100vh; }
        .page-header h1 { font-size: 1.875rem; font-weight: 700; color: #111827; margin-bottom: 0.5rem; }
        .page-header p { color: #6b7280; font-size: 0.95rem; margin-bottom: 2rem; }

        .upload-card {
            background: white; border-radius: 12px; padding: 1.5rem;
            margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            border: 1px solid #f0f0f0;
        }
        .upload-box {
            border: 2px dashed #cbd5e1; border-radius: 12px; padding: 4rem 2rem;
            text-align: center; background: #ffffff; transition: all 0.3s ease; cursor: pointer;
        }
        .upload-box:hover, .upload-box.highlight { border-color: #2563eb; background: #f8fafc; }
        .upload-icon-wrapper { margin-bottom: 1.5rem; color: #2563eb; }
        .upload-title { font-size: 1.25rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem; }
        .upload-subtitle { color: #6b7280; font-size: 0.95rem; margin-bottom: 2rem; }
        
        /* Definitive fix for duplicate icons */
        .upload-box h3::before, .upload-box h3::after,
        .info-box h4::before, .info-box h4::after {
            display: none !important;
            content: none !important;
        }

        .button-group { display: flex; justify-content: center; gap: 12px; margin-bottom: 1.5rem; }
        .btn-choose {
            background: #2563eb; color: white; padding: 0.8rem 1.8rem;
            border-radius: 8px; font-weight: 600; display: flex; align-items: center;
            gap: 8px; cursor: pointer; border: none; font-size: 0.95rem;
        }
        .btn-scan-main {
            background: #10b981; color: white; padding: 0.8rem 1.8rem;
            border-radius: 8px; font-weight: 600; display: flex; align-items: center;
            gap: 8px; cursor: pointer; border: none; font-size: 0.95rem;
        }
        .btn-scan-main:disabled { opacity: 0.6; cursor: not-allowed; background: #cbd5e1; }
        .max-size-text { color: #9ca3af; font-size: 0.8rem; }

        .info-box {
            background: #eff6ff; border: 1px solid #bfdbfe; border-left: 4px solid #3b82f6;
            border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem;
        }
        .info-box h4 { margin-top: 0; color: #1e40af; font-size: 1rem; display: flex; align-items: center; gap: 8px; }
        .info-box h4::before { display: none !important; content: none !important; }
        .info-box ul { padding-left: 0; margin-bottom: 0; color: #1f2937; font-size: 0.85rem; line-height: 1.8; list-style: none; }
        .info-box ul li { position: relative; padding-left: 1.5rem; margin-bottom: 0.25rem; }
        .info-box ul li::before { content: "✓"; position: absolute; left: 0; color: #2563eb; font-weight: bold; }

        .result-container-card {
            background: white; border-radius: 12px; padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #f0f0f0;
        }
        .result-header-text { font-size: 1rem; font-weight: 700; color: #374151; margin-bottom: 1rem; }
        .scan-placeholder { padding: 4rem 2rem; text-align: center; }
        .placeholder-icon { color: #e5e7eb; margin-bottom: 1rem; }

        @keyframes scanning { 0% { transform: translateX(-100%); } 100% { transform: translateX(200%); } }
        .progress-bar-container { width: 100%; max-width: 400px; height: 6px; background: #e5e7eb; border-radius: 10px; margin: 20px auto; overflow: hidden; }
        .progress-bar-fill { width: 40%; height: 100%; background: #2563eb; animation: scanning 1.5s infinite linear; }

        /* ── PDF Action Buttons ── */
        .pdf-actions {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-top: 2rem;
            flex-wrap: wrap;
        }
        .btn-view-pdf {
            padding: 10px 22px;
            background: white;
            border: 1.5px solid #2563eb;
            border-radius: 8px;
            text-decoration: none;
            color: #2563eb;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn-view-pdf:hover { background: #eff6ff; }

        .btn-download-pdf {
            padding: 10px 22px;
            background: #2563eb;
            border: 1.5px solid #2563eb;
            border-radius: 8px;
            text-decoration: none;
            color: white;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn-download-pdf:hover { background: #1d4ed8; }

        .btn-scan-new {
            padding: 10px 22px;
            background: #f3f4f6;
            border: none;
            border-radius: 8px;
            color: #374151;
            font-weight: 600;
            cursor: pointer;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn-scan-new:hover { background: #e5e7eb; }
    </style>
</head>

<body class="dashboard-page">
    <!-- Sidebar -->
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
            <a href="admin_uploadfile.php" class="nav-item active">
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

            <a href="admin_manageuser.php" class="nav-item">
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
                Logout
            </a>
        </div>
    </div>

    <!-- Main Content -->
    <main class="main-content">
        <div class="page-header" style="display: block;">
            <h1 style="font-size: 1.875rem; font-weight: 700; color: #1f2937; margin: 0 0 6px 0;">File Scanner</h1>
            <p style="color: #6b7280; margin-top: 5px;">Upload Windows files for machine learning trojan detection</p>
        </div>

        <!-- UPLOAD SECTION -->
        <div class="upload-card">
            <div class="upload-box" id="uploadBox" onclick="document.getElementById('fileInput').click()">
                <div class="upload-icon-wrapper">
                    <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                </div>
                <h3 class="upload-title">Upload File for Scanning</h3>
                <p class="upload-subtitle" id="fileStatusText">Select any file type - .exe, .dll, .pdf, .zip, and more</p>

                <div class="button-group">
                    <input type="file" id="fileInput" hidden>
                    <button type="button" class="btn-choose" onclick="event.stopPropagation(); document.getElementById('fileInput').click()">
                        <span>📁</span> Choose File
                    </button>
                    <button type="button" class="btn-scan-main" id="scanBtn" disabled onclick="event.stopPropagation(); startScan()">
                        <span>🔍</span> Scan File
                    </button>
                </div>
                <p class="max-size-text">Max file size: 16MB</p>
            </div>
        </div>

                <!-- LATEST RESULT SECTION -->
        <div class="result-container-card">
            <h3 class="result-header-text">Latest Scan Result</h3>
            
            <div id="scanPlaceholder" class="scan-placeholder">
                <div class="placeholder-icon">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity="0.2">
                        <rect x="3" y="11" width="18" height="10" rx="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                </div>
                <p style="color: #9ca3af; font-size: 0.95rem;">No scan in progress</p>
            </div>

            <div id="scanLoading" style="display:none; text-align:center; padding: 3rem;">
                <h3 style="color:#2563eb; margin-bottom: 0.5rem;">ML Engine Analyzing...</h3>
                <div class="progress-bar-container"><div class="progress-bar-fill"></div></div>
            </div>

            <div id="scanResult" style="display:none; text-align:center; padding: 2rem;"></div>
        </div>
    </main>

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

        let selectedFile = null;

        document.getElementById('fileInput').addEventListener('change', function() {
            handleFileSelection(this.files[0]);
        });

        const uploadBox = document.getElementById('uploadBox');
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => {
            uploadBox.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }, false);
        });
        ['dragenter', 'dragover'].forEach(ev => uploadBox.addEventListener(ev, () => uploadBox.classList.add('highlight'), false));
        ['dragleave', 'drop'].forEach(ev => uploadBox.addEventListener(ev, () => uploadBox.classList.remove('highlight'), false));
        uploadBox.addEventListener('drop', e => handleFileSelection(e.dataTransfer.files[0]), false);

        function handleFileSelection(file) {
            if (!file) return;
            selectedFile = file;
            const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
            document.getElementById('fileStatusText').innerHTML =
                `<strong style="color:#2563eb;">Ready:</strong> ${file.name} (${sizeMb} MB)`;
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanPlaceholder').style.display = 'block';
            document.getElementById('scanResult').style.display = 'none';
        }

        async function startScan() {
            if (!selectedFile) return;

            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanPlaceholder').style.display = 'none';
            document.getElementById('scanLoading').style.display = 'block';
            document.getElementById('scanResult').style.display = 'none';

            const formData = new FormData();
            formData.append('trojan_file', selectedFile);

            try {
                const response = await fetch('api_upload.php', { method: 'POST', body: formData });
                const rawText  = await response.text();

                let data;
                try {
                    data = JSON.parse(rawText);
                } catch(e) {
                    throw new Error("Server did not return JSON. Check api_upload.php.\n\n" + rawText.substring(0, 200));
                }

                document.getElementById('scanLoading').style.display = 'none';

                if (data.success) {
                    showResult(data);
                } else {
                    Swal.fire('Scan Failed', data.message || 'Unknown error', 'error');
                    document.getElementById('scanPlaceholder').style.display = 'block';
                }
            } catch (err) {
                document.getElementById('scanLoading').style.display = 'none';
                document.getElementById('scanPlaceholder').style.display = 'block';
                Swal.fire('Error', err.message, 'error');
            } finally {
                document.getElementById('scanBtn').disabled = false;
            }
        }

        function showResult(data) {
            const resDiv     = document.getElementById('scanResult');
            const resultText = (data.result || data.prediction || '').toLowerCase();
            const isSafe     = resultText.includes('safe');
            const color      = isSafe ? '#10b981' : '#ef4444';
            const scanId     = data.scan_id || 0;

            // Scan method badge
            const isCore      = (data.scan_category || 'Core') === 'Core';
            const badgeBg     = isCore ? '#1d4ed8' : '#7c3aed';
            const badgeLabel  = isCore ? '⚙️ Core ML Feature' : '🔬 Extended Feature';
            const methodLabel = data.scan_method || 'ML-Based Analysis';

            // Threat info row (if Trojan)
            let threatRow = '';
            if (!isSafe && data.threat) {
                const sevColor = data.severity === 'High' ? '#ef4444' : data.severity === 'Medium' ? '#f97316' : '#eab308';
                threatRow = `
                    <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f9fafb;">
                        <span style="color:#6b7280;">Threat Name:</span>
                        <strong style="color:#dc2626;">${data.threat}</strong>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f9fafb;">
                        <span style="color:#6b7280;">Severity:</span>
                        <strong style="color:${sevColor};">${data.severity}</strong>
                    </div>`;
            }

            resDiv.innerHTML = `
                <div style="font-size:3.5rem; margin-bottom:1rem;">${isSafe ? '✅' : '⚠️'}</div>

                <div style="display:inline-block; padding:6px 20px; border-radius:20px;
                    background:${isSafe ? '#d1fae5' : '#fee2e2'};
                    color:${isSafe ? '#065f46' : '#991b1b'};
                    font-weight:700; margin-bottom:1rem; text-transform:uppercase;">
                    ${(data.result || data.prediction || '').toUpperCase()}
                </div>

                <h2 style="font-size:2.8rem; font-weight:800; margin:1rem 0; color:${color};">
                    ${data.confidence || 0}% Confidence
                </h2>



                <!-- Detail Table -->
                <div style="text-align:left; max-width:500px; margin:1.5rem auto;
                    border-top:1px solid #f0f0f0; padding-top:1.5rem;">
                    <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f9fafb;">
                        <span style="color:#6b7280;">Scan ID:</span>
                        <strong>#SCAN-${scanId}</strong>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f9fafb;">
                        <span style="color:#6b7280;">File Name:</span>
                        <strong>${data.filename || 'Unknown'}</strong>
                    </div>
                    ${threatRow}
                    <div style="display:flex; justify-content:space-between; padding:8px 0;">
                        <span style="color:#6b7280;">Date & Time:</span>
                        <strong>${data.date || 'Just now'}</strong>
                    </div>
                </div>

                <!-- ── ACTION BUTTONS ── -->
                <div class="pdf-actions">
                    <!-- View PDF dalam browser (tab baru) -->
                    <a href="generate_pdf.php?id=${scanId}"
                       target="_blank"
                       class="btn-view-pdf">
                        👁️ View Report
                    </a>

                    <!-- Download PDF directly to Downloads folder -->
                    <a href="generate_pdf.php?id=${scanId}&download=1"
                       download="TrojanDetect_Report_Scan_${scanId}.pdf"
                       class="btn-download-pdf">
                        ⬇️ Download PDF
                    </a>

                    <!-- Scan new file -->
                    <button onclick="location.reload()" class="btn-scan-new">
                        🔄 Scan New File
                    </button>
                </div>
            `;

            resDiv.style.display = 'block';
            document.getElementById('fileStatusText').innerHTML =
                `<strong style="color:#10b981;">Analysis Complete!</strong>`;
        }
    </script>
</body>
</html>