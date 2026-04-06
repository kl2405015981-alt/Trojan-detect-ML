<?php
session_start();

// 1. SECURITY: Block if not logged in
if (!isset($_SESSION['is_logged_in'])) {
    header("Location: login.php");
    exit;
}

// Block admin from accessing user interface
if ($_SESSION['user_type'] === 'admin') {
    header("Location: admin_dashboard.php");
    exit;
}

$user_id   = $_SESSION['user_id'] ?? 0; 
$full_name = (string)($_SESSION['full_name'] ?? 'User'); 
$email     = (string)($_SESSION['email'] ?? 'user@email.com'); 
$user_type = (string)($_SESSION['user_type'] ?? 'student');
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

        .pdf-actions { display: flex; gap: 10px; justify-content: center; margin-top: 2rem; flex-wrap: wrap; }
        .btn-view-pdf {
            padding: 10px 22px; background: white; border: 1.5px solid #2563eb;
            border-radius: 8px; text-decoration: none; color: #2563eb;
            font-weight: 600; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; transition: all 0.2s;
        }
        .btn-view-pdf:hover { background: #eff6ff; }
        .btn-download-pdf {
            padding: 10px 22px; background: #2563eb; border: 1.5px solid #2563eb;
            border-radius: 8px; text-decoration: none; color: white;
            font-weight: 600; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; transition: all 0.2s;
        }
        .btn-download-pdf:hover { background: #1d4ed8; }
        .btn-scan-new {
            padding: 10px 22px; background: #f3f4f6; border: none;
            border-radius: 8px; color: #374151; font-weight: 600;
            cursor: pointer; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; transition: all 0.2s;
        }
        .btn-scan-new:hover { background: #e5e7eb; }
    </style>
</head>

<body class="dashboard-page">

    <?php $active_page = 'scanner'; ?>
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
                    <?= htmlspecialchars(substr($full_name, 0, 1)) ?>
                </div>
                <div class="user-info" style="flex:1; min-width:0;">
                    <div class="user-name" style="color:white; font-size:0.875rem; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        <?= htmlspecialchars($full_name) ?>
                    </div>
                    <div class="user-email" style="color:#9ca3af; font-size:0.75rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        <?= htmlspecialchars($email) ?>
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
    <main class="main-content">
        <div class="page-header" style="display: block;">
            <h1>File Scanner</h1>
            <p>Upload files for machine learning-based trojan detection</p>
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
                    throw new Error("Server tidak return JSON. Semak api_upload.php.\n\n" + rawText.substring(0, 200));
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

            const isCore      = (data.scan_category || 'Core') === 'Core';
            const badgeBg     = isCore ? '#1d4ed8' : '#7c3aed';
            const badgeLabel  = isCore ? '⚙️ Core ML Feature' : '🔬 Extended Feature';
            const methodLabel = data.scan_method || 'ML-Based Analysis';

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
                <div class="pdf-actions">
                    <a href="generate_pdf.php?id=${scanId}" target="_blank" class="btn-view-pdf">
                        👁️ View Report
                    </a>
                    <a href="generate_pdf.php?id=${scanId}&download=1"
                       download="TrojanDetect_Report_Scan_${scanId}.pdf"
                       class="btn-download-pdf">
                        ⬇️ Download PDF
                    </a>
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