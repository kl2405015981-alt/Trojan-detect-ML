// scan.js - Complete scan functionality

let selectedFile = null;
let currentScanId = null;

// File input change handler
document.getElementById('fileInput').addEventListener('change', function(e) {
    const file = this.files[0];
    
    if (!file) return;
    
    // Validate file size (16MB max)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
        alert('File size exceeds 16MB limit!');
        this.value = '';
        return;
    }
    
    selectedFile = file;
    
    // Update UI
    document.getElementById('statusText').textContent = 'Analysis Complete!';
    document.getElementById('statusText').style.color = '#10b981';
    document.getElementById('scanBtn').disabled = false;
    
    // Show file info
    const fileInfo = `Selected: ${file.name} (${formatFileSize(file.size)})`;
    console.log(fileInfo);
});

// Scan button handler
document.getElementById('scanBtn').addEventListener('click', function() {
    if (!selectedFile) {
        alert('Please select a file first!');
        return;
    }
    
    scanFile(selectedFile);
});

// Main scan function
function scanFile(file) {
    // Show loading
    showLoading();
    
    // Prepare form data
    const formData = new FormData();
    formData.append('file', file);
    
    // AJAX request
    fetch('scan_process.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.success) {
            currentScanId = data.scan_id;
            displayResults(data);
        } else {
            alert('Scan failed: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Error:', error);
        alert('Scan failed. Please try again.');
    });
}

// Display scan results
function displayResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    
    // Update scan ID
    document.getElementById('scanId').textContent = '#SCAN-' + data.scan_id;
    document.getElementById('fileName').textContent = data.file_name;
    document.getElementById('scanTime').textContent = data.scan_time;
    
    // Check if whitelisted
    if (data.whitelist_reason) {
        // WHITELISTED - Show green badge
        document.getElementById('warningIcon').style.display = 'none';
        document.getElementById('badge').className = 'badge-success';
        document.getElementById('badge').innerHTML = '✅ SAFE (WHITELISTED)';
        
        document.getElementById('confidenceScore').textContent = '100% Confidence';
        document.getElementById('confidenceScore').style.color = '#10b981';
        
        document.getElementById('threatName').textContent = 'None';
        document.getElementById('severity').textContent = 'Safe';
        document.getElementById('severity').className = 'severity-safe';
        
        // Show whitelist reason
        const whitelistInfo = document.createElement('div');
        whitelistInfo.className = 'whitelist-info';
        whitelistInfo.innerHTML = `
            <div style="background: #d1fae5; padding: 12px; border-radius: 8px; margin-top: 12px; border-left: 4px solid #10b981;">
                <strong>🛡️ Whitelist Protection Active</strong><br>
                <span style="color: #065f46;">${data.whitelist_reason}</span>
            </div>
        `;
        
        // Remove old whitelist info if exists
        const oldInfo = document.querySelector('.whitelist-info');
        if (oldInfo) oldInfo.remove();
        
        document.querySelector('.details-grid').appendChild(whitelistInfo);
        
    } else if (data.threat_level === 'suspicious') {
        // SUSPICIOUS - Show orange badge
        document.getElementById('warningIcon').style.display = 'block';
        document.getElementById('warningIcon').style.color = '#f59e0b';
        document.getElementById('badge').className = 'badge-warning';
        document.getElementById('badge').innerHTML = '⚠️ SUSPICIOUS';
        
        document.getElementById('confidenceScore').textContent = data.confidence + '% Confidence';
        document.getElementById('confidenceScore').style.color = '#f59e0b';
        
        document.getElementById('threatName').textContent = data.threat_name || 'Potentially Suspicious';
        document.getElementById('severity').textContent = 'Medium';
        document.getElementById('severity').className = 'severity-medium';
        
        // Show recommendation
        const recommendation = document.createElement('div');
        recommendation.className = 'recommendation';
        recommendation.innerHTML = `
            <div style="background: #fef3c7; padding: 12px; border-radius: 8px; margin-top: 12px; border-left: 4px solid #f59e0b;">
                <strong>📋 Manual Review Recommended</strong><br>
                <span style="color: #92400e;">
                    This file exhibits suspicious characteristics but may be legitimate. 
                    Please verify the source and consider scanning with additional tools if uncertain.
                </span>
            </div>
        `;
        
        // Remove old recommendation if exists
        const oldRec = document.querySelector('.recommendation');
        if (oldRec) oldRec.remove();
        
        document.querySelector('.details-grid').appendChild(recommendation);
        
    } else if (data.is_malicious) {
        // MALICIOUS - Show red badge
        document.getElementById('warningIcon').style.display = 'block';
        document.getElementById('warningIcon').style.color = '#ef4444';
        document.getElementById('badge').className = 'badge-danger';
        document.getElementById('badge').innerHTML = '🚨 TROJAN DETECTED';
        
        document.getElementById('confidenceScore').textContent = data.confidence + '% Confidence';
        document.getElementById('confidenceScore').style.color = '#ef4444';
        
        document.getElementById('threatName').textContent = data.threat_name || 'Unknown Trojan';
        document.getElementById('severity').textContent = data.severity.toUpperCase();
        document.getElementById('severity').className = 'severity-' + data.severity;
        
        // Remove whitelist/recommendation info if exists
        const oldInfo = document.querySelector('.whitelist-info');
        const oldRec = document.querySelector('.recommendation');
        if (oldInfo) oldInfo.remove();
        if (oldRec) oldRec.remove();
        
    } else {
        // SAFE - Show green badge
        document.getElementById('warningIcon').style.display = 'none';
        document.getElementById('badge').className = 'badge-success';
        document.getElementById('badge').innerHTML = '✅ SAFE';
        
        document.getElementById('confidenceScore').textContent = (100 - data.confidence) + '% Confidence';
        document.getElementById('confidenceScore').style.color = '#10b981';
        
        document.getElementById('threatName').textContent = 'None';
        document.getElementById('severity').textContent = 'Safe';
        document.getElementById('severity').className = 'severity-safe';
        
        // Remove whitelist/recommendation info if exists
        const oldInfo = document.querySelector('.whitelist-info');
        const oldRec = document.querySelector('.recommendation');
        if (oldInfo) oldInfo.remove();
        if (oldRec) oldRec.remove();
    }
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Loading indicator
function showLoading() {
    const loadingHTML = `
        <div id="loadingOverlay" style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        ">
            <div style="
                background: white;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
            ">
                <div class="spinner"></div>
                <h3 style="margin-top: 20px;">Scanning File...</h3>
                <p>Analyzing PE headers with ML model</p>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', loadingHTML);
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.remove();
    }
}

// Action button functions
function viewReport() {
    if (currentScanId) {
        window.location.href = 'view_report.php?scan_id=' + currentScanId;
    }
}

function downloadPDF() {
    if (currentScanId) {
        window.location.href = 'generate_pdf.php?scan_id=' + currentScanId;
    }
}

function scanNewFile() {
    // Reset form
    document.getElementById('fileInput').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('statusText').textContent = 'Select any file type - .exe, .dll, .pdf, .zip, and more';
    document.getElementById('statusText').style.color = '';
    document.getElementById('scanBtn').disabled = true;
    selectedFile = null;
    currentScanId = null;
    
    // Remove any info boxes
    const oldInfo = document.querySelector('.whitelist-info');
    const oldRec = document.querySelector('.recommendation');
    if (oldInfo) oldInfo.remove();
    if (oldRec) oldRec.remove();
}

// Utility function
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}