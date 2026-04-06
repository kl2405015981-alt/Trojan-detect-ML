<?php
/**
 * timezone_helper.php
 * ====================
 * Helper functions to convert UTC to Malaysia timezone
 * 
 * Usage:
 *   include 'timezone_helper.php';
 *   echo format_datetime($db_datetime);  // Output: 20 Feb 2026, 01:42 PM
 */

/**
 * Set default timezone to Malaysia
 */
date_default_timezone_set('Asia/Kuala_Lumpur');

/**
 * Convert UTC datetime from database to Malaysia time
 * 
 * @param string $utc_datetime - DateTime string from database (UTC)
 * @param string $format - Output format (default: 'd M Y, h:i A')
 * @return string - Formatted datetime in Malaysia timezone
 */
function format_datetime($utc_datetime, $format = 'd M Y, h:i A') {
    if (empty($utc_datetime) || $utc_datetime === '0000-00-00 00:00:00') {
        return 'N/A';
    }
    
    try {
        // Create DateTime object from UTC time
        $dt = new DateTime($utc_datetime, new DateTimeZone('UTC'));
        
        // Convert to Malaysia timezone (UTC+8)
        $dt->setTimezone(new DateTimeZone('Asia/Kuala_Lumpur'));
        
        // Return formatted string
        return $dt->format($format);
        
    } catch (Exception $e) {
        // Fallback if error
        return date($format, strtotime($utc_datetime));
    }
}

/**
 * Format datetime for display in table
 * Output: 20 Feb 2026, 05:42
 */
function format_datetime_short($utc_datetime) {
    return format_datetime($utc_datetime, 'd M Y, H:i');
}

/**
 * Format datetime with seconds
 * Output: 20 Feb 2026, 01:42:30 PM
 */
function format_datetime_full($utc_datetime) {
    return format_datetime($utc_datetime, 'd M Y, h:i:s A');
}

/**
 * Format date only
 * Output: 20 Feb 2026
 */
function format_date($utc_datetime) {
    return format_datetime($utc_datetime, 'd M Y');
}

/**
 * Format time only
 * Output: 01:42 PM
 */
function format_time($utc_datetime) {
    return format_datetime($utc_datetime, 'h:i A');
}

/**
 * Convert Malaysia time to UTC for storing in database
 * 
 * @param string $malaysia_datetime - DateTime string in Malaysia time
 * @return string - UTC datetime string for database
 */
function to_utc($malaysia_datetime) {
    try {
        $dt = new DateTime($malaysia_datetime, new DateTimeZone('Asia/Kuala_Lumpur'));
        $dt->setTimezone(new DateTimeZone('UTC'));
        return $dt->format('Y-m-d H:i:s');
    } catch (Exception $e) {
        return date('Y-m-d H:i:s');
    }
}

/**
 * Get current datetime in Malaysia timezone
 * Output: 2026-02-20 13:42:00
 */
function now_malaysia($format = 'Y-m-d H:i:s') {
    $dt = new DateTime('now', new DateTimeZone('Asia/Kuala_Lumpur'));
    return $dt->format($format);
}

/**
 * Relative time (e.g., "2 hours ago", "Just now")
 */
function time_ago($utc_datetime) {
    try {
        $dt_utc = new DateTime($utc_datetime, new DateTimeZone('UTC'));
        $dt_utc->setTimezone(new DateTimeZone('Asia/Kuala_Lumpur'));
        
        $now = new DateTime('now', new DateTimeZone('Asia/Kuala_Lumpur'));
        $diff = $now->diff($dt_utc);
        
        if ($diff->days > 7) {
            return format_datetime($utc_datetime, 'd M Y');
        } elseif ($diff->days > 0) {
            return $diff->days . ' day' . ($diff->days > 1 ? 's' : '') . ' ago';
        } elseif ($diff->h > 0) {
            return $diff->h . ' hour' . ($diff->h > 1 ? 's' : '') . ' ago';
        } elseif ($diff->i > 0) {
            return $diff->i . ' minute' . ($diff->i > 1 ? 's' : '') . ' ago';
        } else {
            return 'Just now';
        }
    } catch (Exception $e) {
        return 'Unknown';
    }
}