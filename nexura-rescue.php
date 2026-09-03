<?php
// phpcs:ignoreFile PluginCheck.Security.DirectFileAccess.missing_direct_file_access_protection - This is a standalone rescue script.
/**
 * Nexura Security - Disaster Recovery & Rescue Script
 * Version: 1.0.1
 * 
 * INSTRUCTIONS: Upload this file to the root of your domain (where wp-config.php usually is).
 * Then visit: https://yourdomain.com/nexura-rescue.php
 */

error_reporting(0); // phpcs:ignore PluginCheck.CodeAnalysis.PHPErrorReporting.DirectErrorReportingCall
// Suppress errors for clean UI
ini_set('max_execution_time', 300); // Allow time for downloads and unzipping

$worker_base_url = 'https://sgs-db-worker.sentinel-guard-security.workers.dev';
$step = isset($_GET['step']) ? htmlspecialchars(strip_tags($_GET['step'])) : 'login';
$message = '';
$error = '';

session_start();

// SECURITY FIX: Prevent browser caching of sensitive data
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// SECURITY FIX: IP Binding & Strict 30-Minute Expiration Check
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
if ( isset( $_SESSION['nexura_ip'] ) && $_SESSION['nexura_ip'] !== $client_ip ) {
    session_destroy();
    die('Security Error: IP address mismatch for recovery session.');
}

if ( isset( $_SESSION['nexura_recovery_expiry'] ) && time() > $_SESSION['nexura_recovery_expiry'] ) {
    session_destroy();
    die('Security Error: Recovery session expired (30-minute limit). Please log in again.');
}

// SECURITY FIX: Basic rate limiting
$_SESSION['login_attempts'] = $_SESSION['login_attempts'] ?? 0;
if ($_SESSION['login_attempts'] >= 5) {
    die('Rate limit exceeded. Please wait 15 minutes before trying again.');
}
function nexura_api_request($url, $method = 'GET', $headers = [], $body = null) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

    // --- SECURITY FIX: Always verify SSL certificates to prevent MITM attacks ---
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    // Use bundled CA cert if available on the system
    $ca_bundle = __DIR__ . '/cacert.pem';
    if ( file_exists( $ca_bundle ) ) {
        curl_setopt( $ch, CURLOPT_CAINFO, $ca_bundle );
    }
    
    $req_headers = [];
    foreach ($headers as $k => $v) {
        $req_headers[] = "$k: $v";
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $req_headers);
    
    if ($body) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return ['code' => $httpcode, 'body' => $response];
}

function nexura_stream_download($url, $dest_path, $headers = []) {
    $ch = curl_init($url);
    $fp = fopen($dest_path, 'wb');
    if (!$fp) return false;
    
    curl_setopt($ch, CURLOPT_FILE, $fp);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    // SSL Verification
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    $ca_bundle = __DIR__ . '/cacert.pem';
    if (file_exists($ca_bundle)) {
        curl_setopt($ch, CURLOPT_CAINFO, $ca_bundle);
    }
    
    if (!empty($headers)) {
        $req_headers = [];
        foreach ($headers as $k => $v) {
            $req_headers[] = "$k: $v";
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $req_headers);
    }
    
    $aborted = false;
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$aborted, $dest_path) {
        if (stripos($header, 'Content-Length:') === 0) {
            $len = (int)trim(substr($header, 15));
            $max_size = 500 * 1024 * 1024; // 500MB Max backup size
            $free_space = disk_free_space(__DIR__);
            
            if ($len > $max_size) {
                $aborted = 'File size exceeds maximum allowed limit (500MB).';
                return 0; // Abort
            }
            if ($free_space !== false && $len > ($free_space - (50 * 1024 * 1024))) {
                $aborted = 'Insufficient disk space available.';
                return 0; // Abort
            }
        }
        return strlen($header);
    });
    
    curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    fclose($fp);
    
    if ($aborted !== false) {
        unlink($dest_path);
        die("Security Error: " . $aborted);
    }
    
    return $httpcode == 200;
}

function nexura_safe_extract_zip($zip, $dest_dir) {
    if (!is_dir($dest_dir)) {
        @mkdir($dest_dir, 0755, true);
    }
    $dest_dir = realpath($dest_dir);
    if (!$dest_dir) return false;

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $stat = $zip->statIndex($i);
        if (!$stat) continue;
        
        $filename = $stat['name'];
        
        // 1. Reject absolute paths
        if (strpos($filename, '/') === 0 || preg_match('/^[a-zA-Z]:\\\\/', $filename)) {
            continue;
        }
        
        // 2. Reject path traversal
        if (strpos($filename, '../') !== false || strpos($filename, '..\\') !== false) {
            continue;
        }
        
        $target_path = $dest_dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $filename);
        
        if (substr($filename, -1) === '/') {
            if (!is_dir($target_path)) {
                mkdir($target_path, 0755, true);
            }
            continue;
        }

        $target_dir = dirname($target_path);
        if (!is_dir($target_dir)) {
            mkdir($target_dir, 0755, true);
        }
        
        // 3. Canonicalize and ensure target remains inside allowed root
        $canonical_dir = realpath($target_dir);
        if ($canonical_dir === false || strpos($canonical_dir . DIRECTORY_SEPARATOR, rtrim($dest_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) !== 0) {
            continue; // Out of bounds or unexpected destination
        }
        
        // 4. Extract securely using streams (rejects symlinks automatically in PHP)
        $fp = $zip->getStream($filename);
        if (!$fp) continue;
        
        $out = fopen($target_path, 'wb');
        if ($out) {
            while (!feof($fp)) {
                fwrite($out, fread($fp, 8192));
            }
            fclose($out);
        }
        fclose($fp);
    }
    return true;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($step === 'login') {
        $domain = isset($_POST['domain']) ? htmlspecialchars(strip_tags(trim($_POST['domain']))) : '';
        $license = isset($_POST['license']) ? htmlspecialchars(strip_tags(trim($_POST['license']))) : '';
        
        if (empty($domain) || empty($license)) {
            $error = 'Please enter both Domain and License Key.';
        } else {
            // Fetch Backup List
            $res = nexura_api_request("$worker_base_url/v1/backup/list", 'GET', [
                'X-Site-Url' => $domain,
                'X-License-Key' => $license
            ]);
            
            $data = json_decode($res['body'], true);
            // Verify if recovery token exists in response
            if ($res['code'] == 200 && !empty($data['backups']) && !empty($data['recovery_token'])) {
                // SECURITY FIX: Prevent session fixation
                session_regenerate_id(true);
                $_SESSION['login_attempts'] = 0; // Reset rate limit
                
                $_SESSION['nexura_domain'] = $domain;
                $_SESSION['nexura_ip'] = $client_ip;
                // Secure Authentication: Store short-lived token (30-minute limit) instead of raw license
                $_SESSION['nexura_recovery_token'] = $data['recovery_token'];
                $_SESSION['nexura_recovery_expiry'] = time() + 1800; // Strict 30-minute expiration
                $_SESSION['nexura_recovery_nonce'] = isset($data['nonce']) ? $data['nonce'] : bin2hex(random_bytes(16));
                $_SESSION['nexura_backups'] = $data['backups'];
                
                // Anti-CSRF Token for the standalone page
                $_SESSION['nexura_csrf_token'] = bin2hex(random_bytes(32));
                
                header("Location: ?step=select_backup");
                exit;
            } else {
                $_SESSION['login_attempts']++;
                $error = 'No backups found or Invalid License/Domain.';
            }
        }
    } elseif ($step === 'restore') {
        // Anti-CSRF Validation
        $submitted_csrf = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
        $session_csrf = isset($_SESSION['nexura_csrf_token']) ? $_SESSION['nexura_csrf_token'] : '';
        if (empty($session_csrf) || !hash_equals($session_csrf, $submitted_csrf)) {
            die('CSRF token validation failed. Please reload the page and try again.');
        }

        $file_key = isset($_POST['file_key']) ? htmlspecialchars(strip_tags(trim($_POST['file_key']))) : '';
        $domain = $_SESSION['nexura_domain'];
        
        $token = isset($_SESSION['nexura_recovery_token']) ? $_SESSION['nexura_recovery_token'] : '';
        $nonce = isset($_SESSION['nexura_recovery_nonce']) ? $_SESSION['nexura_recovery_nonce'] : '';
        $expiry = isset($_SESSION['nexura_recovery_expiry']) ? $_SESSION['nexura_recovery_expiry'] : 0;
        
        if (time() > $expiry || empty($token)) {
            session_destroy();
            die('Recovery token expired or invalid. Please login again.');
        }
        
        // 1. Download Backup from R2 using streamed download to prevent disk/memory exhaustion
        $zip_path = __DIR__ . '/nexura-restore.zip';
        $download_success = nexura_stream_download("$worker_base_url/v1/backup/download?file=" . urlencode($file_key), $zip_path, [
            'Authorization' => 'Bearer ' . $token,
            'X-Recovery-Nonce' => $nonce,
            'X-Site-Url' => $domain
        ]);
        
        if ($download_success) {
            
            // 2. Unzip Backup
            $zip = new ZipArchive;
            if ($zip->open($zip_path) === TRUE) {
                // Pre-Restore Backup of Critical Files
                $critical_files = ['wp-config.php', '.htaccess', 'index.php'];
                $manifest = [];
                $backup_dir = __DIR__ . '/nexura-pre-restore-backup-' . time();
                
                if (mkdir($backup_dir, 0755)) {
                    file_put_contents($backup_dir . '/.htaccess', 'deny from all'); // Secure backup dir
                    foreach ($critical_files as $cf) {
                        if (file_exists(__DIR__ . '/' . $cf)) {
                            copy(__DIR__ . '/' . $cf, $backup_dir . '/' . $cf);
                            $manifest[] = htmlspecialchars($cf);
                        }
                    }
                    if (!empty($manifest)) {
                        $_SESSION['nexura_restore_manifest'] = $manifest;
                        $_SESSION['nexura_backup_dir'] = basename($backup_dir);
                    }
                }
                
                nexura_safe_extract_zip($zip, __DIR__);
                $zip->close();
                unlink($zip_path);
                
                // 3. Process Dependency Restore (nexus-state.json)
                if (file_exists(__DIR__ . '/nexus-state.json')) {
                    $state = json_decode(file_get_contents(__DIR__ . '/nexus-state.json'), true);
                    
                    // Restore WP Core if missing
                    if (!file_exists(__DIR__ . '/wp-includes/version.php')) {
                        $wp_ver = isset($state['wp_version']) ? $state['wp_version'] : '';
                        if (!preg_match('/^[0-9]+\.[0-9]+(\.[0-9]+)?$/', $wp_ver)) {
                            die('Security Error: Invalid WordPress version format in state file.');
                        }
                        
                        
                        $wp_zip_url = "https://wordpress.org/wordpress-{$wp_ver}.zip";
                        $wp_zip_path = __DIR__ . '/wp-core.zip';
                        if (!nexura_stream_download($wp_zip_url, $wp_zip_path)) {
                            die('Failed to download WordPress Core.');
                        }
                        
                        // SHA-256 Verification (Security Check)
                        if (!empty($state['hashes']['wp_core'])) {
                            if (hash_file('sha256', $wp_zip_path) !== $state['hashes']['wp_core']) {
                                unlink($wp_zip_path);
                                die('Security Error: WordPress Core ZIP SHA-256 checksum mismatch. Download may be corrupted or intercepted.');
                            }
                        }
                        
                        $core_zip = new ZipArchive;
                        if ($core_zip->open($wp_zip_path) === TRUE) {
                            nexura_safe_extract_zip($core_zip, __DIR__);
                            $core_zip->close();
                            // WP extracts into 'wordpress' folder, move it to root
                            if (is_dir(__DIR__ . '/wordpress')) {
                                $files = scandir(__DIR__ . '/wordpress');
                                foreach($files as $file) {
                                    if ($file != '.' && $file != '..') {
                                        rename(__DIR__ . '/wordpress/' . $file, __DIR__ . '/' . $file);
                                    }
                                }
                                rmdir(__DIR__ . '/wordpress');
                            }
                            unlink($wp_zip_path);
                        }
                    }
                    
                    // Restore Free Plugins
                    if (!empty($state['repo_plugins'])) {
                        foreach ($state['repo_plugins'] as $plugin) {
                            // sanitize_key logic
                            $plugin = strtolower(preg_replace('/[^a-z0-9_-]/', '', $plugin));
                            
                            // WordPress.org repository lookup (Security Check)
                            $info_res = nexura_api_request("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={$plugin}");
                            $info = json_decode($info_res['body'], true);
                            if (empty($info['slug'])) {
                                die("Security Error: Plugin {$plugin} not found in official WordPress.org repository.");
                            }
                            
                            $p_zip = __DIR__ . "/{$plugin}.zip";
                            $p_url = "https://downloads.wordpress.org/plugin/{$plugin}.zip"; // gets latest
                            if (nexura_stream_download($p_url, $p_zip)) {
                                
                                // SHA-256 Verification (Security Check)
                                if (!empty($state['hashes']['plugins'][$plugin])) {
                                    if (hash_file('sha256', $p_zip) !== $state['hashes']['plugins'][$plugin]) {
                                        unlink($p_zip);
                                        die("Security Error: Plugin {$plugin} ZIP SHA-256 checksum mismatch.");
                                    }
                                }

                                $pz = new ZipArchive;
                                if ($pz->open($p_zip) === TRUE) {
                                    nexura_safe_extract_zip($pz, __DIR__ . '/wp-content/plugins/');
                                    $pz->close();
                                }
                                unlink($p_zip);
                            }
                        }
                    }
                    
                    // Restore Free Themes
                    if (!empty($state['repo_themes'])) {
                        foreach ($state['repo_themes'] as $theme) {
                            // sanitize_key logic
                            $theme = strtolower(preg_replace('/[^a-z0-9_-]/', '', $theme));
                            
                            // WordPress.org repository lookup (Security Check)
                            $info_res = nexura_api_request("https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={$theme}");
                            $info = json_decode($info_res['body'], true);
                            if (empty($info['slug'])) {
                                die("Security Error: Theme {$theme} not found in official WordPress.org repository.");
                            }
                            
                            $t_zip = __DIR__ . "/{$theme}.zip";
                            $t_url = "https://downloads.wordpress.org/theme/{$theme}.zip";
                            if (nexura_stream_download($t_url, $t_zip)) {
                                
                                // SHA-256 Verification (Security Check)
                                if (!empty($state['hashes']['themes'][$theme])) {
                                    if (hash_file('sha256', $t_zip) !== $state['hashes']['themes'][$theme]) {
                                        unlink($t_zip);
                                        die("Security Error: Theme {$theme} ZIP SHA-256 checksum mismatch.");
                                    }
                                }

                                $tz = new ZipArchive;
                                if ($tz->open($t_zip) === TRUE) {
                                    nexura_safe_extract_zip($tz, __DIR__ . '/wp-content/themes/');
                                    $tz->close();
                                }
                                unlink($t_zip);
                            }
                        }
                    }
                    
                    unlink(__DIR__ . '/nexus-state.json');
                }
                
                header("Location: ?step=success");
                exit;
            } else {
                $error = 'Failed to extract the backup ZIP.';
            }
        } else {
            $error = 'Failed to download backup from Cloudflare R2.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexura Security - Disaster Recovery</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #1e293b; padding: 40px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 1px solid #334155; width: 100%; max-width: 450px; text-align: center; }
        h1 { margin-top: 0; color: #38bdf8; font-size: 24px; }
        p { color: #94a3b8; font-size: 14px; margin-bottom: 25px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #fff; box-sizing: border-box; }
        button { background: #3b82f6; color: white; border: none; padding: 12px 20px; border-radius: 8px; width: 100%; cursor: pointer; font-size: 16px; font-weight: bold; transition: background 0.3s; }
        button:hover { background: #2563eb; }
        .error { background: #ef444420; color: #ef4444; border: 1px solid #ef4444; padding: 10px; border-radius: 8px; margin-bottom: 15px; font-size: 14px; }
        .backup-card { background: #0f172a; border: 1px solid #475569; padding: 15px; border-radius: 8px; margin-bottom: 10px; text-align: left; }
        .success-icon { font-size: 50px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($step === 'login'): ?>
            <h1><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg> Site Disaster Recovery</h1>
            <p>Connect to Cloudflare R2 to retrieve your backups.</p>
            <form method="POST">
                <input type="text" name="domain" placeholder="Domain (e.g. example.com)" required>
                <input type="password" name="license" placeholder="Nexura Pro License Key" required>
                <button type="submit">Connect to Cloudflare</button>
            </form>

        <?php elseif ($step === 'select_backup'): ?>
            <h1><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg> Select Backup</h1>
            <p>We found these backups for <strong><?php echo htmlspecialchars($_SESSION['nexura_domain'] ?? ''); ?></strong></p>
            <form method="POST" action="?step=restore" onsubmit="document.getElementById('res-btn').innerText='Restoring (Please Wait)...';">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['nexura_csrf_token'] ?? ''); ?>">
                <?php foreach (($_SESSION['nexura_backups'] ?? []) as $index => $b): ?>
                    <div class="backup-card">
                        <label style="cursor: pointer; display: flex; align-items: center; gap: 10px;">
                            <input type="radio" name="file_key" value="<?php echo htmlspecialchars($b['key']); ?>" <?php echo $index === 0 ? 'checked' : ''; ?>>
                            <div>
                                <strong><?php echo $index === 0 ? '<svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align: middle; color: #10b981;"><circle cx="12" cy="12" r="10"></circle></svg> Latest Backup' : '<svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align: middle; color: #eab308;"><circle cx="12" cy="12" r="10"></circle></svg> Older Backup'; ?></strong><br>
                                <span style="font-size: 12px; color: #94a3b8;">
                                    Size: <?php echo round($b['size'] / 1048576, 2); ?> MB | 
                                    Date: <?php echo gmdate('Y-m-d H:i', strtotime($b['uploaded'])); ?>
                                </span>
                            </div>
                        </label>
                    </div>
                <?php endforeach; ?>
                <button type="submit" id="res-btn" style="margin-top: 15px; background: #10b981;">Restore Website Now</button>
            </form>

        <?php elseif ($step === 'success'): 
            // SECURITY FIX: Extract manifest details before destroying session
            $manifest = $_SESSION['nexura_restore_manifest'] ?? [];
            $backup_dir = $_SESSION['nexura_backup_dir'] ?? '';

            // SECURITY FIX: Automatic Self-Deletion and Token Destruction upon completion
            $rescue_file = __FILE__;
            $self_deleted = false;
            if ( file_exists( $rescue_file ) ) {
                $self_deleted = @unlink( $rescue_file );
            }
            // Destroy recovery session & token completely
            session_destroy();
        ?>
            <div class="success-icon"><svg width="50" height="50" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #10b981;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></div>
            <h1>Site Restored Successfully!</h1>
            <p>Your website has been completely restored from the cloud snapshot.</p>
            
            <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 20px; text-align: left;">
                <strong>🛡️ Security Hardened:</strong>
                <?php if ( $self_deleted ) : ?>
                    This rescue script (<code>nexura-rescue.php</code>) and session tokens have been automatically deleted from your server root to prevent unauthorized access.
                <?php else : ?>
                    Session tokens have been destroyed. Please manually delete <code>nexura-rescue.php</code> from your server root for security.
                <?php endif; ?>
            </div>

            <?php if (!empty($manifest)): ?>
                <div style="background: #1e293b; border: 1px solid #475569; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: left;">
                    <h3 style="color: #eab308; margin-top: 0; font-size: 16px;">Notice: Critical Files Overwritten</h3>
                    <p style="font-size: 13px; margin-bottom: 10px;">The following files were overwritten during recovery. We created a local backup for you in the folder <code><?php echo htmlspecialchars($backup_dir); ?></code>.</p>
                    <ul style="font-size: 13px; color: #94a3b8; margin: 0; padding-left: 20px;">
                        <?php foreach ($manifest as $file): ?>
                            <li><?php echo $file; ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
            <a href="/"><button style="background: #10b981;">Visit Website</button></a>
        <?php endif; ?>
    </div>
</body>
</html>
