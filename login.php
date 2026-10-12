<?php
/* Panel · Login */
session_start();
require __DIR__ . '/config.php';
if (panel_logueado()) { header('Location: dashboard.php'); exit; }

$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['user'] ?? '');
    $p = (string)($_POST['pass'] ?? '');
    $ip = client_ip();
    // Anti brute-force: max 8 intentos fallidos por IP en 15 min
    $lr = json_read(F_LOGIN);
    $now = time();
    $lr = array_filter($lr, fn($t) => ($now - (int)$t) < 900);
    $fallos = 0;
    foreach ($lr as $k => $t) { if (strpos($k, $ip . '_') === 0) $fallos++; }
    if ($fallos >= 8) {
        $err = 'Demasiados intentos. Espera unos minutos.';
        log_accion('login_bloqueado_ip', $u . ' @ ' . $ip);
    } else {
        $usuarios = json_read(F_USUARIOS);
        $ok = false;
        foreach ($usuarios as $usr) {
            if (($usr['user'] ?? '') === $u && password_verify($p, $usr['pass'] ?? '')) { $ok = true; break; }
        }
        if ($ok) {
            $_SESSION['panel_user'] = $u;
            json_write(F_LOGIN, array_filter($lr, fn($t) => true));
            log_accion('login_panel', $u);
            header('Location: dashboard.php'); exit;
        }
        $lr[$ip . '_' . microtime(true)] = $now;
        json_write(F_LOGIN, $lr);
        $err = 'Usuario o clave incorrectos';
        log_accion('login_fallido', $u . ' @ ' . $ip);
    }
}

