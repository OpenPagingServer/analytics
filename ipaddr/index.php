<?php
header("Content-Type: text/plain");

if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    echo $_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    echo trim($ips[0]);
} else {
    echo $_SERVER['REMOTE_ADDR'];
}
