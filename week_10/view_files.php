<?php
// Simple File System Viewer
if (isset($_GET['path'])) {
    $path = $_GET['path'];
} else {
    $path = '.';
}

if (is_dir($path)) {
    $files = scandir($path);
    echo "<h1>Directory contents of: " . htmlspecialchars($path) . "</h1>";
    echo "<ul>";
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        $fullPath = realpath($path . DIRECTORY_SEPARATOR . $file);
        if (is_dir($fullPath)) {
            echo "<li><a href='?path=" . urlencode($fullPath) . "'>[DIR] " . htmlspecialchars($file) . "</a></li>";
        } else {
            echo "<li>" . htmlspecialchars($file) . "</li>";
        }
    }
    echo "</ul>";
} else {
    echo "<h1>Invalid path</h1>";
}
?>