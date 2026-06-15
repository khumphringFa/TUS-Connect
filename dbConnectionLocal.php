<?php
/**
 * Local database connection helper.
 *
 * Returns a mysqli connection. Credentials can be overridden with the
 * DB_HOST / DB_USER / DB_PASS / DB_NAME / DB_PORT environment variables so the
 * same code runs in local/dev and on the server.
 */

if (!function_exists('db_connect')) {
    function db_connect() {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $user = getenv('DB_USER') ?: 'app';
        $pass = getenv('DB_PASS');
        if ($pass === false) {
            $pass = 'app_pass';
        }
        $name = getenv('DB_NAME') ?: 'leave_app';
        $port = (int)(getenv('DB_PORT') ?: 3306);

        $conn = @mysqli_connect($host, $user, $pass, $name, $port);

        if (!$conn) {
            return null;
        }

        mysqli_set_charset($conn, 'utf8mb4');

        return $conn;
    }
}
