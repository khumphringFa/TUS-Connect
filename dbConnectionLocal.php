<?php
// dbConnectionLocal.php

function leave_db_env($key, $default = '')
{
    $value = getenv($key);

    if ($value === false || $value === '') {
        return $default;
    }

    return $value;
}

function db_connect()
{
    mysqli_report(MYSQLI_REPORT_OFF);

    $host = leave_db_env('DB_HOST', 'localhost');
    $dbname = leave_db_env('DB_NAME', 'trinamul_leave');
    $username = leave_db_env('DB_USER');
    $password = leave_db_env('DB_PASSWORD');

    if ($username === '' || $password === '') {
        error_log('Database credentials are not configured. Set DB_USER and DB_PASSWORD.');
        return false;
    }

    $conn = new mysqli($host, $username, $password, $dbname);

    if ($conn->connect_error) {
        error_log('Database connection failed: ' . $conn->connect_error);
        return false;
    }

    if (!$conn->set_charset('utf8mb4')) {
        error_log('Failed to set database charset: ' . $conn->error);
        $conn->close();
        return false;
    }

    return $conn;
}
