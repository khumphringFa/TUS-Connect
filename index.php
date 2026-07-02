<?php
session_start();
error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);
ini_set('display_errors', 0);

require_once('dbConnectionLocal.php');

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// Already logged in -> go to dashboard landing.
if (!empty($_SESSION['user_email']) && !empty($_SESSION['initiated']) && !empty($_SESSION['user_id'])) {
    $role = $_SESSION['role'] ?? '';
    if (in_array($role, ['Admin', 'Manager', 'Approver'], true)) {
        header('Location: /pages/admin_work_plans.php');
    } else {
        header('Location: /pages/work_plan.php');
    }
    exit();
}

$error = $_GET['message'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    $conn = db_connect();

    if (!$conn) {
        $error = 'Database connection failed.';
    } else {
        $stmt = mysqli_prepare($conn, "SELECT id, name, email, password, designation, project_name, role FROM users WHERE email = ? LIMIT 1");
        mysqli_stmt_bind_param($stmt, 's', $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $id, $name, $dbEmail, $hash, $designation, $project, $role);

        if (mysqli_stmt_fetch($stmt) && password_verify($password, $hash)) {
            mysqli_stmt_close($stmt);

            $_SESSION['user_id'] = (int)$id;
            $_SESSION['user_email'] = $dbEmail;
            $_SESSION['name'] = $name;
            $_SESSION['designation'] = $designation;
            $_SESSION['project_name'] = $project;
            $_SESSION['role'] = $role;
            $_SESSION['initiated'] = true;

            if (in_array($role, ['Admin', 'Manager', 'Approver'], true)) {
                header('Location: /pages/admin_work_plans.php');
            } else {
                header('Location: /pages/work_plan.php');
            }
            exit();
        }

        mysqli_stmt_close($stmt);
        $error = 'Invalid email or password.';
        mysqli_close($conn);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <style>
        body { background:#f5f5f5; font-family:Arial, sans-serif; }
        .login-box { max-width:380px; margin:80px auto; background:#fff; padding:30px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,.12); }
        .login-box h3 { color:#007bff; text-align:center; margin-top:0; }
        .hint { font-size:12px; color:#666; margin-top:15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h3>Trinamul Unnayan Sangstha</h3>
        <p class="text-center">Sign in</p>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?= h($error); ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" class="form-control" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>

        <div class="hint">
            Demo accounts (password: <code>password</code>):<br>
            admin@tus.test (Admin) &middot; manager@tus.test (Manager) &middot; employee@tus.test (Employee)
        </div>
    </div>
</body>
</html>
