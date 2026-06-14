<?php
ob_start();
session_start();
error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

function h($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

if (empty($_SESSION['user_email']) || empty($_SESSION['initiated']) || empty($_SESSION['user_id'])) {
    header("Location: ../login.php?message=Please+login+first");
    exit();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once('../dbConnectionLocal.php');
$conn = db_connect();

if (!$conn) {
    die("Database connection failed.");
}

$user_id = (int)$_SESSION['user_id'];
$user_name = h($_SESSION['name'] ?? '');
$user_role = '';

$role_stmt = mysqli_prepare($conn, "SELECT role FROM users WHERE id = ? LIMIT 1");
if ($role_stmt) {
    mysqli_stmt_bind_param($role_stmt, "i", $user_id);
    mysqli_stmt_execute($role_stmt);
    mysqli_stmt_bind_result($role_stmt, $user_role);
    mysqli_stmt_fetch($role_stmt);
    mysqli_stmt_close($role_stmt);
}

$_SESSION['role'] = $user_role;

if ($user_role !== 'Admin') {
    header("Location: home.php?error=Access+denied");
    exit();
}

$error = "";
$success = "";
$applications = [];
$totalApplications = 0;
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$perPage = 10;
$offset = ($page - 1) * $perPage;
$filterStatus = isset($_GET['status']) ? trim($_GET['status']) : 'Pending';
$allowedStatuses = ['Pending', 'Approved', 'Rejected', ''];

if (!in_array($filterStatus, $allowedStatuses, true)) {
    $filterStatus = 'Pending';
}

// ========================================
// HANDLE APPROVE/REJECT APPLICATION
// ========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['decision'])) {
    $app_id = isset($_POST['application_id']) ? (int)$_POST['application_id'] : 0;
    $decision = trim($_POST['decision']);
    $comments = trim($_POST['comments'] ?? '');
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $error = "Invalid request. Please refresh the page and try again.";
    } elseif ($app_id <= 0) {
        $error = "Invalid application.";
    } elseif (!in_array($decision, ['Approved', 'Rejected'], true)) {
        $error = "Invalid decision.";
    } elseif (strlen($comments) > 2000) {
        $error = "Approver comments must be 2000 characters or fewer.";
    } elseif (!mysqli_begin_transaction($conn)) {
        $error = "Could not start review transaction.";
    } else {
        $shouldRollback = true;

        $get_app = mysqli_prepare($conn, "
            SELECT user_id, number_of_days, leave_type, status
            FROM leave_applications
            WHERE id = ?
            LIMIT 1
            FOR UPDATE
        ");

        if ($get_app) {
            mysqli_stmt_bind_param($get_app, "i", $app_id);
            mysqli_stmt_execute($get_app);
            mysqli_stmt_store_result($get_app);

            if (mysqli_stmt_num_rows($get_app) === 1) {
                mysqli_stmt_bind_result($get_app, $app_user_id, $app_days, $app_leave_type, $app_status);
                mysqli_stmt_fetch($get_app);

                if ($app_status === 'Pending') {
                    $update_stmt = mysqli_prepare($conn, "
                        UPDATE leave_applications
                        SET
                            status = ?,
                            approver_comments = ?,
                            approved_by_user_id = ?,
                            updated_at = NOW()
                        WHERE id = ? AND status = 'Pending'
                    ");

                    if ($update_stmt) {
                        mysqli_stmt_bind_param($update_stmt, "ssii", $decision, $comments, $user_id, $app_id);

                        if (mysqli_stmt_execute($update_stmt) && mysqli_stmt_affected_rows($update_stmt) === 1) {
                            $balanceUpdated = true;

                            if ($decision === 'Approved') {
                                $balance_update = mysqli_prepare($conn, "
                                    UPDATE leave_balances
                                    SET balance = balance - ?
                                    WHERE user_id = ?
                                        AND leave_type = ?
                                        AND year = YEAR(CURDATE())
                                        AND balance >= ?
                                ");

                                if ($balance_update) {
                                    mysqli_stmt_bind_param($balance_update, "disd", $app_days, $app_user_id, $app_leave_type, $app_days);
                                    $balanceUpdated = mysqli_stmt_execute($balance_update)
                                        && mysqli_stmt_affected_rows($balance_update) === 1;
                                    mysqli_stmt_close($balance_update);
                                } else {
                                    $balanceUpdated = false;
                                }
                            }

                            if ($balanceUpdated) {
                                $auditAction = ($decision === 'Approved') ? 'APPROVE_LEAVE' : 'REJECT_LEAVE';
                                $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                                $log_data = "Decision: " . $decision;
                                $log_stmt = mysqli_prepare($conn, "
                                    INSERT INTO audit_logs (user_id, action, module, record_id, new_value, ip_address)
                                    VALUES (?, ?, 'leave_applications', ?, ?, ?)
                                ");

                                if ($log_stmt) {
                                    mysqli_stmt_bind_param($log_stmt, "isiss", $user_id, $auditAction, $app_id, $log_data, $ip);
                                    mysqli_stmt_execute($log_stmt);
                                    mysqli_stmt_close($log_stmt);
                                }

                                if (mysqli_commit($conn)) {
                                    $shouldRollback = false;
                                    $success = "Application " . strtolower($decision) . " successfully.";
                                } else {
                                    $error = "Error saving application review.";
                                }
                            } else {
                                $error = "Unable to approve leave because the employee does not have enough available balance.";
                            }
                        } else {
                            $error = "Application could not be updated. It may have already been reviewed.";
                        }

                        mysqli_stmt_close($update_stmt);
                    } else {
                        $error = "Could not prepare application update.";
                    }
                } else {
                    $error = "This application has already been " . strtolower($app_status) . ".";
                }
            } else {
                $error = "Application not found.";
            }

            mysqli_stmt_close($get_app);
        } else {
            $error = "Could not load application for review.";
        }

        if ($shouldRollback) {
            mysqli_rollback($conn);
        }
    }
}

// ========================================
// FETCH APPLICATIONS (SECURE STMT)
// ========================================
if (!empty($filterStatus)) {
    $count_stmt = mysqli_prepare($conn, "SELECT COUNT(*) FROM leave_applications WHERE status = ?");

    $list_stmt = mysqli_prepare($conn, "
        SELECT
            la.id, u.name, u.email, u.designation, la.leave_type,
            la.number_of_days, la.start_date, la.end_date, la.status,
            la.created_at, la.reason
        FROM leave_applications la
        JOIN users u ON la.user_id = u.id
        WHERE la.status = ?
        ORDER BY la.created_at DESC
        LIMIT ? OFFSET ?
    ");
} else {
    $count_stmt = mysqli_prepare($conn, "SELECT COUNT(*) FROM leave_applications");

    $list_stmt = mysqli_prepare($conn, "
        SELECT
            la.id, u.name, u.email, u.designation, la.leave_type,
            la.number_of_days, la.start_date, la.end_date, la.status,
            la.created_at, la.reason
        FROM leave_applications la
        JOIN users u ON la.user_id = u.id
        ORDER BY la.created_at DESC
        LIMIT ? OFFSET ?
    ");
}

if ($count_stmt) {
    if (!empty($filterStatus)) {
        mysqli_stmt_bind_param($count_stmt, "s", $filterStatus);
    }

    mysqli_stmt_execute($count_stmt);
    mysqli_stmt_bind_result($count_stmt, $totalApplications);
    mysqli_stmt_fetch($count_stmt);
    mysqli_stmt_close($count_stmt);
} elseif (empty($error)) {
    $error = "Could not load application counts.";
}

if ($list_stmt) {
    if (!empty($filterStatus)) {
        mysqli_stmt_bind_param($list_stmt, "sii", $filterStatus, $perPage, $offset);
    } else {
        mysqli_stmt_bind_param($list_stmt, "ii", $perPage, $offset);
    }

    mysqli_stmt_execute($list_stmt);
    mysqli_stmt_store_result($list_stmt);
    mysqli_stmt_bind_result(
        $list_stmt,
        $id,
        $name,
        $email,
        $designation,
        $leave_type,
        $num_days,
        $start_date,
        $end_date,
        $status,
        $created_at,
        $reason
    );

    while (mysqli_stmt_fetch($list_stmt)) {
        $applications[] = [
            'id' => (int)$id,
            'name' => $name,
            'email' => $email,
            'designation' => $designation,
            'leave_type' => $leave_type,
            'days' => (int)$num_days,
            'start_date' => $start_date,
            'end_date' => $end_date,
            'status' => $status,
            'created_at' => $created_at,
            'reason' => $reason,
        ];
    }

    mysqli_stmt_close($list_stmt);
} elseif (empty($error)) {
    $error = "Could not load applications.";
}

$pending_count = 0;
$approved_count = 0;
$rejected_count = 0;

$stats_stmt = mysqli_prepare($conn, "
    SELECT
        COALESCE(SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END), 0) AS pending,
        COALESCE(SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END), 0) AS approved,
        COALESCE(SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END), 0) AS rejected
    FROM leave_applications
");

if ($stats_stmt) {
    mysqli_stmt_execute($stats_stmt);
    mysqli_stmt_bind_result($stats_stmt, $pending_count, $approved_count, $rejected_count);
    mysqli_stmt_fetch($stats_stmt);
    mysqli_stmt_close($stats_stmt);
}

$totalPages = (int)ceil($totalApplications / $perPage);

if ($conn) {
    mysqli_close($conn);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Leave Approvals - Admin</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <style>
        body {
            background: #f5f5f5;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding-top: 60px;
        }
        .container-main {
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 15px;
        }
        .page-header {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .page-header h2 {
            color: #dc3545;
            font-weight: 700;
            margin: 0 0 5px 0;
        }
        .page-header p {
            color: #666;
            margin: 0;
        }
        .stats-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            text-align: center;
            border-top: 5px solid #ffc107;
        }
        .stat-card h3 {
            font-size: 36px;
            font-weight: 700;
            color: #ffc107;
            margin: 15px 0;
        }
        .stat-card p {
            color: #666;
            margin: 0;
            font-size: 14px;
        }
        .stat-card.approved { border-top-color: #28a745; }
        .stat-card.approved h3 { color: #28a745; }
        .stat-card.rejected { border-top-color: #dc3545; }
        .stat-card.rejected h3 { color: #dc3545; }

        .filter-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-buttons a {
            padding: 8px 16px;
            border-radius: 4px;
            border: 2px solid #ddd;
            text-decoration: none;
            color: #666;
            font-weight: 600;
            transition: all 0.3s ease;
            background: white;
        }
        .filter-buttons a.active {
            background: #ffc107;
            color: white;
            border-color: #ffc107;
        }
        .filter-buttons a:hover { border-color: #ffc107; }

        .table-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        table { margin: 0; }
        table thead {
            background: #f9f9f9;
            border-bottom: 2px solid #e9ecef;
        }
        table th {
            padding: 15px;
            font-weight: 700;
            color: #333;
            border: none;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        table td {
            padding: 12px 15px;
            border: none;
            border-bottom: 1px solid #f0f0f0;
            font-size: 13px;
        }
        table tbody tr:hover { background: #f9f9f9; }

        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-approved { background: #d4edda; color: #155724; }
        .status-rejected { background: #f8d7da; color: #721c24; }

        .action-buttons { display: flex; gap: 8px; }
        .btn-review {
            background: #ffc107;
            color: white;
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-review:hover { background: #e0a800; }
        .btn-review[disabled]:hover { background: #ffc107; }

        .modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
        }
        .modal.show { display: block; }
        .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 10001;
        }
        .modal-dialog {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            border-radius: 8px;
            padding: 0;
            z-index: 10002;
            max-width: 600px;
            width: 95%;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
        }
        .modal-header {
            background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
            color: white;
            padding: 20px 25px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 { margin: 0; font-weight: 700; font-size: 18px; }
        .modal-close {
            cursor: pointer;
            font-size: 28px;
            color: white;
            border: none;
            background: none;
            padding: 0;
            line-height: 1;
        }
        .modal-body { padding: 25px; }
        .modal-footer {
            padding: 20px 25px;
            border-top: 1px solid #e9ecef;
        }
        .form-group label {
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-group textarea {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            font-size: 14px;
            width: 100%;
            min-height: 100px;
            resize: vertical;
        }
        .form-group textarea:focus {
            outline: none;
            border-color: #ffc107;
            box-shadow: 0 0 0 3px rgba(255, 193, 7, 0.1);
        }
        .btn-approve,
        .btn-reject,
        .btn-cancel {
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-approve { background: #28a745; }
        .btn-approve:hover { background: #218838; }
        .btn-reject { background: #dc3545; }
        .btn-reject:hover { background: #c82333; }
        .btn-cancel { background: #6c757d; }
        .btn-cancel:hover { background: #5a6268; }
        .alert { border-radius: 6px; margin-bottom: 20px; }
        .alert-error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .empty-state { text-align: center; padding: 50px 20px; color: #999; }
        .pagination-container {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            border-top: 1px solid #f0f0f0;
        }
        .pagination-container a {
            padding: 6px 12px;
            border-radius: 4px;
            border: 1px solid #ddd;
            text-decoration: none;
            color: #007BFF;
            margin: 0 5px;
            transition: all 0.3s ease;
        }
        .pagination-container a:hover,
        .pagination-container a.active {
            background: #007BFF;
            color: white;
            border-color: #007BFF;
        }

        @media (max-width: 768px) {
            .stats-cards { grid-template-columns: 1fr; }
            .filter-buttons { flex-direction: column; }
            .filter-buttons a { width: 100%; }
            table { font-size: 12px; }
            table th, table td { padding: 10px; }
        }
    </style>
</head>
<body>

<?php include 'navbar.php'; ?>

<div class="container-main">
    <div class="page-header">
        <h2><span class="glyphicon glyphicon-check"></span> Leave Application Approvals</h2>
        <p>Review and approve/reject leave applications</p>
    </div>

    <?php if (!empty($error)): ?>
        <div class="alert alert-error">
            <button type="button" class="close" data-dismiss="alert">&times;</button>
            <strong>Error:</strong> <?= h($error); ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="alert alert-success">
            <button type="button" class="close" data-dismiss="alert">&times;</button>
            <strong>Success!</strong> <?= h($success); ?>
        </div>
    <?php endif; ?>

    <div class="stats-cards">
        <div class="stat-card">
            <p>Pending Approvals</p>
            <h3><?= (int)$pending_count; ?></h3>
        </div>
        <div class="stat-card approved">
            <p>Approved</p>
            <h3><?= (int)$approved_count; ?></h3>
        </div>
        <div class="stat-card rejected">
            <p>Rejected</p>
            <h3><?= (int)$rejected_count; ?></h3>
        </div>
    </div>

    <div class="filter-section">
        <h4><span class="glyphicon glyphicon-filter"></span> Filter by Status</h4>
        <div class="filter-buttons">
            <a href="?status=Pending" class="<?= ($filterStatus === 'Pending') ? 'active' : ''; ?>">
                <span class="glyphicon glyphicon-time"></span> Pending
            </a>
            <a href="?status=Approved" class="<?= ($filterStatus === 'Approved') ? 'active' : ''; ?>">
                <span class="glyphicon glyphicon-ok"></span> Approved
            </a>
            <a href="?status=Rejected" class="<?= ($filterStatus === 'Rejected') ? 'active' : ''; ?>">
                <span class="glyphicon glyphicon-remove"></span> Rejected
            </a>
            <a href="?status=" class="<?= (empty($filterStatus)) ? 'active' : ''; ?>">
                <span class="glyphicon glyphicon-list"></span> All
            </a>
        </div>
    </div>

    <div class="table-container">
        <div style="overflow-x: auto;">
            <table class="table">
                <thead>
                    <tr>
                        <th>Employee</th>
                        <th>Designation</th>
                        <th>Leave Type</th>
                        <th style="text-align: center;">Days</th>
                        <th>Date Range</th>
                        <th>Status</th>
                        <th>Applied On</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (!empty($applications)): ?>
                        <?php foreach ($applications as $app): ?>
                            <?php
                            $startFormatted = date('d-m-y', strtotime($app['start_date']));
                            $endFormatted = date('d-m-y', strtotime($app['end_date']));
                            $dateRange = $startFormatted . ' to ' . $endFormatted;
                            $appliedDate = date('d-m-Y', strtotime($app['created_at']));

                            $statusClass = 'status-pending';
                            if ($app['status'] === 'Approved') {
                                $statusClass = 'status-approved';
                            } elseif ($app['status'] === 'Rejected') {
                                $statusClass = 'status-rejected';
                            }
                            ?>
                            <tr>
                                <td>
                                    <strong><?= h($app['name']); ?></strong>
                                    <br>
                                    <small style="color: #999;"><?= h($app['email']); ?></small>
                                </td>
                                <td><?= h($app['designation']); ?></td>
                                <td><?= h($app['leave_type']); ?></td>
                                <td style="text-align: center;"><span class="badge"><?= (int)$app['days']; ?></span></td>
                                <td><?= h($dateRange); ?></td>
                                <td>
                                    <span class="status-badge <?= h($statusClass); ?>">
                                        <?= h($app['status']); ?>
                                    </span>
                                </td>
                                <td><?= h($appliedDate); ?></td>
                                <td>
                                    <div class="action-buttons">
                                        <?php if ($app['status'] === 'Pending'): ?>
                                            <button
                                                type="button"
                                                class="btn-review js-review-button"
                                                data-app-id="<?= (int)$app['id']; ?>"
                                                data-employee-name="<?= h($app['name']); ?>"
                                                data-leave-reason="<?= h($app['reason']); ?>"
                                            >
                                                <span class="glyphicon glyphicon-eye-open"></span> Review
                                            </button>
                                        <?php else: ?>
                                            <button class="btn-review" disabled style="opacity: 0.6; cursor: not-allowed;">
                                                <span class="glyphicon glyphicon-lock"></span> <?= h($app['status']); ?>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="8">
                                <div class="empty-state">
                                    <i class="glyphicon glyphicon-inbox"></i>
                                    <p>No applications found for the selected filter.</p>
                                </div>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
            <div class="pagination-container">
                <?php if ($page > 1): ?>
                    <a href="?page=1&status=<?= urlencode($filterStatus); ?>">First</a>
                    <a href="?page=<?= $page - 1; ?>&status=<?= urlencode($filterStatus); ?>">Previous</a>
                <?php endif; ?>

                <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                    <a href="?page=<?= $i; ?>&status=<?= urlencode($filterStatus); ?>" class="<?= ($i === $page) ? 'active' : ''; ?>">
                        <?= $i; ?>
                    </a>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="?page=<?= $page + 1; ?>&status=<?= urlencode($filterStatus); ?>">Next</a>
                    <a href="?page=<?= $totalPages; ?>&status=<?= urlencode($filterStatus); ?>">Last</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<div id="reviewModal" class="modal" aria-hidden="true">
    <div class="modal-backdrop" data-close-review-modal></div>
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="reviewModalTitle">
        <div class="modal-header">
            <h3 id="reviewModalTitle"><span class="glyphicon glyphicon-check"></span> Review Leave Application</h3>
            <button type="button" class="modal-close" data-close-review-modal>&times;</button>
        </div>
        <form method="post" action="">
            <div class="modal-body">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="application_id" id="modalAppId">

                <div class="form-group">
                    <label>Employee Name:</label>
                    <p id="modalEmployeeName" style="font-weight: 600; color: #333; margin: 5px 0 15px 0;"></p>
                </div>

                <div class="form-group">
                    <label>Leave Reason:</label>
                    <p id="modalLeaveReason" style="background: #f9f9f9; padding: 12px; border-radius: 4px; margin: 5px 0 15px 0; max-height: 120px; overflow-y: auto; color: #555; border: 1px solid #eee;"></p>
                </div>

                <div class="form-group">
                    <label for="comments">Approver Comments</label>
                    <textarea id="comments" name="comments" maxlength="2000" placeholder="Add any comments for the employee (optional)..."></textarea>
                </div>
            </div>

            <div class="modal-footer" style="display: block; width: 100%;">
                <div style="display: flex; gap: 10px; width: 100%; justify-content: space-between; align-items: center;">
                    <div style="display: flex; gap: 10px; flex: 1;">
                        <button type="submit" name="decision" value="Approved" class="btn-approve" style="margin: 0; padding: 10px 20px; flex: 1;">
                            <span class="glyphicon glyphicon-ok"></span> Approve
                        </button>
                        <button type="submit" name="decision" value="Rejected" class="btn-reject" style="margin: 0; padding: 10px 20px; flex: 1;">
                            <span class="glyphicon glyphicon-remove"></span> Reject
                        </button>
                    </div>

                    <button type="button" class="btn-cancel" data-close-review-modal style="padding: 10px 20px; margin: 0;">Cancel</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>

<script>
    (function () {
        const modal = document.getElementById('reviewModal');
        const appIdInput = document.getElementById('modalAppId');
        const employeeName = document.getElementById('modalEmployeeName');
        const leaveReason = document.getElementById('modalLeaveReason');
        const comments = document.getElementById('comments');

        function openReviewModal(button) {
            appIdInput.value = button.dataset.appId;
            employeeName.textContent = button.dataset.employeeName || '';
            leaveReason.textContent = button.dataset.leaveReason || 'No reason provided.';
            comments.value = '';
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
            comments.focus();
        }

        function closeReviewModal() {
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
        }

        document.querySelectorAll('.js-review-button').forEach(function (button) {
            button.addEventListener('click', function () {
                openReviewModal(button);
            });
        });

        document.querySelectorAll('[data-close-review-modal]').forEach(function (button) {
            button.addEventListener('click', closeReviewModal);
        });

        window.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' && modal.classList.contains('show')) {
                closeReviewModal();
            }
        });
    }());
</script>
</body>
</html>
