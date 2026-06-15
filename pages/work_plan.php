<?php
ob_start();
session_start();
error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function column_exists($conn, $table, $column) {
    $table = mysqli_real_escape_string($conn, $table);
    $column = mysqli_real_escape_string($conn, $column);
    $result = mysqli_query($conn, "SHOW COLUMNS FROM `$table` LIKE '$column'");
    return $result && mysqli_num_rows($result) > 0;
}

function ensure_work_plan_tables($conn) {
    mysqli_query($conn, "
        CREATE TABLE IF NOT EXISTS monthly_work_plans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            plan_month INT NOT NULL,
            plan_year INT NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'Draft',
            edit_request_status VARCHAR(30) NULL,
            edit_request_reason TEXT NULL,
            edit_request_at DATETIME NULL,
            edit_request_reviewed_by INT NULL,
            edit_request_reviewed_at DATETIME NULL,
            submitted_at DATETIME NULL,
            reviewed_by_user_id INT NULL,
            reviewed_at DATETIME NULL,
            reviewer_comments TEXT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NULL DEFAULT NULL,
            UNIQUE KEY unique_user_month_year (user_id, plan_month, plan_year)
        )
    ");

    mysqli_query($conn, "
        CREATE TABLE IF NOT EXISTS monthly_work_plan_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            plan_id INT NOT NULL,
            work_date DATE NOT NULL,
            activity TEXT NULL,
            objective TEXT NULL,
            location TEXT NULL,
            expected_output TEXT NULL,
            responsible_support TEXT NULL,
            remarks TEXT NULL,
            achievement TEXT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NULL DEFAULT NULL,
            UNIQUE KEY unique_plan_date (plan_id, work_date)
        )
    ");
}

function ensure_work_plan_columns($conn) {
    $columns = [
        'edit_request_status' => "ALTER TABLE monthly_work_plans ADD COLUMN edit_request_status VARCHAR(30) NULL",
        'edit_request_reason' => "ALTER TABLE monthly_work_plans ADD COLUMN edit_request_reason TEXT NULL",
        'edit_request_at' => "ALTER TABLE monthly_work_plans ADD COLUMN edit_request_at DATETIME NULL",
        'edit_request_reviewed_by' => "ALTER TABLE monthly_work_plans ADD COLUMN edit_request_reviewed_by INT NULL",
        'edit_request_reviewed_at' => "ALTER TABLE monthly_work_plans ADD COLUMN edit_request_reviewed_at DATETIME NULL"
    ];

    foreach ($columns as $column => $sql) {
        if (!column_exists($conn, 'monthly_work_plans', $column)) {
            mysqli_query($conn, $sql);
        }
    }
}

function get_assigned_manager($conn, $employeeId) {
    $manager = null;

    $stmt = mysqli_prepare($conn, "
        SELECT u.id, u.name, u.email, ac.approval_level
        FROM approval_chains ac
        JOIN users u ON u.id = ac.approver_id
        WHERE ac.employee_id = ?
          AND ac.status = 'Active'
        ORDER BY ac.approval_level ASC
        LIMIT 1
    ");

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $employeeId);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        mysqli_stmt_bind_result($stmt, $mid, $mname, $memail, $level);

        if (mysqli_stmt_fetch($stmt)) {
            $manager = [
                'id' => (int)$mid,
                'name' => $mname,
                'email' => $memail,
                'level' => (int)$level
            ];
        }

        mysqli_stmt_close($stmt);
    }

    if ($manager) {
        return $manager;
    }

    $stmt = mysqli_prepare($conn, "
        SELECT u.id, u.name, u.email, ac.approval_level
        FROM approval_chains ac
        JOIN users u ON u.id = ac.approver_id
        WHERE ac.employee_id = ?
        ORDER BY ac.approval_level ASC
        LIMIT 1
    ");

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $employeeId);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        mysqli_stmt_bind_result($stmt, $mid, $mname, $memail, $level);

        if (mysqli_stmt_fetch($stmt)) {
            $manager = [
                'id' => (int)$mid,
                'name' => $mname,
                'email' => $memail,
                'level' => (int)$level
            ];
        }

        mysqli_stmt_close($stmt);
    }

    return $manager;
}

function can_review_work_plan($conn, $viewerId, $viewerRole, $employeeId) {
    if ($viewerRole === 'Admin') {
        return true;
    }

    if (!in_array($viewerRole, ['Manager', 'Approver'], true)) {
        return false;
    }

    $stmt = mysqli_prepare($conn, "
        SELECT id
        FROM approval_chains
        WHERE employee_id = ?
          AND approver_id = ?
          AND status = 'Active'
        LIMIT 1
    ");

    if (!$stmt) {
        return false;
    }

    mysqli_stmt_bind_param($stmt, "ii", $employeeId, $viewerId);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    $allowed = mysqli_stmt_num_rows($stmt) === 1;

    mysqli_stmt_close($stmt);

    if ($allowed) {
        return true;
    }

    $stmt = mysqli_prepare($conn, "
        SELECT id
        FROM approval_chains
        WHERE employee_id = ?
          AND approver_id = ?
        LIMIT 1
    ");

    if (!$stmt) {
        return false;
    }

    mysqli_stmt_bind_param($stmt, "ii", $employeeId, $viewerId);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    $allowed = mysqli_stmt_num_rows($stmt) === 1;

    mysqli_stmt_close($stmt);

    return $allowed;
}

function get_or_create_plan($conn, $userId, $month, $year) {
    $stmt = mysqli_prepare($conn, "
        SELECT id
        FROM monthly_work_plans
        WHERE user_id = ?
          AND plan_month = ?
          AND plan_year = ?
        LIMIT 1
    ");

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "iii", $userId, $month, $year);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        mysqli_stmt_bind_result($stmt, $planId);

        if (mysqli_stmt_fetch($stmt)) {
            mysqli_stmt_close($stmt);
            return (int)$planId;
        }

        mysqli_stmt_close($stmt);
    }

    $insert = mysqli_prepare($conn, "
        INSERT INTO monthly_work_plans
            (user_id, plan_month, plan_year, status)
        VALUES
            (?, ?, ?, 'Draft')
    ");

    mysqli_stmt_bind_param($insert, "iii", $userId, $month, $year);
    mysqli_stmt_execute($insert);
    $newId = mysqli_insert_id($conn);
    mysqli_stmt_close($insert);

    return (int)$newId;
}

function fetch_plan($conn, $planId) {
    $stmt = mysqli_prepare($conn, "
        SELECT
            mwp.id,
            mwp.user_id,
            mwp.plan_month,
            mwp.plan_year,
            mwp.status,
            mwp.edit_request_status,
            mwp.edit_request_reason,
            mwp.edit_request_at,
            mwp.submitted_at,
            mwp.reviewed_by_user_id,
            mwp.reviewed_at,
            mwp.reviewer_comments,
            mwp.created_at,
            mwp.updated_at,
            u.name,
            u.email,
            u.designation,
            u.project_name,
            reviewer.name AS reviewer_name
        FROM monthly_work_plans mwp
        JOIN users u ON u.id = mwp.user_id
        LEFT JOIN users reviewer ON reviewer.id = mwp.reviewed_by_user_id
        WHERE mwp.id = ?
        LIMIT 1
    ");

    if (!$stmt) {
        return null;
    }

    mysqli_stmt_bind_param($stmt, "i", $planId);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    mysqli_stmt_bind_result(
        $stmt,
        $id,
        $userId,
        $month,
        $year,
        $status,
        $editRequestStatus,
        $editRequestReason,
        $editRequestAt,
        $submittedAt,
        $reviewedBy,
        $reviewedAt,
        $reviewerComments,
        $createdAt,
        $updatedAt,
        $name,
        $email,
        $designation,
        $project,
        $reviewerName
    );

    $plan = null;

    if (mysqli_stmt_fetch($stmt)) {
        $plan = [
            'id' => (int)$id,
            'user_id' => (int)$userId,
            'month' => (int)$month,
            'year' => (int)$year,
            'status' => $status,
            'edit_request_status' => $editRequestStatus,
            'edit_request_reason' => $editRequestReason,
            'edit_request_at' => $editRequestAt,
            'submitted_at' => $submittedAt,
            'reviewed_by_user_id' => $reviewedBy,
            'reviewed_at' => $reviewedAt,
            'reviewer_comments' => $reviewerComments,
            'created_at' => $createdAt,
            'updated_at' => $updatedAt,
            'name' => $name,
            'email' => $email,
            'designation' => $designation,
            'project_name' => $project,
            'reviewer_name' => $reviewerName
        ];
    }

    mysqli_stmt_close($stmt);

    return $plan;
}

function fetch_plan_items($conn, $planId) {
    $items = [];

    $stmt = mysqli_prepare($conn, "
        SELECT
            id,
            work_date,
            activity,
            objective,
            location,
            expected_output,
            responsible_support,
            remarks,
            achievement
        FROM monthly_work_plan_items
        WHERE plan_id = ?
        ORDER BY work_date ASC
    ");

    if (!$stmt) {
        return $items;
    }

    mysqli_stmt_bind_param($stmt, "i", $planId);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    mysqli_stmt_bind_result(
        $stmt,
        $id,
        $workDate,
        $activity,
        $objective,
        $location,
        $expectedOutput,
        $responsible,
        $remarks,
        $achievement
    );

    while (mysqli_stmt_fetch($stmt)) {
        $items[] = [
            'id' => (int)$id,
            'work_date' => $workDate,
            'activity' => $activity,
            'objective' => $objective,
            'location' => $location,
            'expected_output' => $expectedOutput,
            'responsible_support' => $responsible,
            'remarks' => $remarks,
            'achievement' => $achievement
        ];
    }

    mysqli_stmt_close($stmt);

    return $items;
}

if (empty($_SESSION['user_email']) || empty($_SESSION['initiated']) || empty($_SESSION['user_id'])) {
    header("Location: /index.php?message=Please+login+first");
    exit();
}

require_once('../dbConnectionLocal.php');
$conn = db_connect();

if (!$conn) {
    die("Database connection failed.");
}

ensure_work_plan_tables($conn);
ensure_work_plan_columns($conn);

$user_id = (int)$_SESSION['user_id'];
$error = "";
$success = "";

$name = $_SESSION['name'] ?? '';
$email = $_SESSION['user_email'] ?? '';
$designation = $_SESSION['designation'] ?? '';
$project_name = $_SESSION['project_name'] ?? '';
$user_role = '';

$stmt = mysqli_prepare($conn, "
    SELECT name, email, designation, project_name, role
    FROM users
    WHERE id = ?
    LIMIT 1
");

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $db_name, $db_email, $db_designation, $db_project, $db_role);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    $name = $db_name ?: $name;
    $email = $db_email ?: $email;
    $designation = $db_designation ?: $designation;
    $project_name = $db_project ?: $project_name;
    $user_role = $db_role ?: '';
    $_SESSION['role'] = $user_role;
}

$selectedMonth = isset($_GET['month']) ? (int)$_GET['month'] : (int)date('n');
$selectedYear = isset($_GET['year']) ? (int)$_GET['year'] : (int)date('Y');

if ($selectedMonth < 1 || $selectedMonth > 12) {
    $selectedMonth = (int)date('n');
}

if ($selectedYear < 2000 || $selectedYear > 2100) {
    $selectedYear = (int)date('Y');
}

$monthName = date('F', mktime(0, 0, 0, $selectedMonth, 1));
$daysInMonth = (int)date('t', strtotime(sprintf('%04d-%02d-01', $selectedYear, $selectedMonth)));

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* Save draft / submit */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['save_plan']) || isset($_POST['submit_plan']))) {
    $csrf = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $error = "Invalid request. Please refresh and try again.";
    } else {
        $postMonth = (int)($_POST['month'] ?? $selectedMonth);
        $postYear = (int)($_POST['year'] ?? $selectedYear);

        $planId = get_or_create_plan($conn, $user_id, $postMonth, $postYear);
        $plan = fetch_plan($conn, $planId);

        $canEditMainPlan = $plan && (
            in_array($plan['status'], ['Draft', 'Rejected'], true)
            || $plan['edit_request_status'] === 'Approved'
        );

        if (!$plan || $plan['user_id'] !== $user_id) {
            $error = "Unable to load work plan.";
        } elseif (!$canEditMainPlan) {
            $error = "This work plan has already been submitted. Please send an edit request if changes are needed.";
        } else {
            $workDates = $_POST['work_date'] ?? [];
            $activities = $_POST['activity'] ?? [];
            $objectives = $_POST['objective'] ?? [];
            $locations = $_POST['location'] ?? [];
            $outputs = $_POST['expected_output'] ?? [];
            $responsibles = $_POST['responsible_support'] ?? [];
            $remarksList = $_POST['remarks'] ?? [];

            $deleteItems = mysqli_prepare($conn, "DELETE FROM monthly_work_plan_items WHERE plan_id = ?");
            if ($deleteItems) {
                mysqli_stmt_bind_param($deleteItems, "i", $planId);
                mysqli_stmt_execute($deleteItems);
                mysqli_stmt_close($deleteItems);
            }

            $insertItem = mysqli_prepare($conn, "
                INSERT INTO monthly_work_plan_items
                    (plan_id, work_date, activity, objective, location, expected_output, responsible_support, remarks)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?)
            ");

            if ($insertItem) {
                foreach ($workDates as $idx => $workDate) {
                    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $workDate)) {
                        continue;
                    }

                    $activity = trim($activities[$idx] ?? '');
                    $objective = trim($objectives[$idx] ?? '');
                    $location = trim($locations[$idx] ?? '');
                    $output = trim($outputs[$idx] ?? '');
                    $responsible = trim($responsibles[$idx] ?? '');
                    $remarks = trim($remarksList[$idx] ?? '');

                    mysqli_stmt_bind_param(
                        $insertItem,
                        "isssssss",
                        $planId,
                        $workDate,
                        $activity,
                        $objective,
                        $location,
                        $output,
                        $responsible,
                        $remarks
                    );

                    mysqli_stmt_execute($insertItem);
                }

                mysqli_stmt_close($insertItem);
            }

            if (isset($_POST['submit_plan'])) {
                $manager = get_assigned_manager($conn, $user_id);

                if (!$manager) {
                    $error = "No assigned manager found. Please contact Admin to setup approval chain.";
                } else {
                    $updatePlan = mysqli_prepare($conn, "
                        UPDATE monthly_work_plans
                        SET status = 'Submitted',
                            submitted_at = NOW(),
                            edit_request_status = NULL,
                            edit_request_reason = NULL,
                            edit_request_at = NULL,
                            reviewed_by_user_id = NULL,
                            reviewed_at = NULL,
                            reviewer_comments = NULL,
                            updated_at = NOW()
                        WHERE id = ?
                    ");

                    mysqli_stmt_bind_param($updatePlan, "i", $planId);
                    mysqli_stmt_execute($updatePlan);
                    mysqli_stmt_close($updatePlan);

                    $success = "Monthly work plan submitted to " . h($manager['name']) . ".";
                    $selectedMonth = $postMonth;
                    $selectedYear = $postYear;
                }
            } else {
                $updatePlan = mysqli_prepare($conn, "
                    UPDATE monthly_work_plans
                    SET status = 'Draft',
                        updated_at = NOW()
                    WHERE id = ?
                ");

                mysqli_stmt_bind_param($updatePlan, "i", $planId);
                mysqli_stmt_execute($updatePlan);
                mysqli_stmt_close($updatePlan);

                $success = "Work plan saved as draft.";
                $selectedMonth = $postMonth;
                $selectedYear = $postYear;
            }
        }
    }
}

/* Send edit request */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_edit_request'])) {
    $csrf = $_POST['csrf_token'] ?? '';
    $planId = (int)($_POST['plan_id'] ?? 0);
    $reason = trim($_POST['edit_request_reason'] ?? '');

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $error = "Invalid request.";
    } elseif ($reason === '') {
        $error = "Please write a reason for edit request.";
    } else {
        $plan = fetch_plan($conn, $planId);

        if (!$plan || $plan['user_id'] !== $user_id) {
            $error = "Work plan not found.";
        } elseif ($plan['status'] === 'Draft' || $plan['status'] === 'Rejected') {
            $error = "This work plan is already editable.";
        } else {
            $stmtReq = mysqli_prepare($conn, "
                UPDATE monthly_work_plans
                SET edit_request_status = 'Pending',
                    edit_request_reason = ?,
                    edit_request_at = NOW(),
                    edit_request_reviewed_by = NULL,
                    edit_request_reviewed_at = NULL,
                    updated_at = NOW()
                WHERE id = ?
            ");

            mysqli_stmt_bind_param($stmtReq, "si", $reason, $planId);

            if (mysqli_stmt_execute($stmtReq)) {
                $success = "Edit request sent to assigned manager.";
            } else {
                $error = "Could not send edit request.";
            }

            mysqli_stmt_close($stmtReq);
        }
    }
}

/* Save achievements */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_achievements'])) {
    $csrf = $_POST['csrf_token'] ?? '';
    $planId = (int)($_POST['plan_id'] ?? 0);

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $error = "Invalid request.";
    } else {
        $plan = fetch_plan($conn, $planId);

        if (!$plan || $plan['user_id'] !== $user_id) {
            $error = "You are not allowed to update achievements.";
        } elseif ($plan['status'] !== 'Approved') {
            $error = "Achievements can be updated only after work plan approval.";
        } else {
            $itemIds = $_POST['item_id'] ?? [];
            $achievements = $_POST['achievement'] ?? [];

            foreach ($itemIds as $idx => $itemId) {
                $itemId = (int)$itemId;
                $achievement = trim($achievements[$idx] ?? '');

                if ($itemId <= 0) {
                    continue;
                }

                $achStmt = mysqli_prepare($conn, "
                    UPDATE monthly_work_plan_items
                    SET achievement = ?,
                        updated_at = NOW()
                    WHERE id = ?
                      AND plan_id = ?
                ");

                if ($achStmt) {
                    mysqli_stmt_bind_param($achStmt, "sii", $achievement, $itemId, $planId);
                    mysqli_stmt_execute($achStmt);
                    mysqli_stmt_close($achStmt);
                }
            }

            $success = "Achievements saved successfully.";
        }
    }
}

$currentPlanId = get_or_create_plan($conn, $user_id, $selectedMonth, $selectedYear);
$currentPlan = fetch_plan($conn, $currentPlanId);
$currentItems = fetch_plan_items($conn, $currentPlanId);

$itemByDate = [];
foreach ($currentItems as $item) {
    $itemByDate[$item['work_date']] = $item;
}

mysqli_close($conn);

$statusClass = 'status-draft';
if ($currentPlan['status'] === 'Submitted') {
    $statusClass = 'status-submitted';
} elseif ($currentPlan['status'] === 'Approved') {
    $statusClass = 'status-approved';
} elseif ($currentPlan['status'] === 'Rejected') {
    $statusClass = 'status-rejected';
}

$isEditable = in_array($currentPlan['status'], ['Draft', 'Rejected'], true)
    || $currentPlan['edit_request_status'] === 'Approved';

$showAchievementColumn = ($currentPlan['status'] === 'Approved');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Monthly Work Plan</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link rel="icon" type="image/png" href="/img/logo/tus_b2.png">
    <link rel="shortcut icon" type="image/png" href="/img/logo/tus_b2.png">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">

    <style>
        body {
            background: #f5f5f5;
            font-family: Arial, sans-serif;
            padding-top: 70px;
        }

        .container-main {
            max-width: 1300px;
            margin: 30px auto;
            padding: 0 15px;
        }

        .sheet {
            background: #fff;
            padding: 35px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.12);
            margin-bottom: 25px;
        }

        .sheet-header {
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 18px;
            margin-bottom: 25px;
        }

        .org-header {
            position: relative;
            min-height: 95px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .org-logo {
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 90px;
            height: auto;
        }

        .org-info {
            text-align: center;
            padding: 0 110px;
        }

        .org-info h3 {
            margin: 0 0 5px 0;
            font-weight: bold;
            color: #007bff;
            font-size: 22px;
        }

        .org-info p {
            margin: 2px 0;
            font-size: 14px;
            color: #333;
        }

        .form-title {
            color: #800000;
            margin: 20px 0 0 0;
            font-weight: bold;
            text-transform: uppercase;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 25px;
        }

        .info-item {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 10px;
            font-size: 14px;
        }

        .info-item strong {
            display: inline-block;
            min-width: 130px;
        }

        .filter-area {
            text-align: right;
            margin-bottom: 15px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        table th {
            background: #007bff;
            color: white;
            text-align: center;
            font-size: 12px;
            vertical-align: middle !important;
            border: 1px solid #0069d9;
            padding: 8px;
        }

        table td {
            border: 1px solid #ccc;
            padding: 8px;
            font-size: 13px;
            vertical-align: top;
        }

        table textarea,
        table input {
            width: 100%;
            border: none;
            resize: vertical;
            min-height: 48px;
            outline: none;
            background: transparent;
            font-size: 13px;
        }

        .section-title {
            background: #e7f3ff;
            border-left: 5px solid #007bff;
            padding: 10px 12px;
            margin: 20px 0 10px;
            font-weight: bold;
            color: #0056b3;
        }

        .signature-section {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 25px;
            margin-top: 45px;
            text-align: center;
        }

        .signature-box {
            border-top: 1px solid #333;
            padding-top: 8px;
            font-weight: bold;
            font-size: 13px;
        }

        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 16px;
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
        }

        .status-draft {
            background: #e2e3e5;
            color: #383d41;
        }

        .status-submitted {
            background: #fff3cd;
            color: #856404;
        }

        .status-approved {
            background: #d4edda;
            color: #155724;
        }

        .status-rejected {
            background: #f8d7da;
            color: #721c24;
        }

        .btn-print {
            background: #17a2b8;
            color: white;
            border: none;
        }

        .btn-print:hover {
            background: #138496;
            color: white;
        }

        @media print {
            .navbar,
            .no-print,
            .site-footer {
                display: none !important;
            }

            body {
                background: white;
                padding-top: 0;
            }

            .container-main {
                margin: 0;
                max-width: 100%;
                padding: 0;
            }

            .sheet {
                box-shadow: none;
                border-radius: 0;
                padding: 15px;
            }

            table th,
            table td {
                font-size: 10px;
                padding: 5px;
            }

            table textarea,
            table input {
                border: none;
                overflow: hidden;
            }
        }

        @media (max-width: 700px) {
            .org-logo {
                position: static;
                transform: none;
                display: block;
                margin: 0 auto 10px;
            }

            .org-header {
                display: block;
            }

            .org-info {
                padding: 0;
            }

            .info-grid,
            .signature-section {
                grid-template-columns: 1fr;
            }

            .filter-area {
                text-align: left;
            }
        }
    </style>
</head>

<body>

<?php include 'navbar.php'; ?>

<div class="container-main">

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger no-print">
            <strong>Error:</strong> <?= h($error); ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="alert alert-success no-print">
            <strong>Success:</strong> <?= h($success); ?>
        </div>
    <?php endif; ?>

    <div class="no-print filter-area">
        <form method="get" action="" class="form-inline" style="display:inline-block; margin-right:10px;">
            <select name="month" class="form-control">
                <?php for ($m = 1; $m <= 12; $m++): ?>
                    <option value="<?= $m; ?>" <?= $selectedMonth === $m ? 'selected' : ''; ?>>
                        <?= date('F', mktime(0, 0, 0, $m, 1)); ?>
                    </option>
                <?php endfor; ?>
            </select>

            <input type="number" name="year" class="form-control" value="<?= (int)$selectedYear; ?>" min="2000" max="2100">

            <button type="submit" class="btn btn-primary">
                Generate
            </button>
        </form>

        <button type="button" class="btn btn-print" onclick="window.print()">
            <span class="glyphicon glyphicon-print"></span> Print / Save PDF
        </button>
    </div>

    <form method="post" action="">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="month" value="<?= (int)$selectedMonth; ?>">
        <input type="hidden" name="year" value="<?= (int)$selectedYear; ?>">
        <input type="hidden" name="plan_id" value="<?= (int)$currentPlan['id']; ?>">

        <div class="sheet">
            <div class="sheet-header">
                <div class="org-header">
                    <img class="org-logo" src="https://www.trinamulchtbd.org/public/images/settings/1772007296.9576_1751906617.2319_TUS_logo_1.jpg" alt="TUS Logo">

                    <div class="org-info">
                        <h3>Trinamul Unnayan Sangstha</h3>
                        <p>(An organization for Community Development)</p>
                        <p>Khagrachari Sadar, Khagrachari Hill District - 4400</p>
                        <p>Phone: 8802337714282, Fax: 8802337714282.</p>
                    </div>
                </div>

                <h2 class="form-title">Monthly Work Plan</h2>
                <p>
                    <span class="status-badge <?= h($statusClass); ?>">
                        <?= h($currentPlan['status']); ?>
                    </span>
                </p>

                <?php if (!empty($currentPlan['edit_request_status'])): ?>
                    <p class="no-print">
                        <strong>Edit Request:</strong> <?= h($currentPlan['edit_request_status']); ?>
                    </p>
                <?php endif; ?>
            </div>

            <div class="info-grid">
                <div class="info-item">
                    <strong>Employee Name:</strong> <?= h($name); ?>
                </div>

                <div class="info-item">
                    <strong>Email:</strong> <?= h($email); ?>
                </div>

                <div class="info-item">
                    <strong>Designation:</strong> <?= h($designation); ?>
                </div>

                <div class="info-item">
                    <strong>Project:</strong> <?= h($project_name); ?>
                </div>

                <div class="info-item">
                    <strong>Month:</strong> <?= h($monthName); ?>
                </div>

                <div class="info-item">
                    <strong>Year:</strong> <?= (int)$selectedYear; ?>
                </div>
            </div>

            <?php if (!$isEditable && !$showAchievementColumn): ?>
                <div class="alert alert-info no-print">
                    This work plan is already submitted/final. Main plan editing is locked.
                </div>
            <?php endif; ?>

            <?php if ($showAchievementColumn): ?>
                <div class="alert alert-success no-print">
                    Work plan approved. You can now enter and update achievements.
                </div>
            <?php endif; ?>

            <div class="section-title">A. Planned Activities</div>

            <table>
                <thead>
                    <tr>
                        <th style="width:9%;">Date</th>
                        <th style="width:6%;">Day</th>
                        <th style="width:14%;">Major Activity</th>
                        <th style="width:13%;">Objective / Purpose</th>
                        <th style="width:10%;">Location</th>
                        <th style="width:13%;">Expected Output</th>
                        <th style="width:11%;">Responsible / Support</th>
                        <th style="width:10%;">Remarks</th>
                        <?php if ($showAchievementColumn): ?>
                            <th style="width:14%;">Achievement</th>
                        <?php endif; ?>
                    </tr>
                </thead>

                <tbody>
                    <?php for ($day = 1; $day <= $daysInMonth; $day++): ?>
                        <?php
                        $dateValue = sprintf('%04d-%02d-%02d', $selectedYear, $selectedMonth, $day);
                        $dateDisplay = date('d-m-Y', strtotime($dateValue));
                        $dayDisplay = date('D', strtotime($dateValue));
                        $existing = $itemByDate[$dateValue] ?? [
                            'id' => 0,
                            'activity' => '',
                            'objective' => '',
                            'location' => '',
                            'expected_output' => '',
                            'responsible_support' => '',
                            'remarks' => '',
                            'achievement' => ''
                        ];
                        ?>
                        <tr>
                            <td style="text-align:center; font-weight:bold;">
                                <?= h($dateDisplay); ?>
                                <input type="hidden" name="work_date[]" value="<?= h($dateValue); ?>">
                            </td>
                            <td style="text-align:center;"><?= h($dayDisplay); ?></td>
                            <td><textarea name="activity[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['activity']); ?></textarea></td>
                            <td><textarea name="objective[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['objective']); ?></textarea></td>
                            <td><textarea name="location[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['location']); ?></textarea></td>
                            <td><textarea name="expected_output[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['expected_output']); ?></textarea></td>
                            <td><textarea name="responsible_support[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['responsible_support']); ?></textarea></td>
                            <td><textarea name="remarks[]" <?= !$isEditable ? 'readonly' : ''; ?>><?= h($existing['remarks']); ?></textarea></td>

                            <?php if ($showAchievementColumn): ?>
                                <td>
                                    <input type="hidden" name="item_id[]" value="<?= (int)$existing['id']; ?>">
                                    <textarea name="achievement[]"><?= h($existing['achievement']); ?></textarea>
                                </td>
                            <?php endif; ?>
                        </tr>
                    <?php endfor; ?>
                </tbody>
            </table>

            <?php if (!$isEditable && $currentPlan['user_id'] === $user_id && !$showAchievementColumn): ?>
                <div class="no-print">
                    <h4>Request Edit Permission</h4>
                    <textarea name="edit_request_reason" class="form-control" placeholder="Write why you need to edit this submitted work plan..." style="min-height:70px;"></textarea>
                    <br>
                    <button type="submit" name="send_edit_request" value="1" class="btn btn-warning">
                        Send Edit Request
                    </button>
                </div>
            <?php endif; ?>

            <?php if ($showAchievementColumn): ?>
                <div class="no-print" style="text-align:right; margin-top:15px;">
                    <button type="submit" name="save_achievements" value="1" class="btn btn-success">
                        Save Achievements
                    </button>
                </div>
            <?php endif; ?>

            <div class="signature-section">
                <div class="signature-box">
                    Prepared By<br>
                    Employee Signature
                </div>

                <div class="signature-box">
                    Reviewed By<br>
                    Supervisor / Manager
                </div>

                <div class="signature-box">
                    Approved By<br>
                    Authority
                </div>
            </div>
        </div>

        <?php if ($isEditable): ?>
            <div class="no-print" style="text-align:right; margin-bottom:25px;">
                <button type="submit" name="save_plan" value="1" class="btn btn-primary">
                    Save Draft
                </button>

                <button type="submit" name="submit_plan" value="1" class="btn btn-success" onclick="return confirm('Submit this work plan to assigned manager?');">
                    Submit to Manager
                </button>
            </div>
        <?php endif; ?>
    </form>

</div>

<?php include 'footer.php'; ?>

<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>

</body>
</html>
