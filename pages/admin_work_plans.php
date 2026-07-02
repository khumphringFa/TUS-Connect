<?php
/**
 * Admin / Reviewer panel for Monthly Work Plans.
 *
 * Lets an Admin (all employees) or a Manager / Approver (only their assigned
 * employees via approval_chains) browse submitted work plans, open a read-only
 * view of any plan, and approve / reject submitted plans and edit requests.
 *
 * This page is self-contained: it only needs an active session, the shared
 * dbConnectionLocal.php (db_connect) one directory up, and navbar.php/footer.php
 * next to it -- exactly like work_plan.php.
 */

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

function fetch_plan($conn, $planId) {
    $stmt = mysqli_prepare($conn, "
        SELECT
            mwp.id, mwp.user_id, mwp.plan_month, mwp.plan_year, mwp.status,
            mwp.edit_request_status, mwp.edit_request_reason, mwp.edit_request_at,
            mwp.submitted_at, mwp.reviewed_by_user_id, mwp.reviewed_at, mwp.reviewer_comments,
            mwp.created_at, mwp.updated_at,
            u.name, u.email, u.designation, u.project_name,
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
        $stmt, $id, $userId, $month, $year, $status,
        $editRequestStatus, $editRequestReason, $editRequestAt,
        $submittedAt, $reviewedBy, $reviewedAt, $reviewerComments,
        $createdAt, $updatedAt, $name, $email, $designation, $project, $reviewerName
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
        SELECT id, work_date, activity, objective, location,
               expected_output, responsible_support, remarks, achievement
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
        $stmt, $id, $workDate, $activity, $objective, $location,
        $expectedOutput, $responsible, $remarks, $achievement
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

function status_class($status) {
    switch ($status) {
        case 'Submitted': return 'status-submitted';
        case 'Approved':  return 'status-approved';
        case 'Rejected':  return 'status-rejected';
        default:          return 'status-draft';
    }
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

if (empty($_SESSION['user_email']) || empty($_SESSION['initiated']) || empty($_SESSION['user_id'])) {
    header("Location: /index.php?message=Please+login+first");
    exit();
}

require_once('../dbConnectionLocal.php');
$conn = db_connect();

if (!$conn) {
    die("Database connection failed.");
}

$viewerId = (int)$_SESSION['user_id'];
$viewerRole = '';

$stmt = mysqli_prepare($conn, "SELECT name, role FROM users WHERE id = ? LIMIT 1");
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "i", $viewerId);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $viewerName, $viewerRoleDb);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);
    $viewerRole = $viewerRoleDb ?: '';
    $_SESSION['role'] = $viewerRole;
}

if (!in_array($viewerRole, ['Admin', 'Manager', 'Approver'], true)) {
    http_response_code(403);
    die("Access denied. This panel is available to Admins, Managers and Approvers only.");
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = "";
$success = "";

/* ------------------------------------------------------------------ */
/* Review actions (approve / reject plan, approve / reject edit req)   */
/* ------------------------------------------------------------------ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    $planId = (int)($_POST['plan_id'] ?? 0);
    $comments = trim($_POST['reviewer_comments'] ?? '');

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $error = "Invalid request. Please refresh and try again.";
    } else {
        $plan = fetch_plan($conn, $planId);

        if (!$plan) {
            $error = "Work plan not found.";
        } elseif (!can_review_work_plan($conn, $viewerId, $viewerRole, $plan['user_id'])) {
            $error = "You are not allowed to review this work plan.";
        } elseif (isset($_POST['approve_plan']) || isset($_POST['reject_plan'])) {
            if ($plan['status'] !== 'Submitted') {
                $error = "Only submitted work plans can be approved or rejected.";
            } else {
                $newStatus = isset($_POST['approve_plan']) ? 'Approved' : 'Rejected';
                $upd = mysqli_prepare($conn, "
                    UPDATE monthly_work_plans
                    SET status = ?,
                        reviewed_by_user_id = ?,
                        reviewed_at = NOW(),
                        reviewer_comments = ?,
                        updated_at = NOW()
                    WHERE id = ?
                ");
                mysqli_stmt_bind_param($upd, "sisi", $newStatus, $viewerId, $comments, $planId);
                if (mysqli_stmt_execute($upd)) {
                    $success = "Work plan {$newStatus} successfully.";
                } else {
                    $error = "Could not update work plan.";
                }
                mysqli_stmt_close($upd);
            }
        } elseif (isset($_POST['approve_edit']) || isset($_POST['reject_edit'])) {
            if ($plan['edit_request_status'] !== 'Pending') {
                $error = "There is no pending edit request for this work plan.";
            } else {
                $newReqStatus = isset($_POST['approve_edit']) ? 'Approved' : 'Rejected';
                $upd = mysqli_prepare($conn, "
                    UPDATE monthly_work_plans
                    SET edit_request_status = ?,
                        edit_request_reviewed_by = ?,
                        edit_request_reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = ?
                ");
                mysqli_stmt_bind_param($upd, "sii", $newReqStatus, $viewerId, $planId);
                if (mysqli_stmt_execute($upd)) {
                    $success = "Edit request {$newReqStatus}.";
                } else {
                    $error = "Could not update edit request.";
                }
                mysqli_stmt_close($upd);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Detail view                                                         */
/* ------------------------------------------------------------------ */

$detailPlanId = isset($_GET['plan_id']) ? (int)$_GET['plan_id'] : 0;
$detailPlan = null;
$detailItems = [];

if ($detailPlanId > 0) {
    $detailPlan = fetch_plan($conn, $detailPlanId);

    if (!$detailPlan || !can_review_work_plan($conn, $viewerId, $viewerRole, $detailPlan['user_id'])) {
        $detailPlan = null;
        if ($error === "") {
            $error = "Work plan not found or you are not allowed to view it.";
        }
    } else {
        $detailItems = fetch_plan_items($conn, $detailPlanId);
    }
}

/* ------------------------------------------------------------------ */
/* List view filters + query                                          */
/* ------------------------------------------------------------------ */

$filterStatus = $_GET['status'] ?? '';
$filterMonth = isset($_GET['month']) ? (int)$_GET['month'] : 0;
$filterYear = isset($_GET['year']) ? (int)$_GET['year'] : 0;
$filterSearch = trim($_GET['q'] ?? '');

$validStatuses = ['Draft', 'Submitted', 'Approved', 'Rejected'];

$where = [];
$types = "";
$params = [];

if ($viewerRole !== 'Admin') {
    $where[] = "EXISTS (SELECT 1 FROM approval_chains ac WHERE ac.employee_id = mwp.user_id AND ac.approver_id = ?)";
    $types .= "i";
    $params[] = $viewerId;
}

if (in_array($filterStatus, $validStatuses, true)) {
    $where[] = "mwp.status = ?";
    $types .= "s";
    $params[] = $filterStatus;
}

if ($filterMonth >= 1 && $filterMonth <= 12) {
    $where[] = "mwp.plan_month = ?";
    $types .= "i";
    $params[] = $filterMonth;
}

if ($filterYear >= 2000 && $filterYear <= 2100) {
    $where[] = "mwp.plan_year = ?";
    $types .= "i";
    $params[] = $filterYear;
}

if ($filterSearch !== '') {
    $where[] = "(u.name LIKE ? OR u.email LIKE ?)";
    $types .= "ss";
    $like = "%{$filterSearch}%";
    $params[] = $like;
    $params[] = $like;
}

$whereSql = $where ? ("WHERE " . implode(" AND ", $where)) : "";

$listSql = "
    SELECT
        mwp.id, mwp.plan_month, mwp.plan_year, mwp.status,
        mwp.edit_request_status, mwp.submitted_at,
        u.name, u.email, u.designation, u.project_name
    FROM monthly_work_plans mwp
    JOIN users u ON u.id = mwp.user_id
    {$whereSql}
    ORDER BY (mwp.status = 'Submitted') DESC,
             (mwp.edit_request_status = 'Pending') DESC,
             mwp.plan_year DESC, mwp.plan_month DESC, mwp.submitted_at DESC, mwp.id DESC
    LIMIT 500
";

$plans = [];
$stmt = mysqli_prepare($conn, $listSql);
if ($stmt) {
    if ($types !== "") {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    while ($row = mysqli_fetch_assoc($res)) {
        $plans[] = $row;
    }
    mysqli_stmt_close($stmt);
}

/* Pending counts for the header badges */
$pendingReview = 0;
$pendingEdits = 0;
foreach ($plans as $p) {
    if ($p['status'] === 'Submitted') {
        $pendingReview++;
    }
    if ($p['edit_request_status'] === 'Pending') {
        $pendingEdits++;
    }
}

mysqli_close($conn);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin &middot; Work Plans</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <style>
        body { background:#f5f5f5; font-family:Arial, sans-serif; padding-top:70px; }
        .container-main { max-width:1300px; margin:25px auto; padding:0 15px; }
        .panel-card { background:#fff; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,.12); padding:25px; margin-bottom:25px; }
        .page-head { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; margin-bottom:18px; }
        .page-head h2 { margin:0; color:#007bff; }
        .count-pill { display:inline-block; background:#fff3cd; color:#856404; padding:5px 12px; border-radius:14px; font-size:13px; font-weight:bold; margin-left:6px; }
        .count-pill.edits { background:#e7f3ff; color:#0056b3; }
        .filter-bar { margin-bottom:18px; }
        .filter-bar .form-control { display:inline-block; width:auto; margin-right:6px; margin-bottom:6px; }
        table.list { width:100%; border-collapse:collapse; }
        table.list th { background:#007bff; color:#fff; padding:9px; font-size:12px; text-align:left; border:1px solid #0069d9; }
        table.list td { border:1px solid #e0e0e0; padding:9px; font-size:13px; vertical-align:middle; }
        table.list tr:nth-child(even) td { background:#fafafa; }
        .status-badge { display:inline-block; padding:4px 10px; border-radius:12px; font-weight:bold; font-size:11px; text-transform:uppercase; }
        .status-draft { background:#e2e3e5; color:#383d41; }
        .status-submitted { background:#fff3cd; color:#856404; }
        .status-approved { background:#d4edda; color:#155724; }
        .status-rejected { background:#f8d7da; color:#721c24; }
        .req-badge { display:inline-block; padding:3px 8px; border-radius:10px; font-size:11px; font-weight:bold; }
        .req-Pending { background:#ffe8b3; color:#7a5b00; }
        .req-Approved { background:#d4edda; color:#155724; }
        .req-Rejected { background:#f8d7da; color:#721c24; }
        .detail-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:18px 0; }
        .detail-item { background:#f8f9fa; border-left:4px solid #007bff; padding:10px; font-size:13px; }
        .detail-item strong { display:block; color:#666; font-size:11px; text-transform:uppercase; }
        table.plan { width:100%; border-collapse:collapse; margin-top:12px; }
        table.plan th { background:#007bff; color:#fff; padding:8px; font-size:12px; border:1px solid #0069d9; text-align:center; }
        table.plan td { border:1px solid #ccc; padding:8px; font-size:13px; vertical-align:top; }
        .empty { text-align:center; color:#888; padding:40px 0; }
        .review-box { background:#f8f9fa; border:1px solid #e0e0e0; border-radius:6px; padding:18px; margin-top:18px; }
    </style>
</head>
<body>

<?php include 'navbar.php'; ?>

<div class="container-main">

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><strong>Error:</strong> <?= h($error); ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="alert alert-success"><strong>Success:</strong> <?= h($success); ?></div>
    <?php endif; ?>

<?php if ($detailPlan): ?>

    <?php
        $items = $detailItems;
        $itemByDate = [];
        foreach ($items as $it) {
            $itemByDate[$it['work_date']] = $it;
        }
        $daysInMonth = (int)date('t', strtotime(sprintf('%04d-%02d-01', $detailPlan['year'], $detailPlan['month'])));
        $monthName = date('F', mktime(0, 0, 0, $detailPlan['month'], 1));
        $showAchievement = ($detailPlan['status'] === 'Approved');
        $canReviewPlan = ($detailPlan['status'] === 'Submitted');
        $canReviewEdit = ($detailPlan['edit_request_status'] === 'Pending');
    ?>

    <div class="panel-card">
        <div class="page-head">
            <h2>Work Plan Review</h2>
            <a href="/pages/admin_work_plans.php" class="btn btn-default">&larr; Back to list</a>
        </div>

        <div class="detail-grid">
            <div class="detail-item"><strong>Employee</strong><?= h($detailPlan['name']); ?></div>
            <div class="detail-item"><strong>Email</strong><?= h($detailPlan['email']); ?></div>
            <div class="detail-item"><strong>Designation</strong><?= h($detailPlan['designation'] ?: '-'); ?></div>
            <div class="detail-item"><strong>Project</strong><?= h($detailPlan['project_name'] ?: '-'); ?></div>
            <div class="detail-item"><strong>Period</strong><?= h($monthName . ' ' . $detailPlan['year']); ?></div>
            <div class="detail-item"><strong>Status</strong>
                <span class="status-badge <?= h(status_class($detailPlan['status'])); ?>"><?= h($detailPlan['status']); ?></span>
            </div>
            <div class="detail-item"><strong>Submitted At</strong><?= h($detailPlan['submitted_at'] ?: '-'); ?></div>
            <div class="detail-item"><strong>Reviewed By</strong><?= h($detailPlan['reviewer_name'] ?: '-'); ?></div>
            <div class="detail-item"><strong>Reviewed At</strong><?= h($detailPlan['reviewed_at'] ?: '-'); ?></div>
        </div>

        <?php if (!empty($detailPlan['reviewer_comments'])): ?>
            <div class="alert alert-info"><strong>Reviewer comments:</strong> <?= h($detailPlan['reviewer_comments']); ?></div>
        <?php endif; ?>

        <?php if (!empty($detailPlan['edit_request_status'])): ?>
            <div class="alert alert-warning">
                <strong>Edit request:</strong>
                <span class="req-badge req-<?= h($detailPlan['edit_request_status']); ?>"><?= h($detailPlan['edit_request_status']); ?></span>
                <?php if (!empty($detailPlan['edit_request_reason'])): ?>
                    <div style="margin-top:6px;">Reason: <?= h($detailPlan['edit_request_reason']); ?></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <table class="plan">
            <thead>
                <tr>
                    <th style="width:9%;">Date</th>
                    <th style="width:6%;">Day</th>
                    <th style="width:15%;">Major Activity</th>
                    <th style="width:14%;">Objective / Purpose</th>
                    <th style="width:10%;">Location</th>
                    <th style="width:14%;">Expected Output</th>
                    <th style="width:11%;">Responsible / Support</th>
                    <th style="width:10%;">Remarks</th>
                    <?php if ($showAchievement): ?><th style="width:14%;">Achievement</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
                <?php for ($day = 1; $day <= $daysInMonth; $day++): ?>
                    <?php
                        $dateValue = sprintf('%04d-%02d-%02d', $detailPlan['year'], $detailPlan['month'], $day);
                        $row = $itemByDate[$dateValue] ?? null;
                        if (!$row) { continue; }
                        $dateDisplay = date('d-m-Y', strtotime($dateValue));
                        $dayDisplay = date('D', strtotime($dateValue));
                    ?>
                    <tr>
                        <td style="text-align:center; font-weight:bold;"><?= h($dateDisplay); ?></td>
                        <td style="text-align:center;"><?= h($dayDisplay); ?></td>
                        <td><?= nl2br(h($row['activity'])); ?></td>
                        <td><?= nl2br(h($row['objective'])); ?></td>
                        <td><?= nl2br(h($row['location'])); ?></td>
                        <td><?= nl2br(h($row['expected_output'])); ?></td>
                        <td><?= nl2br(h($row['responsible_support'])); ?></td>
                        <td><?= nl2br(h($row['remarks'])); ?></td>
                        <?php if ($showAchievement): ?><td><?= nl2br(h($row['achievement'])); ?></td><?php endif; ?>
                    </tr>
                <?php endfor; ?>
                <?php if (empty($items)): ?>
                    <tr><td colspan="<?= $showAchievement ? 9 : 8; ?>" class="empty">No activity rows were filled in for this plan.</td></tr>
                <?php endif; ?>
            </tbody>
        </table>

        <?php if ($canReviewPlan || $canReviewEdit): ?>
            <div class="review-box">
                <form method="post" action="/pages/admin_work_plans.php">
                    <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="plan_id" value="<?= (int)$detailPlan['id']; ?>">

                    <?php if ($canReviewPlan): ?>
                        <h4>Review Submitted Plan</h4>
                        <div class="form-group">
                            <label>Reviewer comments (optional)</label>
                            <textarea name="reviewer_comments" class="form-control" rows="2" placeholder="Add a note for the employee..."></textarea>
                        </div>
                        <button type="submit" name="approve_plan" value="1" class="btn btn-success"
                                onclick="return confirm('Approve this work plan?');">Approve Plan</button>
                        <button type="submit" name="reject_plan" value="1" class="btn btn-danger"
                                onclick="return confirm('Reject this work plan?');">Reject Plan</button>
                    <?php endif; ?>

                    <?php if ($canReviewEdit): ?>
                        <hr>
                        <h4>Pending Edit Request</h4>
                        <button type="submit" name="approve_edit" value="1" class="btn btn-primary"
                                onclick="return confirm('Approve edit request? The employee will be able to edit this plan.');">Approve Edit Request</button>
                        <button type="submit" name="reject_edit" value="1" class="btn btn-warning"
                                onclick="return confirm('Reject edit request?');">Reject Edit Request</button>
                    <?php endif; ?>
                </form>
            </div>
        <?php endif; ?>
    </div>

<?php else: ?>

    <div class="panel-card">
        <div class="page-head">
            <h2>Monthly Work Plans
                <?php if ($pendingReview > 0): ?><span class="count-pill"><?= (int)$pendingReview; ?> awaiting review</span><?php endif; ?>
                <?php if ($pendingEdits > 0): ?><span class="count-pill edits"><?= (int)$pendingEdits; ?> edit request(s)</span><?php endif; ?>
            </h2>
            <span class="text-muted"><?= h($viewerRole); ?> view</span>
        </div>

        <form method="get" action="/pages/admin_work_plans.php" class="filter-bar form-inline">
            <input type="text" name="q" class="form-control" placeholder="Search name or email" value="<?= h($filterSearch); ?>">

            <select name="status" class="form-control">
                <option value="">All statuses</option>
                <?php foreach ($validStatuses as $st): ?>
                    <option value="<?= h($st); ?>" <?= $filterStatus === $st ? 'selected' : ''; ?>><?= h($st); ?></option>
                <?php endforeach; ?>
            </select>

            <select name="month" class="form-control">
                <option value="0">All months</option>
                <?php for ($m = 1; $m <= 12; $m++): ?>
                    <option value="<?= $m; ?>" <?= $filterMonth === $m ? 'selected' : ''; ?>><?= date('F', mktime(0,0,0,$m,1)); ?></option>
                <?php endfor; ?>
            </select>

            <input type="number" name="year" class="form-control" style="width:90px;" placeholder="Year"
                   value="<?= $filterYear ? (int)$filterYear : ''; ?>" min="2000" max="2100">

            <button type="submit" class="btn btn-primary">Filter</button>
            <a href="/pages/admin_work_plans.php" class="btn btn-default">Reset</a>
        </form>

        <table class="list">
            <thead>
                <tr>
                    <th>Employee</th>
                    <th>Designation</th>
                    <th>Project</th>
                    <th>Period</th>
                    <th>Status</th>
                    <th>Edit Req.</th>
                    <th>Submitted</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($plans)): ?>
                    <tr><td colspan="8" class="empty">No work plans match the current filters.</td></tr>
                <?php else: ?>
                    <?php foreach ($plans as $p): ?>
                        <?php $period = date('F', mktime(0,0,0,(int)$p['plan_month'],1)) . ' ' . (int)$p['plan_year']; ?>
                        <tr>
                            <td>
                                <strong><?= h($p['name']); ?></strong><br>
                                <span class="text-muted" style="font-size:12px;"><?= h($p['email']); ?></span>
                            </td>
                            <td><?= h($p['designation'] ?: '-'); ?></td>
                            <td><?= h($p['project_name'] ?: '-'); ?></td>
                            <td><?= h($period); ?></td>
                            <td><span class="status-badge <?= h(status_class($p['status'])); ?>"><?= h($p['status']); ?></span></td>
                            <td>
                                <?php if (!empty($p['edit_request_status'])): ?>
                                    <span class="req-badge req-<?= h($p['edit_request_status']); ?>"><?= h($p['edit_request_status']); ?></span>
                                <?php else: ?>
                                    <span class="text-muted">-</span>
                                <?php endif; ?>
                            </td>
                            <td><?= h($p['submitted_at'] ?: '-'); ?></td>
                            <td>
                                <a class="btn btn-sm btn-primary" href="/pages/admin_work_plans.php?plan_id=<?= (int)$p['id']; ?>">View</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

<?php endif; ?>

</div>

<?php include 'footer.php'; ?>

<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>

</body>
</html>
