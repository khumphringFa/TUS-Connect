<?php
/**
 * Idempotent seed data for local testing.
 * Run with:  php sql/seed.php
 *
 * Creates demo accounts (password: "password"), an approval chain, and a
 * sample SUBMITTED work plan so the admin panel has something to review.
 */

require_once(__DIR__ . '/../dbConnectionLocal.php');

$conn = db_connect();
if (!$conn) {
    fwrite(STDERR, "DB connection failed\n");
    exit(1);
}

function upsert_user($conn, $name, $email, $password, $designation, $project, $role) {
    $hash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ? LIMIT 1");
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $id);
    $found = mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    if ($found) {
        $u = mysqli_prepare($conn, "UPDATE users SET name=?, password=?, designation=?, project_name=?, role=? WHERE id=?");
        mysqli_stmt_bind_param($u, "sssssi", $name, $hash, $designation, $project, $role, $id);
        mysqli_stmt_execute($u);
        mysqli_stmt_close($u);
        return (int)$id;
    }

    $i = mysqli_prepare($conn, "INSERT INTO users (name, email, password, designation, project_name, role) VALUES (?,?,?,?,?,?)");
    mysqli_stmt_bind_param($i, "ssssss", $name, $email, $hash, $designation, $project, $role);
    mysqli_stmt_execute($i);
    $newId = mysqli_insert_id($conn);
    mysqli_stmt_close($i);
    return (int)$newId;
}

$adminId    = upsert_user($conn, 'System Admin',  'admin@tus.test',    'password', 'Administrator',      'HQ',              'Admin');
$managerId  = upsert_user($conn, 'Rahim Manager', 'manager@tus.test',  'password', 'Project Manager',    'Community Health', 'Manager');
$employeeId = upsert_user($conn, 'Karim Employee','employee@tus.test', 'password', 'Field Officer',      'Community Health', 'Employee');

// Approval chain: employee -> manager (active)
$chk = mysqli_prepare($conn, "SELECT id FROM approval_chains WHERE employee_id=? AND approver_id=? LIMIT 1");
mysqli_stmt_bind_param($chk, "ii", $employeeId, $managerId);
mysqli_stmt_execute($chk);
mysqli_stmt_store_result($chk);
$hasChain = mysqli_stmt_num_rows($chk) > 0;
mysqli_stmt_close($chk);

if (!$hasChain) {
    $ac = mysqli_prepare($conn, "INSERT INTO approval_chains (employee_id, approver_id, approval_level, status) VALUES (?,?,1,'Active')");
    mysqli_stmt_bind_param($ac, "ii", $employeeId, $managerId);
    mysqli_stmt_execute($ac);
    mysqli_stmt_close($ac);
}

// Sample submitted work plan for the current month so the admin panel is non-empty.
$month = (int)date('n');
$year  = (int)date('Y');

$pchk = mysqli_prepare($conn, "SELECT id FROM monthly_work_plans WHERE user_id=? AND plan_month=? AND plan_year=? LIMIT 1");
mysqli_stmt_bind_param($pchk, "iii", $employeeId, $month, $year);
mysqli_stmt_execute($pchk);
mysqli_stmt_bind_result($pchk, $existingPlanId);
$planExists = mysqli_stmt_fetch($pchk);
mysqli_stmt_close($pchk);

if (!$planExists) {
    $ip = mysqli_prepare($conn, "INSERT INTO monthly_work_plans (user_id, plan_month, plan_year, status, submitted_at) VALUES (?,?,?, 'Submitted', NOW())");
    mysqli_stmt_bind_param($ip, "iii", $employeeId, $month, $year);
    mysqli_stmt_execute($ip);
    $planId = mysqli_insert_id($conn);
    mysqli_stmt_close($ip);

    $rows = [
        [sprintf('%04d-%02d-02', $year, $month), 'Community health awareness session', 'Increase awareness on hygiene', 'Khagrachari Sadar', '40 households reached', 'Field Officer / Volunteer', 'Coordinate with local leaders'],
        [sprintf('%04d-%02d-05', $year, $month), 'Monthly nutrition survey', 'Collect nutrition data', 'Panchari Union', 'Survey of 25 families', 'Field Officer', 'Bring survey forms'],
        [sprintf('%04d-%02d-09', $year, $month), 'Caregiver training', 'Train mothers on child nutrition', 'Community Center', '20 caregivers trained', 'Field Officer / Nurse', ''],
    ];

    $ii = mysqli_prepare($conn, "INSERT INTO monthly_work_plan_items (plan_id, work_date, activity, objective, location, expected_output, responsible_support, remarks) VALUES (?,?,?,?,?,?,?,?)");
    foreach ($rows as $r) {
        mysqli_stmt_bind_param($ii, "isssssss", $planId, $r[0], $r[1], $r[2], $r[3], $r[4], $r[5], $r[6]);
        mysqli_stmt_execute($ii);
    }
    mysqli_stmt_close($ii);
}

echo "Seed complete.\n";
echo "  Admin    : admin@tus.test / password (id={$adminId})\n";
echo "  Manager  : manager@tus.test / password (id={$managerId})\n";
echo "  Employee : employee@tus.test / password (id={$employeeId})\n";
echo "  Sample submitted plan for {$month}/{$year}.\n";

mysqli_close($conn);
