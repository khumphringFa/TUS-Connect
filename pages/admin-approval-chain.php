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

function table_exists($conn, $table) {
    $table = mysqli_real_escape_string($conn, $table);
    $result = mysqli_query($conn, "SHOW TABLES LIKE '$table'");
    return $result && mysqli_num_rows($result) > 0;
}

function column_exists($conn, $table, $column) {
    $table = mysqli_real_escape_string($conn, $table);
    $column = mysqli_real_escape_string($conn, $column);
    $result = mysqli_query($conn, "SHOW COLUMNS FROM `$table` LIKE '$column'");
    return $result && mysqli_num_rows($result) > 0;
}

function ensure_column($conn, $table, $column, $definition) {
    if (!column_exists($conn, $table, $column)) {
        mysqli_query($conn, "ALTER TABLE `$table` ADD COLUMN `$column` $definition");
    }
}

function count_query($conn, $sql) {
    $res = mysqli_query($conn, $sql);
    if ($res) {
        $row = mysqli_fetch_row($res);
        return (int)$row[0];
    }
    return 0;
}

function log_action($conn, $userId, $action, $message) {
    mysqli_query($conn, "
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            action VARCHAR(50) NOT NULL,
            module VARCHAR(50) NOT NULL,
            record_id INT NULL,
            old_value TEXT NULL,
            new_value TEXT NULL,
            ip_address VARCHAR(45) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    $stmt = mysqli_prepare($conn, "
        INSERT INTO audit_logs (user_id, action, module, new_value, ip_address)
        VALUES (?, ?, 'approval_chain', ?, ?)
    ");

    if ($stmt) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        mysqli_stmt_bind_param($stmt, "isss", $userId, $action, $message, $ip);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    }
}

function ensure_approval_schema($conn) {
    mysqli_query($conn, "
        CREATE TABLE IF NOT EXISTS approval_chains (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id INT NOT NULL,
            approver_id INT NOT NULL,
            approval_level INT NOT NULL DEFAULT 1,
            leave_type VARCHAR(255) NULL,
            criteria TEXT NULL,
            module_type VARCHAR(50) NOT NULL DEFAULT 'leave',
            min_days INT DEFAULT 0,
            max_days INT DEFAULT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'Active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NULL DEFAULT NULL,
            created_by INT NULL,
            INDEX employee_id_idx (employee_id),
            INDEX approver_id_idx (approver_id),
            INDEX approval_level_idx (approval_level),
            INDEX module_type_idx (module_type),
            INDEX status_idx (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    ensure_column($conn, 'approval_chains', 'criteria', "TEXT NULL AFTER leave_type");
    ensure_column($conn, 'approval_chains', 'module_type', "VARCHAR(50) NOT NULL DEFAULT 'leave' AFTER criteria");
    ensure_column($conn, 'approval_chains', 'min_days', "INT DEFAULT 0 AFTER module_type");
    ensure_column($conn, 'approval_chains', 'max_days', "INT DEFAULT NULL AFTER min_days");
    ensure_column($conn, 'approval_chains', 'created_by', "INT NULL");
    ensure_column($conn, 'approval_chains', 'updated_at', "TIMESTAMP NULL DEFAULT NULL");

    mysqli_query($conn, "
        CREATE TABLE IF NOT EXISTS project_approval_chains (
            id INT AUTO_INCREMENT PRIMARY KEY,
            project_name VARCHAR(255) NOT NULL,
            approver_id INT NOT NULL,
            approval_level INT NOT NULL,
            module_type VARCHAR(50) NOT NULL DEFAULT 'leave',
            min_days INT DEFAULT 0,
            max_days INT DEFAULT NULL,
            criteria_note TEXT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'Active',
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NULL DEFAULT NULL,
            INDEX project_name_idx (project_name),
            INDEX approver_id_idx (approver_id),
            INDEX approval_level_idx (approval_level),
            INDEX module_type_idx (module_type),
            INDEX status_idx (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    ensure_column($conn, 'project_approval_chains', 'criteria_note', "TEXT NULL AFTER max_days");
    ensure_column($conn, 'project_approval_chains', 'created_by', "INT NULL");
    ensure_column($conn, 'project_approval_chains', 'updated_at', "TIMESTAMP NULL DEFAULT NULL");
}

function insert_project_rule($conn, $projectName, $approverId, $level, $moduleType, $minDays, $maxDays, $criteria, $createdBy) {
    if ($approverId <= 0) {
        return false;
    }

    $close = mysqli_prepare($conn, "
        UPDATE project_approval_chains
        SET status = 'Inactive', updated_at = NOW()
        WHERE project_name = ?
          AND approval_level = ?
          AND module_type = ?
          AND status = 'Active'
    ");
    if ($close) {
        mysqli_stmt_bind_param($close, "sis", $projectName, $level, $moduleType);
        mysqli_stmt_execute($close);
        mysqli_stmt_close($close);
    }

    $stmt = mysqli_prepare($conn, "
        INSERT INTO project_approval_chains
            (project_name, approver_id, approval_level, module_type, min_days, max_days, criteria_note, status, created_by)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, 'Active', ?)
    ");

    if (!$stmt) {
        throw new Exception("Could not prepare project {$moduleType} Level {$level} rule.");
    }

    mysqli_stmt_bind_param($stmt, "siisiisi", $projectName, $approverId, $level, $moduleType, $minDays, $maxDays, $criteria, $createdBy);
    $ok = mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    if (!$ok) {
        throw new Exception("Could not save project {$moduleType} Level {$level} rule.");
    }

    return true;
}

function insert_staff_rule($conn, $employeeId, $approverId, $level, $moduleType, $minDays, $maxDays, $criteria, $createdBy) {
    if ($approverId <= 0) {
        return false;
    }

    if ($employeeId === $approverId) {
        throw new Exception("Staff and approver cannot be the same at Level {$level}.");
    }

    $close = mysqli_prepare($conn, "
        UPDATE approval_chains
        SET status = 'Inactive', updated_at = NOW()
        WHERE employee_id = ?
          AND approval_level = ?
          AND module_type = ?
          AND status = 'Active'
    ");
    if ($close) {
        mysqli_stmt_bind_param($close, "iis", $employeeId, $level, $moduleType);
        mysqli_stmt_execute($close);
        mysqli_stmt_close($close);
    }

    $leaveType = ucfirst($moduleType);

    $stmt = mysqli_prepare($conn, "
        INSERT INTO approval_chains
            (employee_id, approver_id, approval_level, leave_type, criteria, module_type, min_days, max_days, status, created_by)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?)
    ");

    if (!$stmt) {
        throw new Exception("Could not prepare staff {$moduleType} Level {$level} rule.");
    }

    mysqli_stmt_bind_param($stmt, "iiisssiii", $employeeId, $approverId, $level, $leaveType, $criteria, $moduleType, $minDays, $maxDays, $createdBy);
    $ok = mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    if (!$ok) {
        throw new Exception("Could not save staff {$moduleType} Level {$level} rule.");
    }

    return true;
}

if (empty($_SESSION['user_email']) || empty($_SESSION['initiated']) || empty($_SESSION['user_id'])) {
    header("Location: ../index.php?message=Please+login+first");
    exit();
}

require_once('../dbConnectionLocal.php');
$conn = db_connect();

if (!$conn) {
    die("Database connection failed.");
}

mysqli_query($conn, "SET time_zone = '+06:00'");
ensure_approval_schema($conn);

$user_id = (int)$_SESSION['user_id'];
$user_name = h($_SESSION['name'] ?? 'User');

$role_stmt = mysqli_prepare($conn, "SELECT role FROM users WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($role_stmt, "i", $user_id);
mysqli_stmt_execute($role_stmt);
mysqli_stmt_bind_result($role_stmt, $user_role);
mysqli_stmt_fetch($role_stmt);
mysqli_stmt_close($role_stmt);

$_SESSION['role'] = $user_role;

$roleLower = strtolower(trim((string)$user_role));
if (!in_array($roleLower, ['admin', 'super admin', 'super_admin'], true)) {
    header("Location: home.php?error=Access+denied");
    exit();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = '';

$levelTitles = [
    1 => 'Level 1 - Manager / Reviewer',
    2 => 'Level 2 - Senior Reviewer / Project Lead',
    3 => 'Level 3 - Final ED / Director Approval'
];

$ruleNotes = [
    1 => 'Workplan approval and Leave approval up to 3 days.',
    2 => 'Workplan approval and Leave approval up to 3 days.',
    3 => 'Leave approval for 4 days or more and all Tour approvals.'
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $error = "Invalid request. Please refresh the page and try again.";
    } elseif (isset($_POST['save_project_approval_stage'])) {
        $project_name = trim($_POST['project_name'] ?? '');
        $criteria = trim($_POST['criteria_note'] ?? '');
        $levels = $_POST['project_levels'] ?? [];

        if ($project_name === '') {
            $error = "Please select a project.";
        } else {
            mysqli_begin_transaction($conn);

            try {
                $saved = 0;

                $level1 = (int)($levels[1] ?? 0);
                $level2 = (int)($levels[2] ?? 0);
                $level3 = (int)($levels[3] ?? 0);

                if ($level1 <= 0 && $level2 <= 0 && $level3 <= 0) {
                    throw new Exception("Please select at least one approval level.");
                }

                if ($level1 > 0) {
                    if (insert_project_rule($conn, $project_name, $level1, 1, 'leave', 0, 3, $criteria ?: 'Level 1: Leave up to 3 days', $user_id)) $saved++;
                    if (insert_project_rule($conn, $project_name, $level1, 1, 'workplan', 0, null, $criteria ?: 'Level 1: Workplan approval', $user_id)) $saved++;
                }

                if ($level2 > 0) {
                    if (insert_project_rule($conn, $project_name, $level2, 2, 'leave', 0, 3, $criteria ?: 'Level 2: Leave up to 3 days', $user_id)) $saved++;
                    if (insert_project_rule($conn, $project_name, $level2, 2, 'workplan', 0, null, $criteria ?: 'Level 2: Workplan approval', $user_id)) $saved++;
                }

                if ($level3 > 0) {
                    if (insert_project_rule($conn, $project_name, $level3, 3, 'leave', 4, null, $criteria ?: 'Level 3: Leave 4 days or more', $user_id)) $saved++;
                    if (insert_project_rule($conn, $project_name, $level3, 3, 'tour', 0, null, $criteria ?: 'Level 3: Tour approval', $user_id)) $saved++;
                }

                mysqli_commit($conn);
                $success = "Project-wise approval chain saved successfully. Active rules saved: {$saved}.";
                log_action($conn, $user_id, 'SAVE_PROJECT_APPROVAL_CHAIN', "Saved {$saved} project-wise approval rules for project {$project_name}");
            } catch (Throwable $e) {
                mysqli_rollback($conn);
                $error = $e->getMessage();
            }
        }
    } elseif (isset($_POST['save_staff_approval_stage'])) {
        $employee_id = (int)($_POST['employee_id'] ?? 0);
        $criteria = trim($_POST['staff_criteria'] ?? '');
        $levels = $_POST['levels'] ?? [];

        if ($employee_id <= 0) {
            $error = "Please select a staff member.";
        } else {
            mysqli_begin_transaction($conn);

            try {
                $saved = 0;

                $level1 = (int)($levels[1] ?? 0);
                $level2 = (int)($levels[2] ?? 0);
                $level3 = (int)($levels[3] ?? 0);

                if ($level1 <= 0 && $level2 <= 0 && $level3 <= 0) {
                    throw new Exception("Please select at least one approval level for staff exception.");
                }

                if ($level1 > 0) {
                    if (insert_staff_rule($conn, $employee_id, $level1, 1, 'leave', 0, 3, $criteria ?: 'Staff exception Level 1: Leave up to 3 days', $user_id)) $saved++;
                    if (insert_staff_rule($conn, $employee_id, $level1, 1, 'workplan', 0, null, $criteria ?: 'Staff exception Level 1: Workplan approval', $user_id)) $saved++;
                }

                if ($level2 > 0) {
                    if (insert_staff_rule($conn, $employee_id, $level2, 2, 'leave', 0, 3, $criteria ?: 'Staff exception Level 2: Leave up to 3 days', $user_id)) $saved++;
                    if (insert_staff_rule($conn, $employee_id, $level2, 2, 'workplan', 0, null, $criteria ?: 'Staff exception Level 2: Workplan approval', $user_id)) $saved++;
                }

                if ($level3 > 0) {
                    if (insert_staff_rule($conn, $employee_id, $level3, 3, 'leave', 4, null, $criteria ?: 'Staff exception Level 3: Leave 4 days or more', $user_id)) $saved++;
                    if (insert_staff_rule($conn, $employee_id, $level3, 3, 'tour', 0, null, $criteria ?: 'Staff exception Level 3: Tour approval', $user_id)) $saved++;
                }

                mysqli_commit($conn);
                $success = "Staff-wise special approval chain saved successfully. Active rules saved: {$saved}.";
                log_action($conn, $user_id, 'SAVE_STAFF_APPROVAL_EXCEPTION', "Saved {$saved} staff exception approval rules for employee ID {$employee_id}");
            } catch (Throwable $e) {
                mysqli_rollback($conn);
                $error = $e->getMessage();
            }
        }
    } elseif (isset($_POST['deactivate_project_chain'])) {
        $chain_id = (int)($_POST['chain_id'] ?? 0);

        if ($chain_id > 0) {
            $stmt = mysqli_prepare($conn, "UPDATE project_approval_chains SET status = 'Inactive', updated_at = NOW() WHERE id = ?");
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "i", $chain_id);
                if (mysqli_stmt_execute($stmt)) {
                    $success = "Project approval rule deactivated successfully.";
                    log_action($conn, $user_id, 'DEACTIVATE_PROJECT_CHAIN', "Deactivated project approval chain ID {$chain_id}");
                } else {
                    $error = "Could not deactivate project approval rule.";
                }
                mysqli_stmt_close($stmt);
            }
        } else {
            $error = "Invalid project chain ID.";
        }
    } elseif (isset($_POST['deactivate_staff_chain'])) {
        $chain_id = (int)($_POST['chain_id'] ?? 0);

        if ($chain_id > 0) {
            $stmt = mysqli_prepare($conn, "UPDATE approval_chains SET status = 'Inactive', updated_at = NOW() WHERE id = ?");
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "i", $chain_id);
                if (mysqli_stmt_execute($stmt)) {
                    $success = "Staff exception rule deactivated successfully.";
                    log_action($conn, $user_id, 'DEACTIVATE_STAFF_CHAIN', "Deactivated staff approval chain ID {$chain_id}");
                } else {
                    $error = "Could not deactivate staff exception rule.";
                }
                mysqli_stmt_close($stmt);
            }
        } else {
            $error = "Invalid staff chain ID.";
        }
    }
}

$selectedProject = trim($_GET['project'] ?? '');
$selectedEmployee = (int)($_GET['employee_id'] ?? ($_POST['employee_id'] ?? 0));
$selectedStatus = trim($_GET['chain_status'] ?? 'Active');

if (!in_array($selectedStatus, ['Active', 'Inactive', 'All'], true)) {
    $selectedStatus = 'Active';
}

$projectOptions = [];
$projectResult = mysqli_query($conn, "
    SELECT DISTINCT project_name
    FROM users
    WHERE project_name IS NOT NULL AND TRIM(project_name) != ''
    ORDER BY project_name ASC
");
if ($projectResult) {
    while ($row = mysqli_fetch_assoc($projectResult)) {
        $projectOptions[] = $row['project_name'];
    }
    mysqli_free_result($projectResult);
}

$employees = [];
$empSql = "
    SELECT id, name, email, designation, project_name, role
    FROM users
    WHERE COALESCE(is_active,1) = 1
";
$empTypes = '';
$empParams = [];
if ($selectedProject !== '') {
    $empSql .= " AND project_name = ?";
    $empTypes .= 's';
    $empParams[] = $selectedProject;
}
$empSql .= " ORDER BY name ASC";
$emp_stmt = mysqli_prepare($conn, $empSql);
if ($emp_stmt) {
    if ($empTypes !== '') {
        mysqli_stmt_bind_param($emp_stmt, $empTypes, ...$empParams);
    }
    mysqli_stmt_execute($emp_stmt);
    mysqli_stmt_store_result($emp_stmt);
    mysqli_stmt_bind_result($emp_stmt, $eid, $ename, $eemail, $edesig, $eproject, $erole);

    while (mysqli_stmt_fetch($emp_stmt)) {
        $employees[] = [
            'id' => (int)$eid,
            'name' => h($ename),
            'email' => h($eemail),
            'designation' => h($edesig),
            'project' => h($eproject),
            'role' => h($erole)
        ];
    }
    mysqli_stmt_close($emp_stmt);
}

$approvers = [];
$app_stmt = mysqli_prepare($conn, "
    SELECT id, name, email, designation, project_name, role
    FROM users
    WHERE COALESCE(is_active,1) = 1
      AND role IN ('Director', 'Manager', 'Approver', 'Admin', 'Super Admin', 'super_admin', 'super admin')
    ORDER BY FIELD(role, 'Manager', 'Approver', 'Director', 'Admin', 'Super Admin', 'super_admin', 'super admin'), name ASC
");
if ($app_stmt) {
    mysqli_stmt_execute($app_stmt);
    mysqli_stmt_store_result($app_stmt);
    mysqli_stmt_bind_result($app_stmt, $aid, $aname, $aemail, $adesig, $aproject, $arole);

    while (mysqli_stmt_fetch($app_stmt)) {
        $approvers[] = [
            'id' => (int)$aid,
            'name' => h($aname),
            'email' => h($aemail),
            'designation' => h($adesig),
            'project' => h($aproject),
            'role' => h($arole)
        ];
    }
    mysqli_stmt_close($app_stmt);
}

$projectStages = [
    1 => ['approver_id' => 0],
    2 => ['approver_id' => 0],
    3 => ['approver_id' => 0]
];

if ($selectedProject !== '') {
    $stageStmt = mysqli_prepare($conn, "
        SELECT approval_level, approver_id
        FROM project_approval_chains
        WHERE project_name = ?
          AND status = 'Active'
        GROUP BY approval_level, approver_id
        ORDER BY approval_level ASC
    ");
    if ($stageStmt) {
        mysqli_stmt_bind_param($stageStmt, "s", $selectedProject);
        mysqli_stmt_execute($stageStmt);
        mysqli_stmt_store_result($stageStmt);
        mysqli_stmt_bind_result($stageStmt, $pLevel, $pApprover);
        while (mysqli_stmt_fetch($stageStmt)) {
            $projectStages[(int)$pLevel] = ['approver_id' => (int)$pApprover];
        }
        mysqli_stmt_close($stageStmt);
    }
}

$selectedStaff = null;
$currentStages = [1 => null, 2 => null, 3 => null];

if ($selectedEmployee > 0) {
    $staffStmt = mysqli_prepare($conn, "
        SELECT id, name, email, designation, project_name, role
        FROM users
        WHERE id = ?
        LIMIT 1
    ");
    if ($staffStmt) {
        mysqli_stmt_bind_param($staffStmt, "i", $selectedEmployee);
        mysqli_stmt_execute($staffStmt);
        mysqli_stmt_store_result($staffStmt);
        mysqli_stmt_bind_result($staffStmt, $sid, $sname, $semail, $sdesignation, $sproject, $srole);
        if (mysqli_stmt_fetch($staffStmt)) {
            $selectedStaff = [
                'id' => (int)$sid,
                'name' => h($sname),
                'email' => h($semail),
                'designation' => h($sdesignation),
                'project' => h($sproject),
                'role' => h($srole)
            ];
        }
        mysqli_stmt_close($staffStmt);
    }

    $stageStmt = mysqli_prepare($conn, "
        SELECT approval_level, approver_id
        FROM approval_chains
        WHERE employee_id = ?
          AND status = 'Active'
        GROUP BY approval_level, approver_id
        ORDER BY approval_level ASC
    ");
    if ($stageStmt) {
        mysqli_stmt_bind_param($stageStmt, "i", $selectedEmployee);
        mysqli_stmt_execute($stageStmt);
        mysqli_stmt_store_result($stageStmt);
        mysqli_stmt_bind_result($stageStmt, $sLevel, $sApprover);
        while (mysqli_stmt_fetch($stageStmt)) {
            $currentStages[(int)$sLevel] = ['approver_id' => (int)$sApprover];
        }
        mysqli_stmt_close($stageStmt);
    }
}

$projectChains = [];
$where = [];
$types = '';
$params = [];

if ($selectedStatus !== 'All') {
    $where[] = "pac.status = ?";
    $types .= 's';
    $params[] = $selectedStatus;
}
if ($selectedProject !== '') {
    $where[] = "pac.project_name = ?";
    $types .= 's';
    $params[] = $selectedProject;
}

$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$stmt = mysqli_prepare($conn, "
    SELECT
        pac.id,
        pac.project_name,
        pac.approver_id,
        pac.approval_level,
        pac.module_type,
        pac.min_days,
        pac.max_days,
        pac.criteria_note,
        pac.status,
        pac.created_at,
        a.name,
        a.role,
        a.email,
        a.designation,
        a.project_name
    FROM project_approval_chains pac
    JOIN users a ON a.id = pac.approver_id
    {$whereSql}
    ORDER BY pac.project_name ASC, pac.approval_level ASC, FIELD(pac.module_type, 'workplan', 'leave', 'tour'), pac.min_days ASC
");
if ($stmt) {
    if ($types !== '') {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    mysqli_stmt_bind_result($stmt, $pcid, $pcProject, $pcApprover, $pcLevel, $pcModule, $pcMin, $pcMax, $pcCriteria, $pcStatus, $pcCreated, $pcName, $pcRole, $pcEmail, $pcDesig, $pcApproverProject);
    while (mysqli_stmt_fetch($stmt)) {
        $projectChains[] = [
            'id' => (int)$pcid,
            'project_name' => h($pcProject),
            'approver_id' => (int)$pcApprover,
            'level' => (int)$pcLevel,
            'module_type' => h(ucfirst($pcModule)),
            'raw_module_type' => $pcModule,
            'min_days' => is_null($pcMin) ? null : (int)$pcMin,
            'max_days' => is_null($pcMax) ? null : (int)$pcMax,
            'criteria' => h($pcCriteria),
            'status' => h($pcStatus),
            'created_at' => !empty($pcCreated) ? date('d-m-Y h:i A', strtotime($pcCreated)) : '',
            'approver_name' => h($pcName),
            'approver_role' => h($pcRole),
            'approver_email' => h($pcEmail),
            'approver_designation' => h($pcDesig),
            'approver_project' => h($pcApproverProject)
        ];
    }
    mysqli_stmt_close($stmt);
}

$staffChains = [];
$swhere = [];
$stypes = '';
$sparams = [];

if ($selectedStatus !== 'All') {
    $swhere[] = "ac.status = ?";
    $stypes .= 's';
    $sparams[] = $selectedStatus;
}
if ($selectedProject !== '') {
    $swhere[] = "e.project_name = ?";
    $stypes .= 's';
    $sparams[] = $selectedProject;
}
if ($selectedEmployee > 0) {
    $swhere[] = "ac.employee_id = ?";
    $stypes .= 'i';
    $sparams[] = $selectedEmployee;
}

$swhereSql = $swhere ? 'WHERE ' . implode(' AND ', $swhere) : '';

$stmt = mysqli_prepare($conn, "
    SELECT
        ac.id,
        ac.employee_id,
        ac.approver_id,
        ac.approval_level,
        ac.module_type,
        ac.min_days,
        ac.max_days,
        ac.criteria,
        ac.status,
        ac.created_at,
        e.name,
        e.email,
        e.designation,
        e.project_name,
        a.name,
        a.role,
        a.email,
        a.designation,
        a.project_name
    FROM approval_chains ac
    JOIN users e ON e.id = ac.employee_id
    JOIN users a ON a.id = ac.approver_id
    {$swhereSql}
    ORDER BY e.name ASC, ac.approval_level ASC, FIELD(ac.module_type, 'workplan', 'leave', 'tour'), ac.min_days ASC
");
if ($stmt) {
    if ($stypes !== '') {
        mysqli_stmt_bind_param($stmt, $stypes, ...$sparams);
    }
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    mysqli_stmt_bind_result($stmt, $scid, $scEmployeeId, $scApproverId, $scLevel, $scModule, $scMin, $scMax, $scCriteria, $scStatus, $scCreated, $scEmployeeName, $scEmployeeEmail, $scEmployeeDesignation, $scEmployeeProject, $scApproverName, $scApproverRole, $scApproverEmail, $scApproverDesignation, $scApproverProject);
    while (mysqli_stmt_fetch($stmt)) {
        $staffChains[] = [
            'id' => (int)$scid,
            'employee_id' => (int)$scEmployeeId,
            'approver_id' => (int)$scApproverId,
            'level' => (int)$scLevel,
            'module_type' => h(ucfirst($scModule)),
            'raw_module_type' => $scModule,
            'min_days' => is_null($scMin) ? null : (int)$scMin,
            'max_days' => is_null($scMax) ? null : (int)$scMax,
            'criteria' => h($scCriteria),
            'status' => h($scStatus),
            'created_at' => !empty($scCreated) ? date('d-m-Y h:i A', strtotime($scCreated)) : '',
            'employee_name' => h($scEmployeeName),
            'employee_email' => h($scEmployeeEmail),
            'employee_designation' => h($scEmployeeDesignation),
            'employee_project' => h($scEmployeeProject),
            'approver_name' => h($scApproverName),
            'approver_role' => h($scApproverRole),
            'approver_email' => h($scApproverEmail),
            'approver_designation' => h($scApproverDesignation),
            'approver_project' => h($scApproverProject)
        ];
    }
    mysqli_stmt_close($stmt);
}

$totalProjectChains = count_query($conn, "SELECT COUNT(*) FROM project_approval_chains WHERE status = 'Active'");
$totalStaffExceptions = count_query($conn, "SELECT COUNT(*) FROM approval_chains WHERE status = 'Active'");
$totalConfiguredProjects = count_query($conn, "SELECT COUNT(DISTINCT project_name) FROM project_approval_chains WHERE status = 'Active'");
$totalApprovers = count_query($conn, "
    SELECT COUNT(DISTINCT approver_id)
    FROM (
        SELECT approver_id FROM project_approval_chains WHERE status = 'Active'
        UNION
        SELECT approver_id FROM approval_chains WHERE status = 'Active'
    ) x
");
$pendingLeave = count_query($conn, "SELECT COUNT(*) FROM leave_applications WHERE status = 'Pending'");

mysqli_close($conn);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Approval Chain Management - Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" href="/img/logo/logo.png">
<link rel="shortcut icon" type="image/png" href="/img/logo/logo.png">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">

<style>
:root{
    --primary:#0d6efd;
    --primary-dark:#084298;
    --primary-soft:#e7f1ff;
    --success:#198754;
    --warning:#f59e0b;
    --danger:#dc3545;
    --purple:#6f42c1;
    --dark:#1f2937;
    --muted:#64748b;
    --border:#e5e7eb;
    --bg:#f3f6fb;
    --white:#ffffff;
}
*{box-sizing:border-box;}
body{
    background:var(--bg);
    font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    padding-top:70px;
    color:var(--dark);
}
.main-wrapper{
    max-width:1450px;
    margin:0 auto;
    padding:22px 15px 45px;
}
.hero-card{
    background:linear-gradient(135deg,#dc3545,#8b1e2d);
    color:#fff;
    border-radius:22px;
    padding:28px;
    margin-bottom:22px;
    box-shadow:0 12px 35px rgba(220,53,69,.24);
    position:relative;
    overflow:hidden;
}
.hero-card:after{
    content:"";
    position:absolute;
    width:230px;
    height:230px;
    border-radius:50%;
    background:rgba(255,255,255,.12);
    right:-75px;
    top:-75px;
}
.hero-card h1{
    margin:0;
    font-size:28px;
    font-weight:900;
    position:relative;
    z-index:1;
}
.hero-card p{
    margin:8px 0 0;
    opacity:.95;
    position:relative;
    z-index:1;
}
.hero-actions{
    margin-top:18px;
    position:relative;
    z-index:1;
}
.hero-btn{
    display:inline-block;
    background:#fff;
    color:#8b1e2d;
    padding:10px 16px;
    border-radius:12px;
    font-weight:900;
    margin-right:8px;
    text-decoration:none;
}
.hero-btn:hover,.hero-btn:focus{color:#8b1e2d;text-decoration:none;background:#f8fafc;}
.stats-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:16px;
    margin-bottom:22px;
}
.stat-card{
    background:var(--white);
    border:1px solid var(--border);
    border-radius:18px;
    padding:20px;
    box-shadow:0 8px 24px rgba(15,23,42,.06);
    display:flex;
    align-items:center;
    gap:14px;
}
.stat-icon{
    width:48px;
    height:48px;
    border-radius:15px;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:22px;
    background:var(--primary-soft);
    color:var(--primary-dark);
    flex:0 0 auto;
}
.stat-icon.success{background:#e8f7ef;color:#0f6848;}
.stat-icon.warning{background:#fff8e1;color:#8a5b00;}
.stat-icon.danger{background:#fdecee;color:#a61b2b;}
.stat-label{
    color:var(--muted);
    font-size:12px;
    font-weight:900;
    text-transform:uppercase;
    letter-spacing:.35px;
}
.stat-value{
    font-size:28px;
    font-weight:900;
    color:var(--primary-dark);
    line-height:1;
    margin-top:6px;
}
.rule-strip{
    background:#fff;
    border:1px solid var(--border);
    border-radius:18px;
    padding:16px;
    margin-bottom:18px;
    box-shadow:0 8px 24px rgba(15,23,42,.06);
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:12px;
}
.rule-item{
    background:#f8fafc;
    border:1px solid var(--border);
    border-radius:15px;
    padding:13px;
    font-weight:800;
    color:#334155;
}
.rule-item span{
    display:block;
    color:var(--muted);
    font-weight:700;
    font-size:12px;
    margin-top:4px;
}
.tabs-card{
    background:#fff;
    border:1px solid var(--border);
    border-radius:20px;
    overflow:hidden;
    box-shadow:0 8px 24px rgba(15,23,42,.06);
    margin-bottom:18px;
}
.tab-buttons{
    display:flex;
    border-bottom:1px solid var(--border);
    background:#f8fafc;
}
.tab-button{
    flex:1;
    border:0;
    background:transparent;
    padding:15px;
    font-weight:900;
    color:#64748b;
}
.tab-button.active{
    background:#fff;
    color:var(--primary-dark);
    box-shadow:inset 0 -4px 0 var(--primary);
}
.tab-pane{display:none;padding:22px;}
.tab-pane.active{display:block;}
.content-grid{
    display:grid;
    grid-template-columns:.95fr 1.35fr;
    gap:18px;
    align-items:start;
}
.panel-card{
    background:#fff;
    border-radius:20px;
    border:1px solid var(--border);
    box-shadow:0 8px 24px rgba(15,23,42,.06);
    margin-bottom:18px;
    overflow:hidden;
}
.panel-header{
    padding:18px 22px;
    background:#fbfdff;
    border-bottom:1px solid var(--border);
}
.panel-title{
    margin:0;
    color:var(--primary-dark);
    font-weight:900;
    font-size:20px;
}
.panel-subtitle{
    margin:5px 0 0;
    color:var(--muted);
    font-size:13px;
}
.panel-body{padding:22px;}
.form-grid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:15px;
}
.form-control{
    min-height:44px;
    border-radius:12px;
    border:1px solid #cbd5e1;
    box-shadow:none;
}
textarea.form-control{min-height:95px;resize:vertical;}
.form-control:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(13,110,253,.12);}
label{font-weight:800;color:#334155;}
.level-stage{
    background:#f8fafc;
    border:1px solid var(--border);
    border-radius:16px;
    padding:15px;
    margin-bottom:14px;
}
.level-heading{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    margin-bottom:10px;
}
.level-number{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:32px;
    height:32px;
    border-radius:10px;
    background:var(--primary);
    color:#fff;
    font-weight:900;
    margin-right:8px;
}
.level-note{
    font-size:12px;
    color:#64748b;
    margin-top:4px;
}
.current-badge{
    background:#e8f7ef;
    color:#0f6848;
    padding:5px 10px;
    border-radius:999px;
    font-size:11px;
    font-weight:900;
}
.help-box{
    background:#eef6ff;
    color:#084298;
    border:1px solid #cfe2ff;
    border-radius:16px;
    padding:15px;
    line-height:1.6;
    margin-bottom:15px;
}
.selected-staff-box{
    background:#fff8e1;
    color:#7c4a03;
    border:1px solid #fde68a;
    border-radius:16px;
    padding:15px;
    margin-bottom:15px;
}
.btn-main{
    background:var(--primary);
    color:#fff;
    border:none;
    padding:12px 18px;
    border-radius:12px;
    font-weight:900;
    display:inline-block;
    text-decoration:none;
}
.btn-main:hover,.btn-main:focus{background:var(--primary-dark);color:#fff;text-decoration:none;}
.btn-secondary-custom{background:#64748b;}
.btn-danger-custom{background:var(--danger);}
.filter-card{
    background:#fff;
    border:1px solid var(--border);
    border-radius:18px;
    padding:18px;
    margin-bottom:18px;
    box-shadow:0 8px 24px rgba(15,23,42,.06);
}
.filter-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:14px;
    align-items:end;
}
.table-card{
    background:#fff;
    border-radius:20px;
    border:1px solid var(--border);
    box-shadow:0 8px 24px rgba(15,23,42,.06);
    overflow:hidden;
    margin-bottom:18px;
}
.table-header{
    padding:16px 20px;
    background:linear-gradient(135deg,#0d6efd,#084298);
    color:#fff;
    font-weight:900;
    font-size:18px;
}
.table{margin:0;}
.table th{
    background:#f8fafc;
    color:#334155;
    font-size:12px;
    text-transform:uppercase;
    white-space:nowrap;
}
.table td{font-size:13px;vertical-align:middle!important;}
.status-pill,.module-pill,.role-pill{
    display:inline-block;
    padding:5px 10px;
    border-radius:999px;
    font-weight:900;
    font-size:11px;
    text-transform:uppercase;
}
.status-active{background:#d1fae5;color:#065f46;}
.status-inactive{background:#fee2e2;color:#991b1b;}
.module-workplan{background:#e0f2fe;color:#075985;}
.module-leave{background:#fef3c7;color:#92400e;}
.module-tour{background:#ede9fe;color:#5b21b6;}
.role-pill{
    background:#e7f1ff;
    color:#084298;
}
.action-buttons{display:flex;gap:6px;flex-wrap:wrap;}
.alert{border-radius:14px;border:none;font-weight:700;}
@media(max-width:1100px){.stats-grid,.filter-grid,.rule-strip{grid-template-columns:repeat(2,1fr)}.content-grid{grid-template-columns:1fr}}
@media(max-width:700px){
    body{padding-top:65px;}
    .main-wrapper{padding:14px 10px 35px;}
    .hero-card{padding:22px;border-radius:18px;}
    .hero-card h1{font-size:23px;}
    .stats-grid,.filter-grid,.form-grid,.rule-strip{grid-template-columns:1fr;}
    .panel-header,.panel-body,.tab-pane{padding:16px;}
    .tab-buttons{display:block;}
    .hero-btn,.btn-main{width:100%;text-align:center;margin:6px 0;}
    .action-buttons{flex-direction:column;}
    .action-buttons .btn,.action-buttons form{width:100%;}
    .action-buttons .btn{display:block;}
}
@media print{.no-print,.navbar,.site-footer{display:none!important;}body{padding-top:0;background:#fff}.main-wrapper{max-width:100%;padding:0}.panel-card,.table-card,.filter-card,.tabs-card{box-shadow:none;border:1px solid #ddd}.table th,.table td{font-size:10px;padding:5px!important;}}
</style>
</head>
<body>

<?php include 'navbar.php'; ?>

<div class="main-wrapper">

    <div class="hero-card">
        <h1><span class="glyphicon glyphicon-random"></span> Approval Chain Management</h1>
        <p>Project-wise approval chain is the main setup. Staff-wise chain is only for special exceptions.</p>
        <div class="hero-actions no-print">
            <a href="approver-dashboard.php" class="hero-btn"><span class="glyphicon glyphicon-ok-circle"></span> Approver Dashboard</a>
            <a href="workplan_approver.php" class="hero-btn"><span class="glyphicon glyphicon-list-alt"></span> Workplan Approver</a>
            <a href="home.php" class="hero-btn"><span class="glyphicon glyphicon-home"></span> Dashboard</a>
        </div>
    </div>

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><strong>Error:</strong> <?= h($error); ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="alert alert-success"><strong>Success:</strong> <?= h($success); ?></div>
    <?php endif; ?>

    <div class="stats-grid">
        <div class="stat-card"><div class="stat-icon success"><span class="glyphicon glyphicon-folder-open"></span></div><div><div class="stat-label">Project Rules</div><div class="stat-value"><?= (int)$totalProjectChains; ?></div></div></div>
        <div class="stat-card"><div class="stat-icon"><span class="glyphicon glyphicon-briefcase"></span></div><div><div class="stat-label">Configured Projects</div><div class="stat-value"><?= (int)$totalConfiguredProjects; ?></div></div></div>
        <div class="stat-card"><div class="stat-icon warning"><span class="glyphicon glyphicon-user"></span></div><div><div class="stat-label">Staff Exceptions</div><div class="stat-value"><?= (int)$totalStaffExceptions; ?></div></div></div>
        <div class="stat-card"><div class="stat-icon danger"><span class="glyphicon glyphicon-time"></span></div><div><div class="stat-label">Pending Leave</div><div class="stat-value"><?= (int)$pendingLeave; ?></div></div></div>
    </div>

    <div class="rule-strip">
        <div class="rule-item">
            Level 1 & Level 2
            <span>Can approve Workplan and Leave up to 3 days.</span>
        </div>
        <div class="rule-item">
            Level 3 / ED
            <span>Can approve Leave 4+ days and Tour requests.</span>
        </div>
        <div class="rule-item">
            Priority
            <span>Staff exception is checked first, then project-wise chain.</span>
        </div>
    </div>

    <div class="filter-card no-print">
        <form method="get" action="">
            <div class="filter-grid">
                <div class="form-group">
                    <label>Project Filter</label>
                    <select name="project" class="form-control" onchange="this.form.submit()">
                        <option value="">All Projects</option>
                        <?php foreach ($projectOptions as $projectName): ?>
                            <option value="<?= h($projectName); ?>" <?= $selectedProject === $projectName ? 'selected' : ''; ?>><?= h($projectName); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label>Staff Exception Filter</label>
                    <select name="employee_id" class="form-control" onchange="this.form.submit()">
                        <option value="0">-- Select Staff --</option>
                        <?php foreach ($employees as $emp): ?>
                            <option value="<?= (int)$emp['id']; ?>" <?= $selectedEmployee === (int)$emp['id'] ? 'selected' : ''; ?>>
                                <?= $emp['name']; ?> - <?= $emp['project']; ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label>Chain Status</label>
                    <select name="chain_status" class="form-control">
                        <option value="Active" <?= $selectedStatus === 'Active' ? 'selected' : ''; ?>>Active</option>
                        <option value="Inactive" <?= $selectedStatus === 'Inactive' ? 'selected' : ''; ?>>Inactive</option>
                        <option value="All" <?= $selectedStatus === 'All' ? 'selected' : ''; ?>>All</option>
                    </select>
                </div>

                <div class="form-group">
                    <button type="submit" class="btn-main"><span class="glyphicon glyphicon-search"></span> Filter</button>
                    <a href="admin-approval-chain.php" class="btn-main btn-secondary-custom">Reset</a>
                </div>
            </div>
        </form>
    </div>

    <div class="tabs-card">
        <div class="tab-buttons no-print">
            <button type="button" class="tab-button active" onclick="switchTab(event, 'projectTab')">
                <span class="glyphicon glyphicon-folder-open"></span> Project-wise Chain
            </button>
            <button type="button" class="tab-button" onclick="switchTab(event, 'staffTab')">
                <span class="glyphicon glyphicon-user"></span> Staff-wise Exception
            </button>
        </div>

        <div id="projectTab" class="tab-pane active">
            <div class="content-grid">
                <div class="panel-card">
                    <div class="panel-header">
                        <h3 class="panel-title">Project-wise Standard Chain</h3>
                        <p class="panel-subtitle">Set once per project. All staff under this project will follow this chain.</p>
                    </div>
                    <div class="panel-body">
                        <div class="help-box">
                            <strong>Recommended:</strong> Use this section for normal approval flow. Staff-wise exception is only needed for special cases.
                        </div>

                        <form method="post" action="">
                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="save_project_approval_stage" value="1">

                            <div class="form-group">
                                <label>Project <span style="color:#dc3545;">*</span></label>
                                <select name="project_name" class="form-control" required>
                                    <option value="">-- Select Project --</option>
                                    <?php foreach ($projectOptions as $projectName): ?>
                                        <option value="<?= h($projectName); ?>" <?= $selectedProject === $projectName ? 'selected' : ''; ?>>
                                            <?= h($projectName); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <?php for ($level = 1; $level <= 3; $level++): ?>
                                <div class="level-stage">
                                    <div class="level-heading">
                                        <div><span class="level-number"><?= $level; ?></span><strong><?= h($levelTitles[$level]); ?></strong></div>
                                        <?php if (!empty($projectStages[$level]['approver_id'])): ?>
                                            <span class="current-badge">Current Set</span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="level-note"><?= h($ruleNotes[$level]); ?></div>
                                    <div class="form-group" style="margin-top:10px;">
                                        <label>Approver for Level <?= $level; ?></label>
                                        <select name="project_levels[<?= $level; ?>]" class="form-control">
                                            <option value="0">-- Not Selected / Remove This Level --</option>
                                            <?php foreach ($approvers as $app): ?>
                                                <option value="<?= (int)$app['id']; ?>" <?= ((int)($projectStages[$level]['approver_id'] ?? 0) === (int)$app['id']) ? 'selected' : ''; ?>>
                                                    <?= $app['name']; ?> - <?= $app['role']; ?> - <?= $app['project']; ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>
                            <?php endfor; ?>

                            <div class="form-group">
                                <label>Criteria / Note</label>
                                <textarea name="criteria_note" class="form-control" placeholder="Example: Level 1 and Level 2 can approve leave up to 3 days and workplan; Level 3 approves leave 4+ days and tour."></textarea>
                            </div>

                            <button type="submit" class="btn-main" onclick="return confirm('Save project-wise approval chain? Old active rules for this project/module/level will be replaced.');">
                                <span class="glyphicon glyphicon-ok"></span> Save Project-wise Chain
                            </button>
                        </form>
                    </div>
                </div>

                <div class="table-card">
                    <div class="table-header"><span class="glyphicon glyphicon-list"></span> Project-wise Approval Rules</div>
                    <?php if (!empty($projectChains)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered">
                                <thead>
                                <tr>
                                    <th>Project</th>
                                    <th>Level</th>
                                    <th>Module</th>
                                    <th>Day Criteria</th>
                                    <th>Approver</th>
                                    <th>Status</th>
                                    <th class="no-print">Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($projectChains as $chain): ?>
                                    <?php
                                    $moduleClass = 'module-' . strtolower($chain['raw_module_type']);
                                    $dayText = 'All';
                                    if ($chain['raw_module_type'] === 'leave') {
                                        $dayText = ($chain['max_days'] === null) ? ((int)$chain['min_days'] . '+ days') : ((int)$chain['min_days'] . '–' . (int)$chain['max_days'] . ' days');
                                    }
                                    ?>
                                    <tr>
                                        <td><strong><?= $chain['project_name']; ?></strong></td>
                                        <td><strong>Level <?= (int)$chain['level']; ?></strong></td>
                                        <td><span class="module-pill <?= h($moduleClass); ?>"><?= $chain['module_type']; ?></span></td>
                                        <td><?= h($dayText); ?></td>
                                        <td>
                                            <strong><?= $chain['approver_name']; ?></strong><br>
                                            <span class="role-pill"><?= $chain['approver_role']; ?></span><br>
                                            <small><?= $chain['approver_email']; ?></small>
                                        </td>
                                        <td><span class="status-pill status-<?= strtolower($chain['status']); ?>"><?= $chain['status']; ?></span></td>
                                        <td class="no-print">
                                            <?php if ($chain['status'] === 'Active'): ?>
                                                <form method="post" action="" onsubmit="return confirm('Deactivate this project approval rule?');">
                                                    <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="chain_id" value="<?= (int)$chain['id']; ?>">
                                                    <button type="submit" name="deactivate_project_chain" value="1" class="btn btn-xs btn-danger">Deactivate</button>
                                                </form>
                                            <?php else: ?>
                                                <span class="text-muted">Inactive</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div style="padding:40px;text-align:center;color:#64748b;">
                            <span class="glyphicon glyphicon-inbox" style="font-size:42px;color:#cbd5e1;"></span>
                            <p style="margin-top:12px;font-weight:800;">No project-wise chain found.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div id="staffTab" class="tab-pane">
            <div class="content-grid">
                <div class="panel-card">
                    <div class="panel-header">
                        <h3 class="panel-title">Staff-wise Special Exception</h3>
                        <p class="panel-subtitle">Use only when one staff needs a different chain than the project standard.</p>
                    </div>
                    <div class="panel-body">
                        <?php if ($selectedStaff): ?>
                            <div class="selected-staff-box">
                                <strong>Selected Staff:</strong> <?= $selectedStaff['name']; ?><br>
                                <strong>Email:</strong> <?= $selectedStaff['email']; ?><br>
                                <strong>Project:</strong> <?= $selectedStaff['project']; ?><br>
                                <strong>Designation:</strong> <?= $selectedStaff['designation']; ?>
                            </div>
                        <?php endif; ?>

                        <form method="post" action="">
                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="save_staff_approval_stage" value="1">

                            <div class="form-group">
                                <label>Staff <span style="color:#dc3545;">*</span></label>
                                <select name="employee_id" class="form-control" required>
                                    <option value="">-- Select Staff --</option>
                                    <?php foreach ($employees as $emp): ?>
                                        <option value="<?= (int)$emp['id']; ?>" <?= $selectedEmployee === (int)$emp['id'] ? 'selected' : ''; ?>>
                                            <?= $emp['name']; ?> - <?= $emp['project']; ?> - <?= $emp['designation']; ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <?php for ($level = 1; $level <= 3; $level++): ?>
                                <div class="level-stage">
                                    <div class="level-heading">
                                        <div><span class="level-number"><?= $level; ?></span><strong><?= h($levelTitles[$level]); ?></strong></div>
                                        <?php if (!empty($currentStages[$level]['approver_id'])): ?>
                                            <span class="current-badge">Current Set</span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="level-note"><?= h($ruleNotes[$level]); ?></div>
                                    <div class="form-group" style="margin-top:10px;">
                                        <label>Approver for Level <?= $level; ?></label>
                                        <select name="levels[<?= $level; ?>]" class="form-control">
                                            <option value="0">-- Not Selected / Remove This Level --</option>
                                            <?php foreach ($approvers as $app): ?>
                                                <option value="<?= (int)$app['id']; ?>" <?= ((int)($currentStages[$level]['approver_id'] ?? 0) === (int)$app['id']) ? 'selected' : ''; ?>>
                                                    <?= $app['name']; ?> - <?= $app['role']; ?> - <?= $app['project']; ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>
                            <?php endfor; ?>

                            <div class="form-group">
                                <label>Exception Criteria / Note</label>
                                <textarea name="staff_criteria" class="form-control" placeholder="Example: Special chain for this staff only."></textarea>
                            </div>

                            <button type="submit" class="btn-main" onclick="return confirm('Save staff-wise special exception?');">
                                <span class="glyphicon glyphicon-ok"></span> Save Staff Exception
                            </button>
                        </form>
                    </div>
                </div>

                <div class="table-card">
                    <div class="table-header"><span class="glyphicon glyphicon-user"></span> Staff-wise Exceptions</div>
                    <?php if (!empty($staffChains)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered">
                                <thead>
                                <tr>
                                    <th>Staff</th>
                                    <th>Level</th>
                                    <th>Module</th>
                                    <th>Day Criteria</th>
                                    <th>Approver</th>
                                    <th>Status</th>
                                    <th class="no-print">Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($staffChains as $chain): ?>
                                    <?php
                                    $moduleClass = 'module-' . strtolower($chain['raw_module_type']);
                                    $dayText = 'All';
                                    if ($chain['raw_module_type'] === 'leave') {
                                        $dayText = ($chain['max_days'] === null) ? ((int)$chain['min_days'] . '+ days') : ((int)$chain['min_days'] . '–' . (int)$chain['max_days'] . ' days');
                                    }
                                    ?>
                                    <tr>
                                        <td>
                                            <strong><?= $chain['employee_name']; ?></strong><br>
                                            <small><?= $chain['employee_project']; ?> | <?= $chain['employee_designation']; ?></small>
                                        </td>
                                        <td><strong>Level <?= (int)$chain['level']; ?></strong></td>
                                        <td><span class="module-pill <?= h($moduleClass); ?>"><?= $chain['module_type']; ?></span></td>
                                        <td><?= h($dayText); ?></td>
                                        <td>
                                            <strong><?= $chain['approver_name']; ?></strong><br>
                                            <span class="role-pill"><?= $chain['approver_role']; ?></span><br>
                                            <small><?= $chain['approver_email']; ?></small>
                                        </td>
                                        <td><span class="status-pill status-<?= strtolower($chain['status']); ?>"><?= $chain['status']; ?></span></td>
                                        <td class="no-print">
                                            <?php if ($chain['status'] === 'Active'): ?>
                                                <form method="post" action="" onsubmit="return confirm('Deactivate this staff exception rule?');">
                                                    <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="chain_id" value="<?= (int)$chain['id']; ?>">
                                                    <button type="submit" name="deactivate_staff_chain" value="1" class="btn btn-xs btn-danger">Deactivate</button>
                                                </form>
                                            <?php else: ?>
                                                <span class="text-muted">Inactive</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div style="padding:40px;text-align:center;color:#64748b;">
                            <span class="glyphicon glyphicon-inbox" style="font-size:42px;color:#cbd5e1;"></span>
                            <p style="margin-top:12px;font-weight:800;">No staff-wise exception found.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function switchTab(event, tabId) {
    event.preventDefault();

    var panes = document.querySelectorAll('.tab-pane');
    for (var i = 0; i < panes.length; i++) {
        panes[i].classList.remove('active');
    }

    var buttons = document.querySelectorAll('.tab-button');
    for (var j = 0; j < buttons.length; j++) {
        buttons[j].classList.remove('active');
    }

    document.getElementById(tabId).classList.add('active');
    event.currentTarget.classList.add('active');
}
</script>

<?php include 'footer.php'; ?>
</body>
</html>
