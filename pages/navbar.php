<?php
/**
 * Shared top navigation bar.
 * Expects an active PHP session (started by the including page).
 */
$navRole = $_SESSION['role'] ?? '';
$navName = $_SESSION['name'] ?? ($_SESSION['user_email'] ?? 'User');
$isReviewer = in_array($navRole, ['Admin', 'Manager', 'Approver'], true);
?>
<nav class="navbar navbar-default navbar-fixed-top no-print" style="border-radius:0; background:#007bff; border:none;">
    <div class="container-fluid">
        <div class="navbar-header">
            <span class="navbar-brand" style="color:#fff; font-weight:bold;">TUS Portal</span>
        </div>
        <ul class="nav navbar-nav">
            <li><a style="color:#fff;" href="/pages/work_plan.php">My Work Plan</a></li>
            <?php if ($isReviewer): ?>
                <li><a style="color:#fff;" href="/pages/admin_work_plans.php">Admin: Work Plans</a></li>
            <?php endif; ?>
        </ul>
        <ul class="nav navbar-nav navbar-right">
            <li><span class="navbar-text" style="color:#fff;">
                <?= htmlspecialchars($navName, ENT_QUOTES, 'UTF-8'); ?>
                <?php if ($navRole !== ''): ?>(<?= htmlspecialchars($navRole, ENT_QUOTES, 'UTF-8'); ?>)<?php endif; ?>
            </span></li>
            <li><a style="color:#fff;" href="/logout.php">Logout</a></li>
        </ul>
    </div>
</nav>
