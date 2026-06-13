<?php
$user_role = $_SESSION['role'] ?? 'Employee';
$user_name = isset($_SESSION['name']) ? htmlspecialchars($_SESSION['name'], ENT_QUOTES, 'UTF-8') : 'User';
$current_page = basename($_SERVER['PHP_SELF']);
?>

<style>
    /* ========================================
       ADMIN NAVBAR (Red/Dark)
       ======================================== */
    .navbar-admin {
        background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        box-shadow: 0 4px 12px rgba(220, 53, 69, 0.25);
        border-bottom: 3px solid #a02830;
    }

    /* ========================================
       EMPLOYEE NAVBAR (Blue/Standard)
       ======================================== */
    .navbar-employee {
        background: linear-gradient(135deg, #007BFF 0%, #0056b3 100%);
        box-shadow: 0 4px 12px rgba(0, 123, 255, 0.25);
        border-bottom: 3px solid #003d82;
    }

    .main-navbar {
        position: fixed;
        width: 100%;
        top: 0;
        z-index: 1000;
    }

    .navbar-brand {
        font-weight: 700;
        font-size: 18px;
        color: white !important;
        padding: 10px 20px !important;
    }

    .navbar-default .navbar-nav > li > a {
        color: rgba(255, 255, 255, 0.9) !important;
        font-weight: 500;
        transition: all 0.3s ease;
        padding: 15px 15px !important;
    }

    .navbar-default .navbar-nav > li > a:hover {
        color: white !important;
        background: rgba(255, 255, 255, 0.15);
        border-radius: 4px;
    }

    .navbar-default .navbar-nav > li.active > a {
        background: rgba(255, 255, 255, 0.25) !important;
        color: white !important;
        border-radius: 4px;
        border-bottom: 3px solid white;
    }

    .navbar-default .navbar-nav > li > a > span {
        margin-right: 8px;
    }

    .dropdown-menu {
        background: rgba(0, 0, 0, 0.9) !important;
        border: none;
        border-radius: 6px;
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.25);
        margin-top: 8px;
    }

    .dropdown-menu > li > a {
        color: rgba(255, 255, 255, 0.9) !important;
        font-weight: 500;
        padding: 12px 20px !important;
        transition: all 0.3s ease;
    }

    .dropdown-menu > li > a:hover {
        background: rgba(255, 255, 255, 0.15) !important;
        color: white !important;
        padding-left: 25px !important;
    }

    .dropdown-menu > li.divider {
        background-color: rgba(255, 255, 255, 0.15);
    }

    .admin-badge {
        background: linear-gradient(135deg, #ffc107 0%, #ff9800 100%);
        color: #333;
        padding: 5px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        margin-left: 8px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        box-shadow: 0 2px 8px rgba(255, 193, 7, 0.3);
    }

    .user-info-navbar {
        color: white;
        padding: 15px 20px;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .user-info-navbar strong {
        display: block;
        font-size: 14px;
        margin-bottom: 3px;
    }

    .user-role {
        font-size: 11px;
        opacity: 0.85;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .user-avatar {
        width: 36px;
        height: 36px;
        background: rgba(255, 255, 255, 0.2);
        border: 2px solid white;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
        margin-right: 8px;
        vertical-align: middle;
    }

    .icon-admin { color: #ffc107; }
    .icon-dashboard { color: #28a745; }
    .icon-home { color: #17a2b8; }
    .icon-users { color: #ffc107; }
    .icon-list { color: #6f42c1; }
    .icon-chart { color: #fd7e14; }
    .icon-profile { color: #20c997; }

    .navbar-toggle {
        border-color: rgba(255, 255, 255, 0.3) !important;
    }

    .navbar-toggle .icon-bar {
        background-color: white !important;
    }

    .navbar-toggle:hover {
        background-color: rgba(255, 255, 255, 0.1) !important;
    }

    @media (max-width: 767px) {
        .navbar-collapse {
            background: rgba(0, 0, 0, 0.15);
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            margin-top: 10px;
        }

        .navbar-default .navbar-nav {
            margin-top: 10px;
        }

        .navbar-default .navbar-nav > li {
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .navbar-default .navbar-nav > li > a {
            padding: 12px 20px !important;
        }

        .user-info-navbar {
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            margin-top: 10px;
            padding-top: 15px;
        }
    }
</style>

<?php if ($user_role === 'Admin'): ?>
<nav class="navbar navbar-default main-navbar navbar-admin">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#admin-navbar-collapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="admin-dashboard.php">
                <span class="glyphicon glyphicon-lock icon-admin"></span> Admin Panel
            </a>
        </div>

        <div class="collapse navbar-collapse" id="admin-navbar-collapse">
            <ul class="nav navbar-nav">
                <li <?= ($current_page === 'admin-dashboard.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-dashboard.php">
                        <span class="glyphicon glyphicon-dashboard icon-dashboard"></span> Dashboard
                    </a>
                </li>
                <li <?= ($current_page === 'admin-users.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-users.php">
                        <span class="glyphicon glyphicon-user icon-users"></span> Manage Users
                    </a>
                </li>
                <li <?= ($current_page === 'admin-approvals.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-approvals.php">
                        <span class="glyphicon glyphicon-check icon-list"></span> Approvals
                    </a>
                </li>
                <li <?= ($current_page === 'admin-approval-chain.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-approval-chain.php">
                        <span class="glyphicon glyphicon-random"></span> Approval Chain
                    </a>
                </li>
                <li <?= ($current_page === 'admin-leave-types.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-leave-types.php">
                        <span class="glyphicon glyphicon-tags"></span> Leave Types
                    </a>
                </li>
                <li <?= ($current_page === 'admin-reports.php') ? 'class="active"' : ''; ?>>
                    <a href="admin-reports.php">
                        <span class="glyphicon glyphicon-stats icon-chart"></span> Reports
                    </a>
                </li>
            </ul>

            <ul class="nav navbar-nav navbar-right">
                <li class="dropdown">
                    <a href="#" class="dropdown-toggle" data-toggle="dropdown">
                        <div class="user-avatar">
                            <span class="glyphicon glyphicon-user"></span>
                        </div>
                        <span class="admin-badge">Admin</span>
                        <b class="caret"></b>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-right">
                        <li class="user-info-navbar">
                            <strong><?= $user_name; ?></strong>
                            <div class="user-role">Administrator</div>
                        </li>
                        <li class="divider"></li>
                        <li><a href="profile.php"><span class="glyphicon glyphicon-cog"></span> My Profile</a></li>
                        <li><a href="admin-dashboard.php"><span class="glyphicon glyphicon-dashboard"></span> Admin Dashboard</a></li>
                        <li><a href="home.php"><span class="glyphicon glyphicon-home"></span> Switch to User Area</a></li>
                        <li class="divider"></li>
                        <li><a href="../logout.php"><span class="glyphicon glyphicon-log-out"></span> Logout</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>
<?php else: ?>
<nav class="navbar navbar-default main-navbar navbar-employee">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#employee-navbar-collapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="home.php">
                <span class="glyphicon glyphicon-briefcase"></span> Leave Management
            </a>
        </div>

        <div class="collapse navbar-collapse" id="employee-navbar-collapse">
            <ul class="nav navbar-nav">
                <li <?= ($current_page === 'home.php') ? 'class="active"' : ''; ?>>
                    <a href="home.php">
                        <span class="glyphicon glyphicon-home icon-home"></span> Home
                    </a>
                </li>
                <li <?= ($current_page === 'my-applications.php') ? 'class="active"' : ''; ?>>
                    <a href="my-applications.php">
                        <span class="glyphicon glyphicon-list icon-list"></span> My Applications
                    </a>
                </li>
                <li <?= ($current_page === 'leave-balance.php') ? 'class="active"' : ''; ?>>
                    <a href="leave-balance.php">
                        <span class="glyphicon glyphicon-chart-bar icon-chart"></span> Leave Balance
                    </a>
                </li>
                <?php if (in_array($user_role, ['Manager', 'Approver'], true)): ?>
                    <li <?= ($current_page === 'approver-dashboard.php') ? 'class="active"' : ''; ?>>
                        <a href="approver-dashboard.php">
                            <span class="glyphicon glyphicon-ok-circle"></span> My Approvals
                        </a>
                    </li>
                <?php endif; ?>
            </ul>

            <ul class="nav navbar-nav navbar-right">
                <li class="dropdown">
                    <a href="#" class="dropdown-toggle" data-toggle="dropdown">
                        <div class="user-avatar">
                            <span class="glyphicon glyphicon-user"></span>
                        </div>
                        <?= $user_name; ?>
                        <b class="caret"></b>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-right">
                        <li class="user-info-navbar">
                            <strong><?= $user_name; ?></strong>
                            <div class="user-role">Employee</div>
                        </li>
                        <li class="divider"></li>
                        <li><a href="profile.php"><span class="glyphicon glyphicon-cog"></span> My Profile</a></li>
                        <li><a href="home.php"><span class="glyphicon glyphicon-home"></span> Home</a></li>
                        <li class="divider"></li>
                        <li><a href="../logout.php"><span class="glyphicon glyphicon-log-out"></span> Logout</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>
<?php endif; ?>
