# AGENTS.md

## Cursor Cloud specific instructions

This repo is a plain **PHP (8.3) + MariaDB** web app (an employee portal with a
Monthly Work Plan feature and an admin/reviewer panel). There is no build step,
no Composer dependencies, and no framework — files are served directly.

### Services & how to run them

- **MariaDB** is not managed by systemd in this VM. Start it manually before
  running the app:
  - `sudo mkdir -p /run/mysqld && sudo chown mysql:mysql /run/mysqld`
    (the socket dir is not auto-created; MariaDB fails to start without it)
  - `sudo -u mysql /usr/sbin/mariadbd >/tmp/mariadb.log 2>&1 &`
  - Check: `sudo mysqladmin ping`
- **App (PHP built-in server)** — the document root is the **repo root**, and
  pages live in `pages/` (they `require '../dbConnectionLocal.php'`):
  - `php -S 0.0.0.0:8000 -t /workspace`
  - Entry point: `http://localhost:8000/index.php`

### Database

- DB name `leave_app`; app connects as `app` / `app_pass` on `127.0.0.1`
  (overridable via `DB_HOST`/`DB_USER`/`DB_PASS`/`DB_NAME`/`DB_PORT` env vars in
  `dbConnectionLocal.php`).
- The DB data dir persists in the VM snapshot, so schema/seed normally survive
  across sessions. To (re)create from scratch:
  - `sudo mysql < sql/schema.sql`
  - create the app user (see `sql/schema.sql` header / `dbConnectionLocal.php`)
  - `php sql/seed.php` (idempotent; seeds demo accounts + a sample submitted plan)
- `monthly_work_plans` / `monthly_work_plan_items` are also auto-created at
  runtime by `pages/work_plan.php` (`ensure_work_plan_*` functions), so they may
  appear even on a fresh DB once that page is opened.

### Demo accounts (password: `password`)

- `admin@tus.test` — Admin (sees all work plans)
- `manager@tus.test` — Manager (sees only employees in their `approval_chains`)
- `employee@tus.test` — Employee (fills in / submits work plans; gets 403 on the admin panel)

### Notes / gotchas

- Login routes reviewers (Admin/Manager/Approver) to
  `pages/admin_work_plans.php` and employees to `pages/work_plan.php`.
- `sql/`, the login/scaffold pages (`index.php`, `logout.php`,
  `pages/navbar.php`, `pages/footer.php`) and `dbConnectionLocal.php` are a local
  harness so the feature runs end-to-end; the real deployment already provides
  equivalents. The reusable deliverable is `pages/admin_work_plans.php`.
