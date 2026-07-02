-- Schema + seed data for the "leave" / work-plan demo application.
-- This file is a LOCAL TEST HARNESS used to run and demonstrate the
-- Monthly Work Plan feature and the new Admin panel page end-to-end.
--
-- In the real deployment these tables already exist (the work plan page
-- even auto-creates monthly_work_plans / monthly_work_plan_items at runtime).
-- The users / approval_chains tables below mirror the columns referenced by
-- the application code.

CREATE DATABASE IF NOT EXISTS leave_app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE leave_app;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    designation VARCHAR(150) NULL,
    project_name VARCHAR(150) NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'Employee',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approval_chains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    approver_id INT NOT NULL,
    approval_level INT NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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
);

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
);
