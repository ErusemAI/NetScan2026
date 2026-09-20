-- NetScan2026 / NET//CHECK v3.0 — reference MySQL schema
-- The Node/Express backend (backend/server.js) auto-creates these on start;
-- this file is provided for manual setup or inspection.

CREATE DATABASE IF NOT EXISTS netscan;
USE netscan;

CREATE TABLE IF NOT EXISTS users(
   id INT AUTO_INCREMENT PRIMARY KEY,
   username VARCHAR(50) UNIQUE,
   password_hash CHAR(255),
   role ENUM('admin','viewer') DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS scans(
   id INT AUTO_INCREMENT PRIMARY KEY,
   scan_name VARCHAR(100),
   start_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions(
   user_id  INT,
   scan_id  INT,
   can_read BOOLEAN DEFAULT TRUE,
   can_write BOOLEAN DEFAULT FALSE,
   PRIMARY KEY(user_id,scan_id),
   FOREIGN KEY(user_id) REFERENCES users(id),
   FOREIGN KEY(scan_id) REFERENCES scans(id)
);
