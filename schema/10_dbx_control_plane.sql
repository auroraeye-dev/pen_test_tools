-- DBX orchestrator (control plane), modelled on the public DBX architecture
-- docs: tenants, members (primary/replica), scoped tenant keys, operators,
-- backups and audit. Structure only, written for this lab.

CREATE DATABASE IF NOT EXISTS dbx_control;
USE dbx_control;

CREATE TABLE tenants (
  tenant_id     VARCHAR(64) PRIMARY KEY,
  display_name  VARCHAR(128),
  state         ENUM('provisioning','active','hibernated','restoring','deleted') NOT NULL,
  data_dir      VARCHAR(255) NOT NULL,
  replicas      INT DEFAULT 0,
  dek_id        VARCHAR(64),
  created_at    DATETIME NOT NULL,
  hibernated_at DATETIME NULL
);

CREATE TABLE tenant_members (
  tenant_id   VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
  member_id   VARCHAR(64) NOT NULL,
  role        ENUM('primary','replica') NOT NULL,
  socket_path VARCHAR(255),
  loopback_port INT NULL,
  wal_seq     BIGINT,
  healthy     BOOLEAN,
  PRIMARY KEY (tenant_id, member_id)
);

CREATE TABLE tenant_keys (
  tenant_id    VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
  key_id       VARCHAR(64) NOT NULL,
  name         VARCHAR(64),
  role         ENUM('reader','writer','tenant-admin') NOT NULL,
  key_patterns VARCHAR(255),
  secret_hash  CHAR(64) NOT NULL,
  created_at   DATETIME NOT NULL,
  revoked_at   DATETIME NULL,
  PRIMARY KEY (tenant_id, key_id)
);

CREATE TABLE operators (
  operator_id   VARCHAR(64) PRIMARY KEY,
  username      VARCHAR(64) NOT NULL UNIQUE,
  password_hash CHAR(60) NOT NULL,
  jwt_issued_at DATETIME NULL
);

CREATE TABLE backups (
  backup_id     VARCHAR(64) PRIMARY KEY,
  tenant_id     VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
  checkpoint_id CHAR(64) NOT NULL,
  manifest_sha  CHAR(64) NOT NULL,
  path          VARCHAR(255),
  created_at    DATETIME NOT NULL
);

CREATE TABLE forget_receipts (
  receipt_id   VARCHAR(64) PRIMARY KEY,
  tenant_id    VARCHAR(64) NOT NULL,
  dek_shredded BOOLEAN NOT NULL,
  purged_at    DATETIME NOT NULL
);

CREATE TABLE usage_daily (
  tenant_id     VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
  day           DATE NOT NULL,
  commands      BIGINT,
  bytes_stored  BIGINT,
  vectors       BIGINT,
  PRIMARY KEY (tenant_id, day)
);

CREATE TABLE audit_events (
  id          BIGINT PRIMARY KEY AUTO_INCREMENT,
  actor       VARCHAR(128) NOT NULL,
  action      VARCHAR(64) NOT NULL,
  tenant_id   VARCHAR(64) NULL,
  detail      TEXT,
  created_at  DATETIME NOT NULL
);
