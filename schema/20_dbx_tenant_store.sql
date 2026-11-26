-- Inside one DBX tenant (data plane): its KV working state, vector indexes,
-- named spaces, WAL and checkpoints. Each tenant owns a separate directory;
-- this is how "acme" looks. Structure only, written for this lab.

CREATE DATABASE IF NOT EXISTS dbx_tenant_acme;
USE dbx_tenant_acme;

CREATE TABLE kv_entries (
  key_name   VARBINARY(512) PRIMARY KEY,
  value      LONGBLOB,
  value_type ENUM('string','vector') NOT NULL,
  expires_at DATETIME NULL,
  wal_seq    BIGINT NOT NULL
);

CREATE TABLE vector_indexes (
  index_name VARCHAR(128) PRIMARY KEY,
  dim        INT NOT NULL,
  encoding   ENUM('f32','sq8') DEFAULT 'sq8',
  metric     VARCHAR(16) DEFAULT 'cosine',
  hnsw_m     INT DEFAULT 16,
  hnsw_ef    INT DEFAULT 200,
  generation BIGINT DEFAULT 0
);

CREATE TABLE vector_spaces (
  index_name VARCHAR(128) NOT NULL REFERENCES vector_indexes(index_name),
  space_name VARCHAR(64) NOT NULL,
  dim        INT NOT NULL,
  mmap_file  VARCHAR(255),
  PRIMARY KEY (index_name, space_name)
);

CREATE TABLE vectors (
  index_name VARCHAR(128) NOT NULL,
  space_name VARCHAR(64) DEFAULT 'default',
  vector_id  VARCHAR(255) NOT NULL,
  embedding  BLOB NOT NULL,
  generation BIGINT NOT NULL,
  tombstoned BOOLEAN DEFAULT FALSE,
  PRIMARY KEY (index_name, space_name, vector_id)
);

CREATE TABLE vector_migrations (
  index_name   VARCHAR(128) PRIMARY KEY,
  target_dim   INT NOT NULL,
  target_enc   ENUM('f32','sq8'),
  state        ENUM('started','swapped','cancelled'),
  rows_added   BIGINT DEFAULT 0
);

CREATE TABLE wal_segments (
  segment_no  BIGINT PRIMARY KEY,
  first_seq   BIGINT NOT NULL,
  last_seq    BIGINT NOT NULL,
  fsync_mode  ENUM('always','everysec') NOT NULL,
  crc_ok      BOOLEAN NOT NULL,
  file_path   VARCHAR(255)
);

CREATE TABLE checkpoints (
  checkpoint_id CHAR(64) PRIMARY KEY,
  covered_seq   BIGINT NOT NULL,
  kv_snapshot   VARCHAR(255),
  vector_seals  TEXT,
  is_current    BOOLEAN DEFAULT FALSE,
  created_at    DATETIME NOT NULL
);

-- Hint for players: the vault lives in the KV space. After AUTH try KEYS vault:*
CREATE TABLE vault_index (
  key_name   VARCHAR(255) PRIMARY KEY,
  size_bytes INT
);
