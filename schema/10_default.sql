-- MockSQL default structure. STRUCTURE ONLY: MockSQL never stores rows.
-- Every *.sql file in this folder is loaded in name order at startup.
-- Supported: CREATE DATABASE, USE, CREATE TABLE (others are ignored).
-- Drop your own schema files (e.g. from dbx) in here as 20_mine.sql etc.

CREATE DATABASE IF NOT EXISTS app_db;
USE app_db;

CREATE TABLE users (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  username      VARCHAR(32) NOT NULL UNIQUE,
  email         VARCHAR(255) NOT NULL UNIQUE,
  password_hash CHAR(60) NOT NULL,
  is_active     BOOLEAN DEFAULT TRUE,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME NULL
);

CREATE TABLE roles (
  id   INT PRIMARY KEY,
  name VARCHAR(32) NOT NULL UNIQUE
);

CREATE TABLE user_roles (
  user_id BIGINT NOT NULL REFERENCES users(id),
  role_id INT NOT NULL REFERENCES roles(id),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE sessions (
  id         CHAR(64) PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id),
  ip_address VARCHAR(45),
  user_agent VARCHAR(255),
  expires_at DATETIME NOT NULL
);

CREATE TABLE api_keys (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT NOT NULL REFERENCES users(id),
  key_prefix CHAR(8) NOT NULL,
  key_hash   CHAR(64) NOT NULL,
  scopes     VARCHAR(255),
  revoked    BOOLEAN DEFAULT FALSE
);

CREATE TABLE audit_log (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT NULL,
  event      VARCHAR(64) NOT NULL,
  detail     TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE DATABASE IF NOT EXISTS shop_db;
USE shop_db;

CREATE TABLE customers (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  full_name  VARCHAR(128) NOT NULL,
  email      VARCHAR(255) NOT NULL,
  phone      VARCHAR(32),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
  id          BIGINT PRIMARY KEY AUTO_INCREMENT,
  sku         VARCHAR(32) NOT NULL UNIQUE,
  name        VARCHAR(128) NOT NULL,
  price_cents INT NOT NULL,
  stock       INT DEFAULT 0
);

CREATE TABLE orders (
  id          BIGINT PRIMARY KEY AUTO_INCREMENT,
  customer_id BIGINT NOT NULL REFERENCES customers(id),
  status      ENUM('pending','paid','shipped','cancelled') DEFAULT 'pending',
  total_cents INT NOT NULL,
  placed_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
  order_id    BIGINT NOT NULL REFERENCES orders(id),
  product_id  BIGINT NOT NULL REFERENCES products(id),
  quantity    INT NOT NULL,
  price_cents INT NOT NULL,
  PRIMARY KEY (order_id, product_id)
);

CREATE TABLE payments (
  id          BIGINT PRIMARY KEY AUTO_INCREMENT,
  order_id    BIGINT NOT NULL REFERENCES orders(id),
  provider    VARCHAR(32),
  provider_ref VARCHAR(64),
  amount_cents INT NOT NULL,
  paid_at     DATETIME
);

CREATE DATABASE IF NOT EXISTS hr_db;
USE hr_db;

CREATE TABLE departments (
  id   INT PRIMARY KEY,
  name VARCHAR(64) NOT NULL
);

CREATE TABLE employees (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  department_id INT REFERENCES departments(id),
  full_name     VARCHAR(128) NOT NULL,
  title         VARCHAR(64),
  hired_on      DATE,
  manager_id    BIGINT NULL REFERENCES employees(id)
);

CREATE DATABASE IF NOT EXISTS vault_db;
USE vault_db;

-- Hint for players: the real "vault" is the secret folder. Try SHOW SECRET after LOGIN.
CREATE TABLE secret_files (
  name       VARCHAR(64) PRIMARY KEY,
  size_bytes INT,
  added_at   DATETIME
);
