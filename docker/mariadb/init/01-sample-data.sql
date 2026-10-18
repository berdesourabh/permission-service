-- Sample schema and accounts for local development.
-- Runs only on first start (empty data volume).

CREATE DATABASE IF NOT EXISTS shop;

CREATE TABLE shop.orders (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    customer_id BIGINT NOT NULL,
    total DECIMAL(10, 2) NOT NULL
);

CREATE TABLE shop.customers (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL
);

-- Accounts to grant permissions to.
CREATE USER 'sourabh' @'%' IDENTIFIED BY 'sourabh';

CREATE USER 'dinesh' @'%' IDENTIFIED BY 'dinesh';