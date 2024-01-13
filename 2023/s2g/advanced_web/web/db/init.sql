CREATE DATABASE IF NOT EXISTS nonsense;

USE nonsense;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    password VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content text,
    user_id INT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

INSERT INTO users (username, password) VALUES ('admin', 'admin');
INSERT INTO notes (content, user_id) VALUES ('S2G{test_flag}', 1);
