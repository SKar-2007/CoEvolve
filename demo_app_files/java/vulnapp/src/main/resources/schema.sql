CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    role VARCHAR(20)
);

INSERT INTO users VALUES (1, 'admin', 'supersecret123', 'admin');
INSERT INTO users VALUES (2, 'user', 'password123', 'user');
