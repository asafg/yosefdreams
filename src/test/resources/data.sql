-- Insert admin user with bcrypt password 'admin'
INSERT INTO users (id, name, username, email, password) VALUES (1, 'Admin', 'admin', 'admin@example.com', '{bcrypt}$2a$10$7EqJtq98hPqEX7fNZaFWoOa5Wv4yQ3e2r6hFZ8b5jB6vZQ4h5h6iK');
INSERT INTO roles (id, name) VALUES (1, 'ROLE_USER');
INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);
