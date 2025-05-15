-- Add columns for reset token
ALTER TABLE users ADD COLUMN reset_token VARCHAR;
ALTER TABLE users ADD COLUMN reset_token_creation_date TIMESTAMP;
