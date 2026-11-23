CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    display_name VARCHAR(100),
    password_hash VARCHAR(60),
    role VARCHAR(16) NOT NULL DEFAULT 'USER',
    email_verified_at TIMESTAMP(6) NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    auth_version BIGINT NOT NULL DEFAULT 0,
    last_auth_email_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE email_action_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    purpose VARCHAR(24) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP(6) NOT NULL,
    consumed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_email_action_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT uq_email_action_user_purpose UNIQUE (user_id, purpose)
) ENGINE=InnoDB;
