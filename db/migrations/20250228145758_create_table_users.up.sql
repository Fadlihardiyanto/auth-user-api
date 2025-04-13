CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(100) UNIQUE NOT NULL,
    email_token VARCHAR(100),
    email_verified_at TIMESTAMP,
    password TEXT,
    password_reset_token VARCHAR(100),
    role VARCHAR(50) DEFAULT 'customer',  -- 'admin', 'customer'
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
