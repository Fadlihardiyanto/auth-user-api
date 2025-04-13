CREATE TABLE user_login_histories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    login_time TIMESTAMP DEFAULT NOW(),
    ip_address TEXT,
    device_info JSONB, -- Simpan detail device dalam format JSONB
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);