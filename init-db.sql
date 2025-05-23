-- Database initialization script
-- This ensures the database and user are properly configured

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE securitytoolkit' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'securitytoolkit')\gexec

-- Grant all privileges to user
GRANT ALL PRIVILEGES ON DATABASE securitytoolkit TO secuser;

-- Connect to the securitytoolkit database
\c securitytoolkit;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO secuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO secuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO secuser;