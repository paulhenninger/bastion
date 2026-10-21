-- Bastion 2.0.1
--
-- 1. user_sessions.auth_method was VARCHAR(20), but PASSWORD_RECOVERY_CODE is 22
--    characters: signing in with a recovery code failed on MySQL. Widened with room
--    to spare; MySqlMigrationTest now checks every enum against its column.
--
-- 2. Each signup's chosen display name travels with its verification link, like its
--    password does, so verification applies the name of the signup the person proved
--    — not one typed by whoever registered the address first (see AuthService).

ALTER TABLE user_sessions
    MODIFY auth_method VARCHAR(32) NOT NULL;

ALTER TABLE email_verification_tokens
    ADD COLUMN name VARCHAR(100) NULL;
