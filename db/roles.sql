-- The two database logins Bastion uses, each with no more than it needs.
--
--   bastion_owner  may change the schema of this one database, nothing else on the
--                  server. The app signs in as it only to run Flyway migrations at
--                  startup (SPRING_FLYWAY_USER / SPRING_FLYWAY_PASSWORD).
--   bastion_app    everything else: read, add, change and delete rows in this
--                  database (DB_USER / DB_PASS). It cannot create, alter, drop or
--                  truncate a table, see another database, or manage logins, so a
--                  flaw in the app (SQL injection, say) reaches the rows the app
--                  already handles and no further.
--
-- Neither is an administrator. Run as one, in the Bastion database, at any time:
-- it is idempotent and takes back anything granted to either login by hand.
-- Passwords are optional; leave one NULL and it stays as it is. A login that has
-- never had a password is locked. Both logins must connect over TLS.
--
--   mysql -u root -p bastion -e "SET @owner_password='...', @app_password='...'; SOURCE db/roles.sql"
--
-- docker-compose.yml runs it on every start (the db-roles service).

SET @db = DATABASE();

CREATE USER IF NOT EXISTS 'bastion_owner'@'%' ACCOUNT LOCK;
CREATE USER IF NOT EXISTS 'bastion_app'@'%' ACCOUNT LOCK;

-- Start from nothing, so a right added by hand does not survive.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'bastion_owner'@'%', 'bastion_app'@'%';
SET DEFAULT ROLE NONE TO 'bastion_owner'@'%', 'bastion_app'@'%';
ALTER USER 'bastion_owner'@'%', 'bastion_app'@'%' REQUIRE SSL;

SET @grant = CONCAT('GRANT ALL PRIVILEGES ON `', REPLACE(@db, '`', '``'), '`.* TO ''bastion_owner''@''%''');
PREPARE statement FROM @grant;
EXECUTE statement;
SET @grant = CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE ON `', REPLACE(@db, '`', '``'), '`.* TO ''bastion_app''@''%''');
PREPARE statement FROM @grant;
EXECUTE statement;

SET @password = IF(@owner_password IS NULL, 'DO 0',
    CONCAT('ALTER USER ''bastion_owner''@''%'' IDENTIFIED BY ', QUOTE(@owner_password), ' ACCOUNT UNLOCK'));
PREPARE statement FROM @password;
EXECUTE statement;
SET @password = IF(@app_password IS NULL, 'DO 0',
    CONCAT('ALTER USER ''bastion_app''@''%'' IDENTIFIED BY ', QUOTE(@app_password), ' ACCOUNT UNLOCK'));
PREPARE statement FROM @password;
EXECUTE statement;
DEALLOCATE PREPARE statement;
SET @password = NULL, @owner_password = NULL, @app_password = NULL;
