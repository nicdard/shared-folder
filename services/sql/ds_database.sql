CREATE DATABASE IF NOT EXISTS ds;

USE ds;

-- Table to store the users
CREATE TABLE users (
    user_email VARCHAR(100) NOT NULL PRIMARY KEY,
    INDEX( user_email(4) ),
    CONSTRAINT user_email_unique UNIQUE (user_email)
) ENGINE =INNODB
DEFAULT CHARSET = UTF8;

-- Table to store the folders
CREATE TABLE folders (
    folder_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY
    -- same folder_name could be used by different users.
    -- folder_name VARCHAR(36) NOT NULL,
) ENGINE =INNODB
DEFAULT CHARSET = UTF8;

-- Relationship table between folders to users (1 to many)
CREATE TABLE folders_users (
    folder_id INT UNSIGNED NOT NULL,
    user_email VARCHAR(100) NOT NULL,
    FOREIGN KEY (folder_id) REFERENCES folders(folder_id),
    FOREIGN KEY (user_email) REFERENCES users(user_email),
    PRIMARY KEY (folder_id, user_email),
    INDEX ( user_email, folder_id ),
    CONSTRAINT folder_user_couple_unique UNIQUE (folder_id, user_email)
) ENGINE =INNODB
DEFAULT CHARSET = UTF8;

-- Store all pending messages for each user and folder.
CREATE TABLE pending_group_messages (
    message_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    folder_id INT UNSIGNED NOT NULL,
    user_email VARCHAR(100) NOT NULL,
    payload BLOB,
    FOREIGN KEY (folder_id) REFERENCES folders(folder_id),
    FOREIGN KEY (user_email) REFERENCES users(user_email),
    INDEX ( user_email, folder_id )
) ENGINE =INNODB
DEFAULT CHARSET = UTF8;