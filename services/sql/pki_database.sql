-- Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
--
-- This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
-- License as published by the Free Software Foundation, version 3.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
-- warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along with this program. If not, see <https://
-- www.gnu.org/licenses/>.
--
CREATE DATABASE IF NOT EXISTS pki;

USE pki;

-- Table to store the certificates
CREATE TABLE certificates (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- The email of the user, maximum length is local part = 64 + domain part = 255 + '@' = 1 = 320
    -- However, addresses should fit in MAIL and RCPT command of 254 characters: https://www.rfc-editor.org/errata_search.php?rfc=3696&eid=1690
    -- We impose a stricter limit: https://stackoverflow.com/questions/1297272/how-long-should-sql-email-fields-be
    email VARCHAR(100) NOT NULL,
    -- The certificate in PEM format
    certificate TEXT NOT NULL,
    -- Create an index on the first 4 characters of the email to speed up queries
    INDEX( email(4) ),
    CONSTRAINT email_unique UNIQUE (email)
) ENGINE =INNODB
DEFAULT CHARSET = UTF8;
