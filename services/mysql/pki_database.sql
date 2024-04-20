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
/* 
The table where to store the certificates:
- serial_number: the Serial Number: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
      It MUST be unique for each certificate issued by a given CA and non negative
*/
CREATE TABLE pki (
    serial_number INT NOT NULL CHECK (serial_number > 0) PRIMARY KEY,
    certificate TEXT NOT NULL
);