#!/bin/bash
# Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.
#

# Initialise test bucket to be used as file storage
echo "Create test-bucket"
awslocal s3api create-bucket --bucket test-bucket
echo "Created test-bucket"
