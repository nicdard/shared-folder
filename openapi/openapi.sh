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
#!/bin/bash

# This script is used to generate the OpenAPI rust client for the PKI service.
docker run --rm -v $(pwd)/openapi:/local openapitools/openapi-generator-cli generate \
    -g rust \
    -i /local/pki-openapi.yml -o /local/pkiclient -c /local/pki-config.yaml
