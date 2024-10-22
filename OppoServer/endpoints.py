"""
/*
 * This file is part of the oppo_metrics distribution (https://github.com/CTTCTech/oppo_metrics).
 * Copyright (c) 2024 Centre Tecnològic de Telecomunicacions de Catalunya (CTTC).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"""

class Endpoint:
    def __init__(self, uri=None):
        if (not uri):
            uri = self.URI

        while uri.startswith("/"):
            uri = uri[1:]
        self._uri = uri

    def encode(self, *args, **kwargs):
        return f"{self._uri}".format(*args, **kwargs)

class GetPemKey(Endpoint):
    URI = "/api/webCgi/GetPemKey"

class GetWebConfig(Endpoint):
    URI = "/api/webCgi/GetWebConfig"

class Login(Endpoint):
    URI = "/api/userLoginCgi/userLogin"

