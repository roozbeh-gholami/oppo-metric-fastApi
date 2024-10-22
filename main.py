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

import json
import hashlib
from OppoServer.Oppo import OppoServer
from credentials import *

def main():
    oppo = OppoServer(
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD
    )

    config_msg = oppo.webconfig()
    print(json.dumps(config_msg))

    login_msg = oppo.login()
    #print(login_msg)

if __name__ == "__main__":
    main()
