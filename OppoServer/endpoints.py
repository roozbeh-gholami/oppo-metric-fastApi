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
    DATA = {}
    NAME = None

    def __init__(self, uri=None):
        if (not uri):
            uri = self.URI

        while uri.startswith("/"):
            uri = uri[1:]
        self._uri = f"/api/{uri}"

    def encode(self, *args, **kwargs):
        return f"{self._uri}".format(*args, **kwargs)

    def batch(self):
        parts = self._uri[1:].split("/")
        return {
            "apiService": parts[1],
            "apiName": parts[2],
            "data": self.DATA,
            "name": self.NAME if self.NAME else f"{parts[1]}{parts[2]}",
        }

class GetPemKey(Endpoint):
    URI = "/webCgi/GetPemKey"

class GetWebConfig(Endpoint):
    URI = "/webCgi/GetWebConfig"

class Login(Endpoint):
    URI = "/userLoginCgi/userLogin"

class NASSignalInfo(Endpoint):
    URI = "/NasMng/GetSignal"

class NASNetworkStatus(Endpoint):
    URI = "/NasMng/GetSysInfo"

class NASServiceStatus(Endpoint):
    URI = "/NasMng/GetCellInfo"

class NASCAInfo(Endpoint):
    URI = "/NasMng/GetCaInfo"

class NASInfo(Endpoint):
    URI = "/NasMng/GetSysInfo"

class NASBandInfo(Endpoint):
    URI = "/NasMng/GetBandInfo"

class IPv6Info(Endpoint):
    URI = "/DialupMng/GetIPv6Status"
    DATA = {
        "CId": 1
    }

class IPv4Info(Endpoint):
    URI = "/DialupMng/GetStatus"
    DATA = {
        "CId": 1
    }
    NAME = "Ipv4Addr"

class SimStatus(Endpoint):
    URI = "/SimService/GetStatus"

class SimInfo(Endpoint):
    URI = "/SimService/GetInfo"

class CheckConflict(Endpoint):
    URI = "/NetLan/CheckConflict"

class Mac(Endpoint):
    URI = "/NetLan/GetMac"

class WifiEnable(Endpoint):
    URI = "/Wifi/GetEnable"

class WifiStatus(Endpoint):
    URI = "/Wifi/GetStatus"

class Wifi5gPerfConfig(Endpoint):
    URI = "/Wifi/Get5gPerfConfig"

class WifiGuestConfig(Endpoint):
    URI = "/Wifi/GetGuestConfig"

class WifiDeviceConfig(Endpoint):
    URI = "/Wifi/GetDevConfig"

class WifiIfaceConfig(Endpoint):
    URI = "/Wifi/GetIfaceConfig"

class WifiDetectWifi(Endpoint):
    URI = "/Wifi/DetectWifi"

class NetConnectivity(Endpoint):
    URI = "/NetWan/CheckNetConnectivity"

class NetStatus(Endpoint):
    URI = "/NetWan/GetNetConnectivity"

class WanType(Endpoint):
    URI = "/NetWan/GetWanType"

class BatchRequest(Endpoint):
    URI = "/webCgi/BatchRequest"

class RefreshToken(Endpoint):
    URI = "/webCgi/refreshtoken"

class TokenStatus(Endpoint):
    URI = "/webCgi/checkTokenStatus"

class DiagStatus(Endpoint):
    URI = "/userLoginCgi/GetDiagStatus"

class IsLogin(Endpoint):
    URI = "/webCgi/isLogin"

class DeviceInfo(Endpoint):
    URI = "/ommng/GetDeviceInfo"
    NAME = "deviceInfo"

class SysInfo(Endpoint):
    URI = "/ommng/GetSysInfo"
    DATA = {
        "CpuInfo": 0
    }

class Version(Endpoint):
    URI = "/UpgMng/QueryVersion"

class EthWanStatus(Endpoint):
    URI = "/EthWan/GetStatus"

class EthStats(Endpoint):
    URI = "/EthWan/GetStats"

class NetStats(Endpoint):
    URI = "/NetStats/GetStats"
    DATA = {
        "Interface": "rmnet_data0"
    }