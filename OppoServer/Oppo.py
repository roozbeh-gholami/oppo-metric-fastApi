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

import os
import json
import time
import random
import hashlib
import requests
import pickle
from base64 import b64decode, b64encode
from binascii import hexlify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from . import endpoints as ep

class OppoServer:
    SESSION_FILE = "session.pkl"
    ACCESS_FILE = "access.pkl"
    TOKEN_TIMEOUT = 1

    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.key = os.urandom(32)
        self.iv = os.urandom(32)
        self.rsa_pubkey = self._get_rsa_public_key()
        self.aes_key_enc = self._encrypt_aes_key()
        self.__access = {
            'last_post': 0,
        }
        try:
            with open(OppoServer.SESSION_FILE, 'rb') as f:
                self.session.cookies.update(pickle.load(f))
        except FileNotFoundError:
            pass
        try:
            with open(OppoServer.ACCESS_FILE, 'rb') as f:
                d = pickle.load(f)
                self.__access['last_post'] = d['last_post']
        except FileNotFoundError:
            pass
        try:
            self.login()
        except ValueError as e:
            raise ValueError(f"Failed to login: {e}")
        with open(OppoServer.SESSION_FILE, 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def _get_rsa_public_key(self):
        response = self.session.get(f"{self.base_url}/api/webCgi/GetPemKey")
        response.raise_for_status()
        pem_data = response.json().get('data', {}).get('pem')
        if pem_data is None:
            raise ValueError("Failed to retrieve PEM key from the server.")
        return load_pem_public_key(pem_data.encode())

    def _encrypt_aes_key(self):
        combined_key = self.key + b'.' + self.iv
        encrypted_key = self.rsa_pubkey.encrypt(
            combined_key,
            OAEP(mgf=MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        )
        return b64encode(encrypted_key).decode()

    def _generate_jwt(self):
        header = {"type": "JWT", "alg": "HS256"}
        payload = {
            "username": self.username,
            "iat": str(int(time.time()))
        }
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv[:len(self.iv) // 2]))
        encryptor = cipher.encryptor()
        header_encoded = b64encode(json.dumps(header).encode()).decode()
        payload_encoded = b64encode(json.dumps(payload).encode()).decode()
        data_to_encrypt = json.dumps({'header': header_encoded, 'payload': payload_encoded})
        ciphertext = encryptor.update(data_to_encrypt.encode()) + encryptor.finalize()
        return b64encode(ciphertext).decode()

    def _build_plain_payload(self, data):
        random_token = ''.join(str(random.randint(0, 9)) for _ in range(16))
        return {
            'data': data,
            'randomToken': random_token,
        }, random_token

    def _encrypt_data(self, data):
        payload, random_token = self._build_plain_payload(data)

        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv[:len(self.iv) // 2]))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json.dumps(payload).encode()) + encryptor.finalize()
        return b64encode(ciphertext).decode(), random_token

    def _calculate_sha256(self, data, random_token, jwt):
        return hashlib.sha256((data + random_token + jwt).encode()).digest()

    def __private_post(self, ep, *args, **kwargs):
        if (len(args) > 0):
            data = args[0]
        else:
            data = dict(kwargs)
        if (not ep.PLAIN):
            encrypted_data, random_token = self._encrypt_data(data)
            jwt = self._generate_jwt()
            checksum = self._calculate_sha256(encrypted_data, random_token, jwt)

            post_payload = {
                'AES': self.aes_key_enc,
                'JWT': jwt,
                'data': encrypted_data,
                'sum': hexlify(checksum).decode(),
            }
        else:
            data['flag'] = 1
            post_payload, _ = self._build_plain_payload(data)

        uri = ep().uri()
        while uri.startswith("/"):
            uri = uri[1:]
        url =  f"{self.base_url}/{uri}"
        response = self.session.post(url, json=post_payload)
        if (response.status_code not in [200, 401]):
            response.raise_for_status()
        if (response.status_code == 401):
            self.login()
        self.__access['last_post'] = time.time()

        try:
            jresp = response.json()
        except json.JSONDecodeError:
            resp = self._decrypt_response(response.text)
            jresp = json.loads(resp)
        if (jresp.get('code', 1) != 0):
            raise ValueError(f"Error code: {jresp.get('code', 1)}")
        data = jresp.get('data', {})
        if ('ErrorCode' in data and data.get('ErrorCode', 1) != 0):
            raise ValueError(f"Error code: {data.get('ErrorCode', 1)}")
        return data

    def _post(self, _ep, *args, **kwargs):
        return self.__private_post(_ep, *args, **kwargs)

    def _decrypt_response(self, encrypted_response):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv[:len(self.iv) // 2]))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(b64decode(encrypted_response)) + decryptor.finalize()
        return decrypted_data

    def batch(self, endpoints):
        batch = []
        for cls in endpoints:
            if cls is not ep.Endpoint and cls is not ep.BatchRequest:
                batch.append(cls().batch())
        return self._post(ep.BatchRequest, batch)

    def is_logged(self):
        return self._post(ep.IsLogin)

    def login(self):
        resp = self.is_logged()
        if (resp.get('isLogin', 0) == 0):
            return self._post(ep.Login, username=self.username, password=hashlib.sha256(self.password.encode()).hexdigest())
        return True

    def webconfig(self):
        return self._post(ep.GetWebConfig)

    def token_status(self):
        return self._post(ep.TokenStatus)
