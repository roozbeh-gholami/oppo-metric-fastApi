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
from base64 import b64decode, b64encode
from binascii import hexlify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from . import endpoints as ep

class OppoServer:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.key = os.urandom(32)
        self.iv = os.urandom(32)
        self.rsa_pubkey = self._get_rsa_public_key()
        self.aes_key_enc = self._encrypt_aes_key()

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

    def _encrypt_data(self, data):
        random_token = ''.join(str(random.randint(0, 9)) for _ in range(16))
        payload = {
            'data': data,
            'randomToken': random_token,
        }
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv[:len(self.iv) // 2]))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json.dumps(payload).encode()) + encryptor.finalize()
        return b64encode(ciphertext).decode(), random_token

    def _calculate_sha256(self, data, random_token, jwt):
        return hashlib.sha256((data + random_token + jwt).encode()).digest()

    def _post(self, uri, *args, **kwargs):
        if (len(args) > 0):
            data = args[0]
        else:
            data = dict(kwargs)
        encrypted_data, random_token = self._encrypt_data(data)
        jwt = self._generate_jwt()
        checksum = self._calculate_sha256(encrypted_data, random_token, jwt)

        post_payload = {
            'AES': self.aes_key_enc,
            'JWT': jwt,
            'data': encrypted_data,
            'sum': hexlify(checksum).decode(),
        }

        uri = uri().encode()
        while uri.startswith("/"):
            uri = uri[1:]
        url =  f"{self.base_url}/{uri}"
        response = self.session.post(url, json=post_payload)
        response.raise_for_status()

        try:
            return response.json()
        except json.JSONDecodeError:
            resp = self._decrypt_response(response.text)
            jresp = json.loads(resp)
            if (jresp.get('code', 1) != 0):
                raise ValueError(f"Error code: {jresp.get('code', 1)}")
            return jresp.get('data', {})

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

    def login(self):
        return self._post(ep.Login, username=self.username, password=hashlib.sha256(self.password.encode()).hexdigest())

    def webconfig(self):
        return self._post(ep.GetWebConfig)
