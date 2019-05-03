from flask import Flask, redirect, url_for, request
from cert_utils import *
from cryptography.hazmat.primitives import serialization

import os

app = Flask(__name__)


@app.route('/get_client_gammal_cert', methods=['POST'])
def get_gammal_cert():
    input_json = request.get_json(force=True)
    client_id = input_json["id"]
    receiver_id = input_json["receiver"]
    receiver_cert = cert_load(
        curr_dir_path + "/database/client_" + receiver_id + "_gammal_cert.pem")
    print(" Received request for gammal certificate from: ", client_id)
    return cert_to_bytes(receiver_cert)


@app.route('/get_client_key_cert', methods=['POST'])
def get_rsa_cert():
    input_json = request.get_json(force=True)
    client_id = input_json["id"]
    receiver_id = input_json["receiver"]
    receiver_cert = cert_load(
        curr_dir_path + "/database/client_" + receiver_id + "_key_cert.pem")
    print(" Received request for RSA certificate from: ", client_id)
    return cert_to_bytes(receiver_cert)


@app.route('/generate_gammal_cert', methods=['POST'])
def generate_gammal_cert():
    input_json = request.get_json(force=True)
    client_id = input_json["id"]
    client_gammal_key = input_json["public_key"]
    print(" New client of id", client_id, " with gammal_key: ", client_gammal_key)
    fake_gammal_key = FakePublicKey(client_gammal_key)
    client_gammal_key = fake_gammal_key.get_key()
    client_cert = cert_build_signed(ca_private_key, client_gammal_key, client_id)
    cert_write(curr_dir_path + "/database/client_" + client_id + "_gammal_cert.pem", client_cert)
    return "ok"


@app.route('/generate_key_cert', methods=['POST'])
def generate_key_cert():
    input_json = request.get_json(force=True)
    # print(input_json["public_key"])
    client_id = input_json["id"]
    client_public_key_bytes = str.encode(input_json["public_key"])
    client_public_key = public_key_from_bytes(client_public_key_bytes)

    print(" New client of id", client_id, " with cert_public_key: ", client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    client_cert = cert_build_signed(ca_private_key, client_public_key, client_id)
    cert_write(curr_dir_path + "/database/client_" + client_id + "_key_cert.pem", client_cert)

    # print(input_json)
    return "ok"


if __name__ == "__main__":
    curr_dir_path = os.path.dirname(os.path.realpath(__file__))  # Get current directory
    exists = os.path.isfile(curr_dir_path + '/ca/ca_public_key.pem')
    exists = exists and os.path.isfile(curr_dir_path + '/ca/ca_private_key.pem')

    if exists:
        print("CA public & private key already exists, loading existing keys")
        ca_private_key = private_key_load(curr_dir_path + '/ca/ca_private_key.pem')
        ca_public_key = public_key_load(curr_dir_path + '/ca/ca_public_key.pem')
    else:
        print("CA public and/or private don't exists, creating new keys")
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())  # Generate private key for CA.

        ca_public_key = ca_private_key.public_key()  # Generate public key for CA.

        public_key_write(curr_dir_path + '/ca/ca_public_key.pem', ca_public_key)  # Writing ca public key.
        private_key_write(curr_dir_path + '/ca/ca_private_key.pem', ca_private_key)  # Writing ca private key.

    app.run(debug=True)
