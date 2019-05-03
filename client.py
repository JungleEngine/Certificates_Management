from Gamal import *
from cert_utils import *
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, redirect, url_for, request
import threading
import os
import base64

app = Flask(__name__)
import requests
import argparse
from base64 import b64encode, b64decode


@app.route('/msg', methods=['POST'])
def receive_message():
    input_json = request.get_json(force=True)

    encrypted_message = input_json["msg"]
    sig_r = input_json["sig_r"]
    sig_s = input_json["sig_s"]
    sender_id = input_json["id"]

    message = private_key_decrypt(encrypted_message, client_private_key)  # Decrypt the message.

    print(" Requesting certificates for user: ", sender_id)

    client_data = {'id': client_id,
                   'receiver': sender_id}

    res = requests.post(ca_url + "/get_client_key_cert", json=client_data)

    receiver_cert = cert_from_bytes(str.encode(res.text))
    valid_cert = cert_validate_signature(receiver_cert, ca_public_key)  # Validate cert.
    if valid_cert:
        print("RSA public key cert received from CA for receiver: ", client_data["receiver"],
              " is valid")
    else:
        print("RSA public key cert received from CA for receiver: ", client_data["receiver"],
              " is invalid")
        return

    res = requests.post(ca_url + "/get_client_gammal_cert", json=client_data)
    receiver_cert = cert_from_bytes(str.encode(res.text))
    valid_cert = cert_validate_signature(receiver_cert, ca_public_key)  # Validate cert.
    if valid_cert:
        print("Gammal public key cert received from CA for receiver: ", client_data["receiver"],
              " is valid")
    else:
        print("Gammal public key cert received from CA for receiver: ", client_data["receiver"],
              " is invalid")
        return
    gammal_fake_pub_key = cert_get_pub_key(receiver_cert)
    gammal_pub_key = get_fake_key_val(gammal_fake_pub_key)
    valid_signature = verifyElGamalSignature(gammal_pub_key, sig_r, sig_s, message)

    print("Message received from: ", sender_id)
    if valid_signature:
        print("Valid signature of: ", sender_id)
    else:
        print("Invalid signature")
        return "no"

    if valid_signature:
        print("Message:", message)
    return "ok"


def send_message(message, url):
    """
    Get receiver certificate, validate it, encrypts the message with it and then send it.
    """
    client_data = {'id': client_id,
                   'receiver': other_client_id}
    res = requests.post(ca_url + "/get_client_key_cert", json=client_data)

    receiver_cert = cert_from_bytes(str.encode(res.text))
    valid_cert = cert_validate_signature(receiver_cert, ca_public_key)  # Validate cert.
    if valid_cert:
        print("RSA public key cert received from CA for receiver: ", client_data["receiver"],
              " is valid")
    else:
        print("RSA public key cert received from CA for receiver: ", client_data["receiver"],
              " is invalid")
        return

    receiver_public_key = cert_get_pub_key(receiver_cert)
    encrypted_message = public_key_encrypt(message, receiver_public_key)
    rr, ss = generateElGamalSignature(sig_priv, message)  # signature.

    client_data = {'id': client_id,
                   'msg': encrypted_message,
                   "sig_r": rr,
                   "sig_s": ss
                   }
    requests.post(url + "/msg", json=client_data)

def publish_client_data_to_ca(ca_url):
    # Generating certificate for rsa public key.
    client_data = {'id': client_id,
                   'public_key': client_public_key.public_bytes(
                       encoding=serialization.Encoding.PEM,
                       format=serialization.PublicFormat.SubjectPublicKeyInfo,
                   )}
    requests.post(ca_url + "/generate_key_cert", json=client_data)

    # Generating certificate for el gammal public key.
    client_data = {'id': client_id,
                   'public_key': sig_pub_key}
    requests.post(ca_url + "/generate_gammal_cert", json=client_data)

def send_loop():
    while True:
        message = input(" write message to send to client: " + other_client_url +
                        " | write exit to exit\n")  # Message to send.
        if message == "exit":
            return
        send_message(message, other_client_url)
        print(" Message sent")

if __name__ == "__main__":
    sig_priv, sig_pub_key = generateElGamalKey()

    curr_dir_path = os.path.dirname(os.path.realpath(__file__))  # Get current directory
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="your port")
    parser.add_argument("-op", "--otherport", help="receiver port")
    args = parser.parse_args()

    ca_public_key = public_key_load(curr_dir_path + "/ca/ca_public_key.pem")

    other_client_id = args.otherport
    other_client_url = 'http://127.0.0.1:' + args.otherport
    client_id = args.port
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())  # Generate private key for client.
    client_public_key = client_private_key.public_key()  # Generate public key for client.
    ca_url = 'http://127.0.0.1:5000'
    print(" Sending ", client_id, " data to CA")
    publish_client_data_to_ca(ca_url)

    sending_thread = threading.Thread(target=send_loop)
    sending_thread.start()
    app.run(port=args.port)
