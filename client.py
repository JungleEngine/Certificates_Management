from cert_utils import *
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, redirect, url_for, request
import threading

app = Flask(__name__)
import requests
import argparse


@app.route('/msg', methods=['POST'])
def receive_message():
    input_json = request.get_json(force=True)

    encrypted_message = input_json["msg"]
    signed_message = encrypted_message  # Decrypt the message.
    valid_public_key = True
    valid_signature = True  # TODO: check the signature

    print("Message received from: ", input_json["id"])
    if valid_signature:
        print("Valid signature")

    if valid_public_key:
        print("Valid public key")

    if valid_signature and valid_public_key:
        print("Message:", signed_message)
    return "ok"


def send_message(message, url):
    client_data = {'id': client_id,
                   'msg': message
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
                   'public_key': gammal_public_key}
    requests.post(ca_url + "/generate_gammal_cert", json=client_data)

def send_loop():
    while True:
        message = input(" write message to send to client: " + other_client_url +
                        " | write exit to exit\n")  # Message to send.
        if message == "exit":
            return

        signed_message = message  # TODO: get the message signed
        encrypted_message = signed_message  # TODO: get the message encrypted

        send_message(encrypted_message, other_client_url)
        print(" Message sent")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="your port")
    parser.add_argument("-op", "--otherport", help="receiver port")
    parser.add_argument("-id", "--name", help="your id")
    args = parser.parse_args()

    other_client_url = 'http://127.0.0.1:' + args.otherport
    client_id = args.name
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())  # Generate private key for client.

    client_public_key = client_private_key.public_key()  # Generate public key for client.

    ca_url = 'http://127.0.0.1:5000'

    gammal_private_key = 11
    gammal_public_key = 15  # Must be odd.

    print(" Sending ", client_id, " data to CA")
    publish_client_data_to_ca(ca_url)

    sending_thread = threading.Thread(target=send_loop)
    sending_thread.start()
    app.run(debug=True, port=args.port)
