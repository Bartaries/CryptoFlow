import socket
import threading
import os
import logging
from crypto_utils import generate_keys, get_public_key_bytes, encrypt_message, decrypt_message, encrypt_session_key, decrypt_session_key
from cryptography.hazmat.primitives import serialization

log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.log')
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PRIVATE_KEY = generate_keys()
PUBLIC_KEY_PEM = get_public_key_bytes(PRIVATE_KEY)
SESSION_KEY = None

def receive_messages(client_socket):
    global SESSION_KEY
    while True:
        try:
            data = client_socket.recv(4096)
            if not data: break
            
            if SESSION_KEY is None:
                if len(data) > 400:
                    logging.info("Received partner's public key.")
                    partner_pub_key = serialization.load_pem_public_key(data)
                    SESSION_KEY = os.urandom(32)
                    encrypted_sk = encrypt_session_key(SESSION_KEY, partner_pub_key)
                    client_socket.send(encrypted_sk)
                    logging.info("Generated and sent session key.")
                else:
                    SESSION_KEY = decrypt_session_key(data, PRIVATE_KEY)
                    logging.info("Received and decrypted session key.")
            else:
                decrypted_msg = decrypt_message(data, SESSION_KEY)
                print(f"\nPartner: {decrypted_msg}")
        except Exception as e:
            logging.error(f"Communication error: {e}")
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5555))
    
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.daemon = True
    thread.start()

    init = input("Do you want to send your public key to start? (y/n): ")
    if init.lower() == 'y':
        client.send(PUBLIC_KEY_PEM)
        logging.info("Sent own public key.")
        print("Waiting for session key from partner...")
    
    while SESSION_KEY is None:
        pass

    print("Secure channel established. You can start chatting.")

    while True:
        msg = input("")
        if msg.lower() == 'exit':
            break
        client.send(encrypt_message(msg, SESSION_KEY))

if __name__ == "__main__":
    start_client()