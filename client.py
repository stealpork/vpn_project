import os
import fcntl
import struct
import subprocess
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, rsa
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
import os
import threading
import json


class TUN:
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, dev_name="tun1"):
        self.dev_name = dev_name
        self.tun_fd = self.create_tun_device()
        self.configure_tun()

    def create_tun(self):
        try:
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", self.dev_name.encode(), self.IFF_TUN | self.IFF_NO_PI)
            fcntl.ioctl(tun_fd, self.TUNSETIFF, ifr)
            print(f"TUN device {self.dev_name} created")
            return tun_fd
        except Exception as e:
            print(f"Error creating TUN device: {e}")
            raise

    def configure_tun(self, ip="10.0.0.2", netmask="255.255.255.0"):
        try:
            subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", self.dev_name], check=True)
            subprocess.run(["ip", "link", "set", "dev", self.dev_name, "up"], check=True)
            print(f"TUN device {self.dev_name} configured with IP {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Error configuring TUN device: {e}")
            raise

    def read(self, buffer_size=4096):
        return os.read(self.tun_fd, buffer_size)

    def write(self, data):
        os.write(self.tun_fd, data)

    def close(self):
        try:
            os.close(self.tun_fd)
            print(f"TUN device {self.dev_name} closed")
        except Exception as e:
            print(f"Error closing TUN device: {e}")


class Encryption():
    def __init__(self, aes_key):
        self.aes_key = aes_key
        self.backend = default_backend()

    def encrypt_aes(self, data):
        if not data:
            raise ValueError("Data to encrypt cannot be empty.")
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted_data
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def decrypt_aes(self, data):
        try:
            if len(encrypted_data) < 16:
                raise ValueError("Encrypted data is too short to contain a valid IV.")
            iv = encrypted_data[:16]  # First 16 bytes are the IV
            encrypted_data = encrypted_data[16:]  # The rest is the encrypted data
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_data) + unpadder.finalize()
            return data
        except ValueError as e:
            print(f"Decryption error (likely invalid padding or corrupted data): {e}")
            return None
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def encrypt_rsa(self, rsa, data):
        try:
            encrypted_aes = rsa.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )   
            )
            return encrypted_aes
        except Exception as e:
            print(f"Decryption error: {e}")
            return None


class Client:
    def __init__(self, ip, port):
        self.addr = (ip, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(100000)
        self.aes_key = os.urandom(32)
        self.enc = Encryption(self.aes_key)
        self.tun = TUN()
        self.cleaned_up = False
    
    def connect_to(self):
        try:
            self.sock.connect(self.addr)
            print(f"Подключено к серверу по адресу: {self.addr}")
            rsa_key = self.sock.recv(4096)
            encr_aes = self.enc.encrypt_rsa(rsa_key, self.aes_key)
            self.sock.sendall(encr_aes)
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            self.cleanup()
            exit(1)
    
    def handle_server(self):
        try:
            while True:
                encrypted_data = self.sock.recv(4096)
                if not encrypted_data:
                    print("Disconnected from server")
                    break
                decrypted_data = self.enc.decrypt(encrypted_data)
                if decrypted_data:
                    self.tun.write(decrypted_data)
        except Exception as e:
            print(f"Error receiving data from server: {e}")
        finally:
            self.cleanup()

    def handle_tun(self):
        try:
            while True:
                packet = self.tun.read()
                encrypted_packet = self.enc.encrypt(packet)
                if encrypted_packet:
                    self.sock.send(encrypted_packet)
        except Exception as e:
            print(f"Error sending data to server: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        if self.cleaned_up:
            return
        self.cleaned_up = True

        try:
            if self.tun:
                self.tun.close()
            if self.sock:
                self.sock.close()
        except Exception as e:
            print(f"Ошибка при отключении: {e}")
        print("Все лишние подключения отключены")
    
    def start(self):
        self.connect_to()
        server_thread = threading.Thread(target=self.handle_server, daemon=True)
        tun_thread = threading.Thread(target=self.handle_tun, daemon=True)
        server_thread.start()
        tun_thread.start()
        server_thread.join()
        tun_thread.join()


if __name__ == "__main__":
    with open("client/config.json", "r") as config_file:
        config = json.load(config_file)
    ip = config["server_ip"]
    port = config["server_port"]
    client = Client(ip, port)
    client.start()