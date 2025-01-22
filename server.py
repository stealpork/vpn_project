import os
import fcntl
import struct
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import socket
import threading
import json
import signal
import sys


class TUN:
    TUNSETIFF = 0x400454ca #позволяет настраивать tun
    IFF_TUN = 0x0001 #указывает, что это tun-интерфейс
    IFF_NO_PI = 0x1000 #интерфейс не добавляет инфомацию о заголовке протокола

    def __init__(self, dev_name="tun0"):
        self.dev_name = dev_name
        self.tun_fd = None
        try:
            self.tun_fd = self.create_tun()
        except Exception as e:
            print(f"Ошибка инициализации TUN-интерфейса: {e}")
            self.close()

    def create_tun(self):
        try:
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", self.dev_name.encode(), self.IFF_TUN | self.IFF_NO_PI)
            fcntl.ioctl(tun_fd, self.TUNSETIFF, ifr)
            print(f"TUN-интерфейс был создан")
            return tun_fd
        except FileNotFoundError:
            raise RuntimeError("TUN/TAP-интерфейс не был найден. Проверьте, существуют ли он.")
        except PermissionError:
            raise RuntimeError("Недостаточно прав. Запустите от имени супер-пользователя")
        except Exception as e:
            raise RuntimeError(f"Неожиданная ошибка в процессе создания интерфейса: {e}")

    def configure_tun(self, ip="10.0.0.1", netmask="255.255.255.0"):
        try:
            subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", self.dev_name], check=True)
            subprocess.run(["ip", "link", "set", "dev", self.dev_name, "up"], check=True)
            print(f"TUN-интерфейс {self.dev_name} был настроен соответственно IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Ошибка настройки TUN-интерфейса: {e}")

    def read(self, buffer_size=4096):
        try:
            return os.read(self.tun_fd, buffer_size)
        except OSError as e:
            print(f"Ошибка чтения: {e}")
            return b""

    def write(self, data):
        try:
            os.write(self.tun_fd, data)
        except OSError as e:
            print(f"Ошибка записи: {e}")

    def close(self):
        if self.tun_fd:
            try:
                os.close(self.tun_fd)
                print(f"TUN-интерфейс {self.dev_name} выключен")
            except OSError as e:
                print(f"Ошибка при закрытии интерфейса: {e}")


class Encryption:
    def __init__(self, rsa_key, enc_aes_key):
        self.aes = self.decrypt_using_rsa(rsa_key, enc_aes_key)
        self.backend = default_backend()
    
    def encrypt_aes(self, data):
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.aes), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted_data
        except Exception as e:
            print(f"Непредвиденная ошибка в шифровании данных: {e}")
            return None
    
    def decrypt_aes(self, data):
        try:
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(self.aes), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_data) + unpadder.finalize()
            return data
        except ValueError as e:
            print(f"Ошибка дешифрования (скорее всего паддинг): {e}")
            return None
        except Exception as e:
            print(f"Ошибка дешифрования: {e}")
            return None
        
    def decrypt_using_rsa(self, pr_rsa, enc_aes):
        try:
            dec_aes = pr_rsa.decrypt(
                enc_aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return dec_aes
        except Exception as e:
            print(f"Ошибка дешифрования: {e}")
            return None
        
    
class Server():
    def __init__(self, ip, port):
        self.address = (ip, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.bind(self.address)
        except OSError as e:
            print(f"Ошибка запуска сервера на адресе {self.server_address}: {e}")
            sys.exit(1)

        self.sock.listen(5)
        self.rsa = self.generate_rsa()
        self.aes_enc = ''
        self.tun = TUN(dev_name="tun0")
    
    def generate_rsa(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return(public_key, private_key)
    
    def accept(self):
        print("Ождиание подключений....")
        client_sock, client_address = self.sock.accept()
        print(f"Подключен {client_address}")
        client_sock.sendall(self.rsa[0]) #публичный ключ rsa
        enc_aes = client_sock.recv(1024) #зашифрованный ключ aes
        return (client_sock, enc_aes)
    
    def handle_traffic(self, client_sock, enc_aes):
        try:
            self.aes_enc = Encryption(self.rsa[-1], enc_aes)
            while True:
                encrypted_data = client_sock.recv(4096)
                if not encrypted_data:
                    print("Клиент отключился")
                    break
                decrypted_data = self.encryption.decrypt_aes(encrypted_data)
                if decrypted_data is None:
                    print("Неудача во время дешифровании данны")
                    break
                self.tun.write(decrypted_data)
        except Exception as e:
            print(f"Ошибка получения данных от клиента: {e}")
        finally:
            client_sock.close()

    def tun_traffic(self, client_sock, enc_aes):
        try:
            self.aes_enc = Encryption(self.rsa[-1], enc_aes)
            while True:
                packet = self.tun.read()
                encrypted_packet = self.aes.encrypt_aes(packet)
                client_sock.send(encrypted_packet)
        except Exception as e:
            print(f"Ошибка отправки данных клиенту: {e}")
        finally:
            client_sock.close()

    def start(self):
        self.tun.configure_tun_device(ip="10.0.0.1")
        print("Сервер запущен и ожидает клиентов...")
        while True:
            try:
                info = self.accept()
                client_thread = threading.Thread(target=self.handle_traffic, args=(info[0], info[1]))
                tun_thread = threading.Thread(target=self.tun_traffic, args=(info[0], info[1]))
                client_thread.daemon = True
                tun_thread.daemon = True
                client_thread.start()
                tun_thread.start()
            except KeyboardInterrupt:
                print("Отключение сервера...")
                self.cleanup()
                break
    
    def clean(self):
        print("Отключение запущенных классов и подключений...")
        self.sock.close()
        self.tun.close()



if __name__ == "__main__":
    with open("server_config.json", "r") as config_file:
        config = json.load(config_file)
    ip = config["server_ip"]
    port = config["server_port"]
    server = Server(ip, port)
    def signal_handler(sig, frame):
        print("\nОтключение сервера...")
        server.cleanup()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    server.start()
