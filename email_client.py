import socket
import dotenv
import os
import pickle
import rsa
import random

#  Application Layer Protocol:
# |   4 bytes    |     4 bytes    |  8 bytes    |  64 bytes  | x bytes | y bytes | z bytes |
# | email length | subject length | data length |  magic rsa |  email  | subject |  data   |

# Loads environment variables from .env file
dotenv.load_dotenv()

# Sets global variables
MAGIC = None
RSA_PUB_KEY = None

# Reads current magic number from file
with open(os.getenv('MAGIC_FILE')) as f:
    MAGIC = f.read()

# Reads RSA public key from file
with open(os.getenv('RSA_PUB_KEY_FILE')) as f:
    RSA_PUB_KEY = pickle.load(f.read())

class EmailClient():
    """
    This class is used to tell a server to send an email.
    """
    def __init__(self):
        self.socket = None

    def connect(self, address, port):
        """
        Connects to a server

        Args:
            address (string): The address of the server
            port (int): The port of the server
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((address, port))
        self.socket.settimeout(0.5)

    def close(self):
        """
        Closes the socket
        """
        self.socket.close()

    def update_magic(self):
        """Updates magic number that validates packets
        """
        global MAGIC

        random.seed(MAGIC)
        with open(os.getenv('MAGIC_FILE'), 'w') as f:
            f.write(random.randbytes(63))

    def receive(self):
        """Receives server responses. Dictates whether to upate magic number or not.
        """
        data = None
        while data != b"d":
            data = self.socket.recv(1)
            
            if data == b"u":
                self.update_magic()

    def send(self, email, subject, data):
        """Sends request to server

        Args:
            email (string): The email address of the sender
            subject (string): The subject of the email
            data (string): The contents of the email
        """
        packet = b""
        packet += socket.htons(len(email))
        packet += socket.htons(len(subject))
        packet += socket.htonl(len(data))
        packet += rsa.encrypt(MAGIC.encode(), RSA_PUB_KEY)
        packet += email.encode()
        packet += subject.encode()
        packet += data.encode()
        self.socket.send(packet)

        self.receive()