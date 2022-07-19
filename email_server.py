import socket
import smtplib
from email.mime.text import MIMEText
import dotenv
import os
import random
import pickle
import rsa

#  Application Layer Protocol:
# |   4 bytes    |     4 bytes    |  8 bytes    |  64 bytes  | x bytes | y bytes | z bytes |
# | email length | subject length | data length |  magic rsa |  email  | subject |  data   |

# Loads environment variables from .env file
dotenv.load_dotenv()

# Sets global variables
HOST = os.getenv('HOST')
LISTEN_PORT = 7071
SMTP_PORT = 25
MAGIC = None
RSA_PRIV_KEY = None
SENDER = os.getenv('SENDER')
RECEIVER = [os.getenv('RECEIVER')]

# Reads current magic number from file
with open(os.getenv('MAGIC_FILE')) as f:
    MAGIC = f.read()

# Reads current RSA private key from file
with open(os.getenv('RSA_PRIV_KEY_FILE', "rb")) as f:
    RSA_PRIV_KEY = pickle.load(f)

while True:
    # Creates empty data variables
    email = None
    subject = None
    data = None

    # Creates socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Binds to socket and waits for a connection
        s.bind((HOST, LISTEN_PORT))
        s.listen()
        conn, addr = s.accept()

        with conn:
            # Receives header data and validates length
            header_data = conn.recv(16)

            if len(header_data) != 16:
                print("Invalid header data")
                s.sendall(b"f")
                continue

            # Parses header data
            email_len = socket.ntohs(header_data[0:4])
            subject_len = socket.ntohs(header_data[4:8])
            data_len = socket.ntohl(header_data[8:16])

            # Decodes magic number and validates it
            magic = rsa.decrypt(conn.recv(64), RSA_PRIV_KEY).decode()

            if magic != MAGIC:
                print("Invalid magic number")
                # Tells client to update it's magic number
                s.sendall(b"u")
                s.sendall(b"f")
                continue

            # Updates magic number in file
            random.seed(MAGIC)
            MAGIC = random.randbytes(63)

            with open(os.getenv('MAGIC_FILE'), 'wb') as f:
                f.write(MAGIC)

            # Tells client to update it's magic number
            s.sendall(b"u")

        # Collects email and content data 
            email = conn.recv(email_len)
            subject = conn.recv(subject_len)
            data = conn.recv(data_len)

    if not email or not data:
        print("Invalid email or data")
        s.sendall(b"f")
        continue

    # Generates Message
    msg = MIMEText("A Message from the server")
    msg['Subject'] = subject.decode()
    msg["From"] = SENDER
    msg["To"] = email.decode("utf-8")

    # Sends email
    with smtplib.SMTP(HOST, SMTP_PORT) as server:
        server.sendmail(SENDER, RECEIVER, msg.as_string())
    
    s.sendall(b"d")