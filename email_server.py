import socket
import smtplib
from email.mime.text import MIMEText
import dotenv
import os
import random
import pickle
import rsa

#  Application Layer Protocol:
# |   4 bytes    |     4 bytes    |  4 bytes    |  64 bytes  | x bytes | y bytes | z bytes |
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
with open(os.getenv('MAGIC_FILE'), "rb") as f:
    MAGIC = f.read()

# Reads current RSA private key from file
with open(os.getenv('RSA_PRIV_KEY_FILE'), "rb") as f:
    RSA_PRIV_KEY = pickle.load(f)


# Creates socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Binds to socket and waits for a connection
    s.bind((HOST, LISTEN_PORT))

    while True:
        try:
            # Creates empty data variables
            email = None
            subject = None
            data = None

            s.listen()
            conn, addr = s.accept()

            with conn:
                # Receives header data and validates length
                header_data = conn.recv(12)

                if len(header_data) != 12:
                    print("Invalid header data")
                    conn.sendall(b"f")
                    conn.recv(1)
                    continue

                # Parses header data
                email_len = int.from_bytes(header_data[0:4], byteorder='big')
                subject_len = int.from_bytes(header_data[4:8], byteorder='big')
                data_len = int.from_bytes(header_data[8:12], byteorder='big')

                # Decodes magic number and validates it
                magic = rsa.decrypt(conn.recv(64), RSA_PRIV_KEY)

                # Collects email and content data 
                email = conn.recv(email_len)
                subject = conn.recv(subject_len)
                data = conn.recv(data_len)

                if magic != MAGIC:
                    print("Invalid magic number")
                    # Tells client to update it's magic number
                    conn.sendall(b"u")
                    conn.sendall(b"f")
                    conn.recv(1)
                    continue

                # Updates magic number in file
                random.seed(MAGIC)
                MAGIC = random.randbytes(53)

                with open(os.getenv('MAGIC_FILE'), 'wb') as f:
                    f.write(MAGIC)

                # Tells client to update it's magic number
                conn.sendall(b"u")

                if not email or not data:
                    print("Invalid email or data")
                    conn.sendall(b"f")
                    conn.recv(1)
                    continue

                # Generates Message
                msg = MIMEText(data.decode())
                msg['Subject'] = subject.decode()
                msg["From"] = SENDER
                msg["To"] = email.decode("utf-8")

                # Sends email
                with smtplib.SMTP(HOST, SMTP_PORT) as server:
                    server.sendmail(SENDER, RECEIVER, msg.as_string())

                conn.sendall(b"d")
                conn.recv(1)
        except ConnectionResetError as e:
            print(e)
            continue