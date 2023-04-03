import ssl
import datetime
import socket

url = 'https://bitdefender.com'
host = url.split('/')[2]
path = '/' + '/'.join(url.split('/')[3:])

context = ssl.create_default_context()
with socket.create_connection((host, 443)) as sock:
  with context.wrap_socket(sock, server_hostname=host) as ssock:
    cert = ssock.getpeercert()
    print(cert)