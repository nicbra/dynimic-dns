import base64
import certifi
import urllib3
from time import sleep
from dotenv import load_dotenv
import os
import json
import logging

class Client:
    def __init__(self, token: str, secret: str):
        """
        See the documentation at https://api.domeneshop.no/docs/ for
        help on how to acquire your API credentials.

        :param token: The API client token
        :type token: str
        :param secret: The API client secret
        :type secret: str

        """

        self._headers = {
            "Authorization": "Basic {}".format(
                base64.b64encode("{}:{}".format(token, secret).encode()).decode()
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "domeneshop-python/0.4.4",
        }
        self._http = urllib3.HTTPSConnectionPool(
            "api.domeneshop.no",
            443,
            maxsize=5,
            block=True,
            headers=self._headers,
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
        )

    def update_ddns(self, hostname: str, ip: str) -> None:
        """
        Update DNS
        """
        resp = self._request("GET", "/dyndns/update", fields = {'hostname': hostname, 'myip': ip})
        return

    def _request(self, method="GET", endpoint="/", data=None, fields=None):
        if data is not None:
            data = json.dumps(data).encode("utf-8")
        try:
            resp = self._http.request(method, "/v0" + endpoint, body=data, fields=fields)
            if resp.status >= 400:
                try:
                    data = json.loads(resp.data.decode("utf-8"))
                except json.JSONDecodeError:
                    data = {"error": resp.status, "help": "A server error occurred."}
                raise DomeneshopError(resp.status, data) from None
        except urllib3.exceptions.HTTPError as e:
            raise e
        else:
            return resp

class DomeneshopError(Exception):
    def __init__(self, status_code: int, error: dict):
        """
        Exception raised for API errors.

            :param status_code: The HTTP status code
            :type status_code: int
            :param error: The error returned from the API
            :type error: dict
        """
        self.status_code = status_code
        self.error_code = error.get("code")
        self.help = error.get("help")

        error_message = "{0} {1}. {2}".format(
            self.status_code, self.error_code, self.help
        )

        super().__init__(error_message)

def get_public_ip():
    resp = urllib3.request('GET', 'https://ifconfig.me/ip')
    if (resp.status == 200):
        return resp.data.decode('utf-8')
    else:
        raise Exception(f"Failed to get IP. Status: {resp.status}.")


logging.basicConfig(format='[%(asctime)s] %(levelname)s:%(message)s')
logger = logging.getLogger('domeneshop')
logger.setLevel(logging.DEBUG)

def main():
    load_dotenv()
    TOKEN = os.getenv('TOKEN')
    SECRET = os.getenv('SECRET')
    ADDRESS = os.getenv('ADDRESS')

    client = Client(TOKEN, SECRET)
    ip_address = ''

    while True:
        try:
            current_ip = get_public_ip()
        except Exception as e:
            logger.error(f"Error getting IP: {e}")
            
        if (current_ip != ip_address):
            ip_address = current_ip
            logger.info(f'Updating IP to {ip_address}')
            try:
                client.update_ddns(ADDRESS, ip_address)
            except Exception as e:
                logger.error(f"An error occurred: {e}")

        sleep(60*5)    # 5 minutes

if __name__ == '__main__':
    main()