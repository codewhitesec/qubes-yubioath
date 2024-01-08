#!/usr/bin/env python3

from __future__ import annotations

import time
import hashlib
import argparse
import subprocess
import configparser

from pathlib import Path
from ykman.device import list_all_devices
from yubikit.core.otp import OtpConnection
from yubikit.oath import OathSession, Credential, Code
from yubikit.core.smartcard import SmartCardConnection


class MissingConfigException(Exception):
    '''
    Custom exception class.
    '''


class RofiAbortedException(Exception):
    '''
    Custom exception class.
    '''


def select_credential(creds: list[Credential], qube: str) -> Credential:
    '''
    Display rofi and display a list of credentials. Wait for the user to
    select a credential and use it as return value.

    Parameters:
        creds           list of credentials to display
        qube            target qube name

    Returns:
        User selected credential
    '''
    rofi_str = ''

    for cred in creds:

        issuer = cred.issuer or 'Unknown'

        line = issuer.ljust(20)
        line += cred.name

        try:
            icon_path = Path(Config.get(issuer))

            if icon_path.is_file():
                line += f'\x00icon\x1f{icon_path}'

        except KeyError:
            pass

        rofi_str += f'{line}\n'

    rofi_msg = f'OTP code is copied to <b>{qube}</b>:\n\n'
    rofi_msg += 'Issuer'.ljust(24)
    rofi_msg += 'Name'

    process = subprocess.Popen(['rofi'] + Config.get_rofi_options() + ['-mesg', rofi_msg],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    try:
        selected = process.communicate(input=rofi_str.encode())[0]
        selected = int(selected.decode().strip())

        if selected == -1:
            raise RofiAbortedException('User selected empty credentials')

        return creds[selected]
        
    except ValueError:
        raise RofiAbortedException('rofi selection was aborted by user')


def copy_code(code: Code, qube: str) -> None:
    '''
    Copy an OTP code to a qube.

    Parameters:
        code            the OTP code to copy
        qube            the qube to copy to

    Returns:
        None
    '''
    process = subprocess.Popen(['qrexec-client-vm', qube, 'custom.QubesKeepass'], stdin=subprocess.PIPE)
    process.stdin.write(code.value.encode())
    process.stdin.close()

    time_left = code.valid_to - int(time.time())
    subprocess.call(['notify-send', f'OTP code expires in {time_left} seconds.'])

class LastUsedCache:
    '''
    The LastUsedCache class is responsible for tracking which credentials were used most
    frequently. When smart_ordering is enabled, the most used credentials are displayed
    first. Moreover, a credential used within the last 30sec will always displayed first.
    '''

    def __init__(self, data: list[tuple]) -> None:
        '''
        Initialize the LastUsedCache object with a list of cached credentials. Each cached
        credential is represented by a tuple of (sha256(issuer-name-deviceid), usage-count,
        usage-time).

        Parameters:
            data            cached credential data

        Returns:
            None
        '''
        self.cached = []
        self.usage_data = {}
        self.timestamps = {}

        for tup in data:

            self.cached.append(tup[0])
            self.usage_data[tup[0]] = tup[1]
            self.timestamps[tup[0]] = tup[2]

    def put(self, cred: Credential) -> None:
        '''
        Put a new Credential into the cache.

        Parameters:
            cred            the credential to put in

        Returns:
            None
        '''
        cred_hash = LastUsedCache.hash(cred)

        if cred_hash not in self.cached:
            self.cached.append(cred_hash)
            self.usage_data[cred_hash] = 1

        else:
            self.usage_data[cred_hash] += 1

        self.timestamps[cred_hash] = int(time.time())

    def write(self, path: Path) -> None:
        '''
        Write the LastUsedCache to the specified location. Make sure that the data
        is written in the correct order according to the usage count.

        Parameters:
            path            path to the cache file

        Returns:
            None
        '''
        data = []

        for cred_hash in self.cached:
            data.append((cred_hash, self.usage_data[cred_hash], self.timestamps[cred_hash]))

        data.sort(key=lambda x: x[1], reverse=True)

        with open(path, 'w') as cache_file:

            for item in data:
                cache_file.write(f'{item[0]}:')
                cache_file.write(f'{item[1]}:')
                cache_file.write(f'{item[2]}\n')

    def get_last(self) -> str:
        '''
        If a credential was used within the last 30 seconds, return it's hash.
        If no credential was used within the last 30 seconds, return an empty
        string.

        Parameters:
            None

        Returns:
            hash of last used credentials within 30 seconds or empty string
        '''
        if not self.cached:
            return ''

        best = self.cached[0]

        for cred_hash in self.cached:

            if self.timestamps[cred_hash] > self.timestamps[best]:
                best = cred_hash

        if (int(time.time()) - self.timestamps[best]) <= 30:
            return best

        return ''

    def sort(self, cred_list: list[Credential]) -> None:
        '''
        Order a list of credentials according to their usage count. This function
        uses the fact that the LastUsedCache is sorted before it is written to disk.
        The hashes stored in self.cached are therefore in the correct order.

        Parameters:
            cred_list           list of credentials to be ordered

        Returns:
            None
        '''
        if not Config.getboolean('smart_sort'):
            return

        cred_dict = {}
        copy_list = list(cred_list)
        cred_list.clear()

        for cred in copy_list:
            cred_dict[LastUsedCache.hash(cred)] = cred

        last_hash = self.get_last()
        last_used = cred_dict.get(last_hash)

        if last_used is not None:
            cred_list.append(last_used)
            copy_list.remove(last_used)
            cred_dict[last_hash] = None

        for cred_hash in self.cached:

            cred = cred_dict.get(cred_hash)

            if cred is not None:
                cred_list.append(cred)
                copy_list.remove(cred)

        cred_list += copy_list

    def load(path: Path) -> LastUsedCache:
        '''
        Initialize the LastUsedCache from the specified cache file.

        Parameters:
            path            path to the cache file

        Returns:
            LastUsedCache object
        '''
        cached_data = []

        if path.is_file():

            text = path.read_text()
            for line in text.split('\n'):

                try:
                    cred_hash, usage_count, access_time = line.split(':', 3)
                    cached_data.append((cred_hash, int(usage_count), int(access_time)))

                except ValueError:
                    continue

            cached_data.sort(key=lambda x: x[1], reverse=True)

        return LastUsedCache(cached_data)

    def hash(cred: Credential) -> str:
        '''
        Copute a hash for a Crednetial object. The hash is simply the sha256
        of issuer-name-device_id.

        Parameters:
            cred            credential to compute the hash for

        Returns:
            sha256 hash for the credential as hex string
        '''
        return hashlib.sha256(f'{cred.issuer}-{cred.name}-{cred.device_id}'.encode()).hexdigest()


class Config:
    '''
    Class for parsing the qubes-yubioath configuration file.
    '''
    parser = None
    config_locations = [
                         Path.home() / '.config/qubes-yubioath.ini',
                         Path.home() / '.config/qubes-yubioath/config.ini',
                         Path.home() / '.config/qubes-yubioath/qubes-yubioath.ini',
                         Path('/etc/qubes-yubioath.ini'),
                         Path('/etc/qubes-yubioath/config.ini'),
                         Path('/etc/qubes-yubioath/qubes-yubioath.ini'),
                       ]

    def get(key: str) -> str:
        '''
        Get the specified key from the configuration file. Currently, only
        unique keys are present and sections are only used for formatting.
        Therefore we can simply iterate over each section to find the key.

        Parameters:
            key             key to obtain from the configuration file

        Returns:
            value for the specified key
        '''
        for section in Config.parser.sections():

            value = Config.parser[section].get(key)

            if value is not None:

                if value == '':
                    return None

                return value

        raise KeyError(key)

    def getboolean(key: str) -> bool:
        '''
        Same as get, but returns bool. Does not raise KeyError if a key does not
        exist. False is assumed in this case.

        Parameters:
            key             key to obtain from the configuration file

        Returns:
            value for the specified key
        '''
        for section in Config.parser.sections():

            value = Config.parser[section].getboolean(key)

            if value is not None:
                return value

            else:
                return False

    def get_rofi_options() -> list[str]:
        '''
        Return the configured rofi options as a list that can be used for
        the subprocess module.

        Parameters:
            None

        Returns:
            list of rofi options.
        '''
        try:
            return list(Config.parser['rofi.options'].values())

        except KeyError:
            return list()

    def load(path: str = None) -> Config:
        '''
        Create a Config object from the specified path or,
        if None was specified, from certain default locations.

        Parameters:
            path            path of a qubes-yubioath configuration file

        Returns:
            Config
        '''
        config_path = None

        if path is not None:
            config_path = Path(path)

        else:

            for path in Config.config_locations:

                if path.is_file():
                    config_path = path
                    break

        if not config_path or not config_path.is_file():
            raise MissingConfigException('No config file found.')

        Config.parser = configparser.ConfigParser()
        Config.parser.read(config_path)


def main():
    '''
    Main method :)
    '''
    parser = argparse.ArgumentParser(description='''qubes-yubioath v1.0.0 - A rofi based yubikey OTP frontend for Qubes''')
    parser.add_argument('qube', help='qube to copy the credential to')
    parser.add_argument('--config', help='path to the configuration file')
    args = parser.parse_args()

    cache_path = Path.home() / '.qubes-yubioath.cache'
    cred_cache = LastUsedCache.load(cache_path)

    Config.load(args.config)
    devices = list_all_devices()

    if len(devices) != 1:

        print(f'[-] Found {len(devices)} YubiKeys. Expected to find 1.')
        print('[-] Aborting.')
        return

    device = devices[0][0]

    if device.supports_connection(SmartCardConnection):
        con = device.open_connection(SmartCardConnection)

    else:
        print(f'[-] {device.fingerprint} does not support SmartCard connections.')
        print('[-] Aborting.')
        return

    try:
        session = OathSession(con)

        cred_map = session.calculate_all()
        creds = list(cred_map.keys())

        cred_cache.sort(creds)
        selected = select_credential(creds, args.qube)

        cred_cache.put(selected)
        cred_cache.write(cache_path)

        if cred_map[selected] is None:

            if selected.touch_required:
                subprocess.call(['notify-send', 'Please touch your YubiKey'])

            code = session.calculate_code(selected)

        else:
            code = cred_map[selected]

        copy_code(code, args.qube)

    except MissingConfigException:
        print('[-] qubes-yubioath configuration was not found.')
        print('[-] Please create one :)')

    except RofiAbortedException:
        print('[-] rofi selection was canceled by user.')

    finally:
        con.close()

main()
