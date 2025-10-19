#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script to read and manage the Discretionary Access Control List of an object
#
# Authors:
#   Fabrizzio Bridi @Fabrizzio53

import argparse
import logging
import sys
import traceback

import ldap3
import ldapdomaindump
from ldap3.utils.dn import parse_dn
from ldap3.utils.conv import escape_filter_chars 

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import init_ldap_session, parse_identity

class OUChange(object):

    def set_correct_cn_format(self,old_target_dn):

        parsed_dn = parse_dn(self.__old_target_dn)
        cn_only = [attr_value[1] for attr_value in parsed_dn if attr_value[0].lower() == 'cn']

        return ','.join([f"CN={cn}" for cn in cn_only])
               


    def __init__(self, ldap_server, ldap_session, args):

        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

        self.__target = args.target
        self.__destination_ou_dn = args.destination_ou_dn
        self.__target_dn = args.target_dn

        self.__old_target_dn = ""

        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

        self.__old_target_dn = self.__target_dn

        if self.__target_dn == None:

            resp = self.ldap_session.search(self.domain_dumper.root, f'(sAMAccountName={self.__target})', attributes=['*'])

            if resp:
                entries = self.ldap_session.entries
                if len(entries) == 1:
                    for entry in entries:
                        print(f"[+] Found target user DN: {entry.entry_dn}")
                        self.__old_target_dn = entry.entry_dn

                else:
                    print(f"[-] Search failed, could not found the specified user {self.__target} wrong domain? wrong user?")
                    return False
            else:
                print(f"[-] Search failed {self.ldap_session.last_error}")    
                return False      

        parsed_cn = self.set_correct_cn_format(self.__old_target_dn)

        print(f"[!] trying to move {self.__target} to {self.__destination_ou_dn}")

        if self.ldap_session.modify_dn(self.__old_target_dn,parsed_cn, new_superior=self.__destination_ou_dn):

            print(f'[+] Success, the user got changed to the new OU {self.__destination_ou_dn}')

        else:

            print(f'[-] Could not change {self.__target} to the new OU: {self.ldap_session.result["description"]}')   


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python editor to move a user to another OU')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    auth_con.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')

    target_parser = parser.add_argument_group("target", description="Principal object to change the OU of")
    target_parser.add_argument("-target", dest="target", metavar="NAME", type=str, required=False, help="sAMAccountName of the target to move to the new OU")
    target_parser.add_argument("-target-dn", dest="target_dn", metavar="NAME", type=str, required=False, help="DN of the target to move to the new OU")
    target_parser.add_argument("-destination-ou-dn", dest="destination_ou_dn", metavar="DN", type=str, required=False, help="OU new destination, DO NOT put CN=, only OU and DC, example: OU=IT,OU=GALACTIC,DC=domain,DC=local")


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
        if args.target_dn != None:

            print("[!] Target DN was passed, no further verifications will be made, make sure that the DN is correct")

        OUChange(ldap_server, ldap_session, args)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
