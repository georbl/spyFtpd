#!/usr/bin/env python3
"""
spyFtpD is a simple frontend to the pyftpdlib Python FTP library
"""

import logging
import os
from pathlib import Path
from dataclasses import dataclass
import sys
import argparse
from functools import partial

BASE = os.path.dirname(os.path.realpath(__file__))
LIB = os.path.join(BASE, "lib") 
if LIB not in sys.path: 
    sys.path.insert(0, LIB)

from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.log import config_logging

__pname__ = "spyFtpD (simple python FTP Daemon)"
__ver__ = "2.0.0"


@dataclass(frozen=True)
class UserType: 
    name: str
    passwd: str
    path: str
    perm: str


# ----------------------------------------------------------------------
# Custom argparse types and actions
# ----------------------------------------------------------------------


def user_type(values: str, name=None, perm=None) -> UserType:
    user: UserType
    if (name == "anonymous"):
        user = UserType(name,None,values,perm)

    else:
        try:
            argname,argpasswd,argpath,argperm = values.split(":", 3)
            user = UserType(argname,argpasswd,argpath,argperm)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Wrong format for user (see help): '{values}'")

    if not Path(user.path).exists(): 
        raise argparse.ArgumentTypeError(f"path does not exist: {values}") 
    return user


class AddUser(argparse.Action):
   
    def __init__(self, option_strings, dest, auth: DummyAuthorizer,**kwargs):
        super().__init__(option_strings, dest, **kwargs)
        self._auth=auth
        self._log = logging.getLogger("spyftpd")

    def __call__(self, parser, namespace, user:UserType, option_string=None):
        try:
            if (self._auth.has_user(user.name)):
                # modify permission path in homedir for existing user
                self._auth.override_perm(user.name,user.path,user.perm,recursive=True)
            else:
                if (user.name == "anonymous"):
                    self._auth.add_anonymous(user.path,perm=user.perm)
                else:
                    self._auth.add_user(user.name, user.passwd, user.path, perm=user.perm)
        except ValueError as e:
            self._log.error(f"Can't add user '{user.name}': {e}")
            sys.exit(1)



# ----------------------------------------------------------------------
# Main daemon class
# ----------------------------------------------------------------------

class SpyFtpD:
    _spyFtpdPath = os.path.dirname(os.path.realpath(__file__))

    def __init__(self):

        # initialize logging
        self._log = logging.getLogger("spyftpd")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)8s: %(message)s"))
        self._log.addHandler(handler)
        

        self._options = None
        self._auth = DummyAuthorizer()

    def main(self):
        self.get_options()

        # set log level
        self._log.setLevel(self._options.Verbose)
        config_logging(self._options.Verbose)

        self._log.info(f"Address:                 {self._options.Address}")
        self._log.info(f"Port:                    {self._options.Port}")

        self._log.info("Users:")
        for userName in self._auth.user_table:
            self._log.info(f"   - {userName}: '{self._auth.get_home_dir(userName)}' with perms '{self._auth.get_perms(userName)}'") 

        handler = FTPHandler
        handler.authorizer = self._auth

        # Start FTP server
        self._log.info("Starting FTP Server")
        address_port = (self._options.Address, self._options.Port)

        try:
            server = FTPServer(address_port, handler)
        except Exception as e:
            self._log.error(f"Failed to start server: {e}")
            sys.exit(1)

        server.serve_forever()


    def get_options(self):
        """
        Parse command line arguments 
        """

        parser = argparse.ArgumentParser(
            prog="spyFtpD",
            description="Start a FTP server without tedious configuration work."
        )

        # Network options
        netArgs = parser.add_argument_group("Network options",
                                        "Network settings of the FTP server")
        
        netArgs.add_argument("-i", "--address",
                            dest="Address", type=str,
                            help="Address of the server to listen on [default: %(default)s]")
        
        netArgs.add_argument("-p", "--port",
                            dest="Port", type=int,
                            help="Port of the server to listen on [default: %(default)s]")
       
        # Authentication options
        authArgs = parser.add_argument_group("Authentication options",
                                         "Authentication settings of the FTP server")
        
        authArgs.add_argument("-u", "--user",
                            type=partial(user_type, name=None, perm=None),
                            action=AddUser, auth=self._auth,
                            help=("Add a USER with password, FTP root path and permissions.\n"
                                "Format:\n"
                                "  <name>:<password>:<path>:<permissions>"))
        
        authArgs.add_argument("-a", "--anonymous",
                            metavar="PATH",
                            type=partial(user_type, name="anonymous", perm="elr"),
                            action=AddUser, auth=self._auth,
                            help=("Add anonymous read-only access for path."))
        
        authArgs.add_argument("-A", "--anonymous-write",
                            metavar="PATH",
                            type=partial(user_type, name="anonymous", perm="elradfmwMT"),
                            action=AddUser, auth=self._auth,
                            help=("Add anonymous read-write access for path."))

        # Misc options
        miscArgs = parser.add_argument_group("Miscellaneous options",
                                         "Miscellaneous settings for program behaviour")
        miscArgs.add_argument("-v", "--verbose",
                          dest="Verbose", action="store_const",
                          const=logging.DEBUG,
                          help="Print debug status messages")


        parser.set_defaults(
            Address="0.0.0.0",
            Port=2121,
            Verbose=logging.WARNING,
        )

        self._options = parser.parse_args()

if __name__ == "__main__":
    daemon = SpyFtpD()
    daemon.main()
