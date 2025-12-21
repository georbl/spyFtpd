#!/usr/bin/env python3
"""
spyFtpD – simple Python FTP daemon (Python 3 version)
- Uses pyftpdlib (modern API)
- Keeps original CLI options
- Adds YAML config support (~/.spyFtpD.yaml by default)
- Uses cryptography for certificate generation (no deprecated pyOpenSSL APIs)
"""

import os
import sys
import logging
import tempfile
import socket
import warnings
import argparse
import datetime

import yaml

BASE = os.path.dirname(os.path.realpath(__file__))
LIB = os.path.join(BASE, "lib") 
if LIB not in sys.path: 
    sys.path.insert(0, LIB)

from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

# cryptography for TLS certificate generation
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


__pname__ = "spyFtpD (simple python FTP Daemon)"
__ver__ = "0.2.1"


# ----------------------------------------------------------------------
# YAML helpers
# ----------------------------------------------------------------------

def load_yaml_config(path):
    """
    Load YAML config from 'path' if it exists.
    Returns a dict (possibly empty).
    """
    path = os.path.expandvars(os.path.expanduser(path))
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Top-level YAML document must be a mapping")
    return data


def write_default_yaml_config(path):
    """
    Write a default YAML configuration file.
    Keys mirror the internal option names so merging is trivial.
    """
    path = os.path.expandvars(os.path.expanduser(path))
    default_cfg = {
        "Address": "0.0.0.0",
        "Port": 2121,
        "Masquerade": None,
        "PassivePorts": None,
        "UseSsl": False,
        "SslCertificate": None,
        # Users are specified in the same string format as the original CLI:
        # "<name>:<password>:<path>:<permissions>[,<path2>:<perm2>:<recursive>]"
        "User": [
            # Example:
            # "anonymous::/tmp/ftp:elr,/tmp/ftp/incoming:elradfmw:False"
        ],
        # Log level by name, if you want to set it via YAML (optional)
        "Verbose": "WARNING"
    }

    if os.path.exists(path):
        raise FileExistsError(f"Config file already exists: {path}")

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(default_cfg, f, default_flow_style=False)


# ----------------------------------------------------------------------
# Custom argparse actions to preserve old CLI behaviour
# ----------------------------------------------------------------------

class AnonymousReadAction(argparse.Action):
    """
    -a / --anonymous PATH  -> append 'anonymous::<PATH>:elr' to User list
    """

    def __call__(self, parser, namespace, values, option_string=None):
        users = getattr(namespace, "User", None)
        if users is None:
            users = []
        users.append(f"anonymous::{values}:elr")
        setattr(namespace, "User", users)


class AnonymousWriteAction(argparse.Action):
    """
    -A / --anonymous-write PATH  -> append 'anonymous::<PATH>:elradfmw' to User list
    """

    def __call__(self, parser, namespace, values, option_string=None):
        users = getattr(namespace, "User", None)
        if users is None:
            users = []
        users.append(f"anonymous::{values}:elradfmw")
        setattr(namespace, "User", users)


# ----------------------------------------------------------------------
# Main daemon class
# ----------------------------------------------------------------------

class SpyFtpD:
    _spyFtpdPath = os.path.dirname(os.path.realpath(__file__))
    _dSep = ","

    def __init__(self):
        warnings.filterwarnings(
            "ignore",
            "Write permissions assigned to anonymous user.",
            RuntimeWarning
        )

        self._log = logging.getLogger("spyftpd")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)8s: %(message)s"))
        self._log.addHandler(handler)

        warnings.showwarning = (
            lambda msg, cat, fn, ln, file=None, line=None:
            self._log.warning(msg)
        )

        self._options = None

    # ------------------------------------------------------------------

    def start(self):
        self.get_options()

        self._log.setLevel(self._options.Verbose)

        created_cert = False
        if self._options.UseSsl and not self._options.SslCertificate:
            self._options.SslCertificate = self.create_certificate_file()
            created_cert = True

        self._log.info(f"Address:                 {self._options.Address}")
        self._log.info(f"Port:                    {self._options.Port}")
        self._log.info(f"Ssl:                     {self._options.UseSsl}")
        if self._options.UseSsl:
            self._log.info(f"Ssl Certificate:         {self._options.SslCertificate}")

        self._log.info("Users:")
        for u in self._options.User:
            self._log.info(f"  {u}")

        # Handler selection
        if self._options.UseSsl:
            handler = TLS_FTPHandler
            handler.certfile = self._options.SslCertificate
            handler.tls_control_required = True
            handler.tls_data_required = True
        else:
            handler = FTPHandler

        handler.authorizer = self.create_authorizer()

        # Masquerade
        if self._options.Masquerade:
            ip = socket.gethostbyname(self._options.Masquerade)
            handler.masquerade_address = ip
            self._log.info(f"Masquerade IP address: {ip}")

        # Passive ports
        if self._options.PassivePorts:
            try:
                start_str, end_str = self._options.PassivePorts.split("-", 1)
                start, end = int(start_str), int(end_str)
            except ValueError as e:
                self._log.error(f"Wrong format in range of passive ports: {e}")
                sys.exit(1)

            if start < 0 or end < start:
                self._log.error(f"Invalid range from {start} to {end}")
                sys.exit(1)

            self._log.info(f"Passive Port Range: {start} to {end}")
            handler.passive_ports = range(start, end)

        # Start FTP server
        self._log.info("Starting FTP Server")
        address_port = (self._options.Address, self._options.Port)
        try:
            server = FTPServer(address_port, handler)
        except Exception as e:
            self._log.error(f"Failed to start server: {e}")
            sys.exit(1)

        server.serve_forever()

        if created_cert:
            self._log.info(f"Removing certificate file '{self._options.SslCertificate}'")
            try:
                os.remove(self._options.SslCertificate)
            except OSError as e:
                self._log.warning(f"Failed to remove certificate file: {e}")

    # ------------------------------------------------------------------

    def create_authorizer(self):
        """
        Build DummyAuthorizer from self._options.User list.
        Each entry is a string like:
            "<name>:<password>:<path>:<perm>[,<dirpath>:<perm>:<recursive>...]"
        """
        auth = DummyAuthorizer()

        for usercfg in self._options.User:
            if self._dSep in usercfg:
                user, dirs = usercfg.split(self._dSep, 1)
            else:
                user, dirs = usercfg, None

            try:
                name, passwd, path, perm = user.split(":", 3)
            except ValueError:
                self._log.error(f"Wrong format for user (see help): '{user}'")
                sys.exit(1)

            if not perm:
                perm = "elradfmw"

            try:
                if name == "anonymous":
                    self._log.info("Allowing anonymous access")
                    auth.add_anonymous(path, perm=perm)
                else:
                    auth.add_user(name, passwd, path, perm=perm)
            except Exception as e:
                self._log.error(f"Failed to add user '{name}': {e}")
                sys.exit(1)

            if dirs:
                for d in dirs.split(self._dSep):
                    try:
                        dpath, dperm, recursive = d.split(":", 2)
                    except ValueError:
                        self._log.error(f"Wrong format for directory (see help): '{d}'")
                        sys.exit(1)

                    recursive_flag = (recursive == "True")

                    try:
                        self._log.info(
                            f"Overriding directory permissions in '{dpath}' for user '{name}'"
                        )
                        auth.override_perm(name, dpath, dperm, recursive_flag)
                    except Exception as e:
                        self._log.error(
                            f"Failed to override directory permissions in '{dpath}' "
                            f"for user '{name}': {e}"
                        )
                        sys.exit(1)

        return auth

    # ------------------------------------------------------------------

    def get_options(self):
        """
        Parse options from CLI and YAML.
        Merge order: defaults -> YAML -> CLI (CLI wins).
        """

        parser = argparse.ArgumentParser(
            prog="spyFtpD",
            description="Start a FTP server without tedious configuration work."
        )

        # Network options
        net = parser.add_argument_group("Network options",
                                        "Network settings of the FTP server")
        # original long name had a typo "--adress"; we keep it for compatibility
        net.add_argument("-i", "--adress",
                         dest="Address", type=str,
                         help="Address of the server to listen on [default: %(default)s]")
        net.add_argument("-p", "--port",
                         dest="Port", type=int,
                         help="Port of the server to listen on [default: %(default)s]")
        net.add_argument("-m", "--masquerade",
                         dest="Masquerade", type=str,
                         help=("Public Host name or IP address used when running "
                               "behind a Router (or similar)"))
        net.add_argument("--passive-ports",
                         dest="PassivePorts", type=str,
                         help=("Range of ports used for passive data transfers "
                               "(e.g., 60001-65000)"))

        # SSL options
        sslg = parser.add_argument_group("SSL options",
                                         "SSL settings of the FTP server")
        sslg.add_argument("-s", "--ssl",
                          dest="UseSsl", action="store_true",
                          help="Use TLS/SSL [default: %(default)s]")
        sslg.add_argument("--ssl-cert",
                          dest="SslCertificate", type=str,
                          help="Certificate file used by the SSL connection [default: %(default)s]")

        # Authentication options
        auth = parser.add_argument_group("Authentication options",
                                         "Authentication settings of the FTP server")
        auth.add_argument("-u", "--user",
                          dest="User", action="append", type=str,
                          help=("Add a USER with password, FTP root path and permissions.\n"
                                "Format:\n"
                                "  <name>:<password>:<path>:<permissions>[,<d>]\n"
                                "  <d> : <path>:<permissions>:<recursive>\n"
                                "Password is ignored if user name is 'anonymous'"))
        auth.add_argument("-a", "--anonymous",
                          dest="AnonymousRead", metavar="PATH",
                          action=AnonymousReadAction,
                          help=("Add anonymous read-only access for path.\n"
                                "Shortcut for anonymous::<PATH>:elr"))
        auth.add_argument("-A", "--anonymous-write",
                          dest="AnonymousWrite", metavar="PATH",
                          action=AnonymousWriteAction,
                          help=("Add anonymous read-write access for path.\n"
                                "Shortcut for anonymous::<PATH>:elradfmw"))

        # Misc options
        misc = parser.add_argument_group("Miscellaneous options",
                                         "Miscellaneous settings for program behaviour")
        misc.add_argument("-v", "--verbose",
                          dest="Verbose", action="store_const",
                          const=logging.DEBUG,
                          help="Print debug status messages")
        misc.add_argument("-c", "--config",
                          dest="ConfigFile", type=str,
                          help="Use this YAML configuration file")
        misc.add_argument("--create-config",
                          dest="CreateConfig", action="store_true",
                          help=("Create YAML configuration file passed as '-c' "
                                "or in your HOME directory (~/.spyFtpD.yaml)"))

        # Hard defaults
        default_cfg_path = "${HOME}/.spyFtpD.yaml"
        parser.set_defaults(
            Address="0.0.0.0",
            Port=2121,
            Masquerade=None,
            PassivePorts=None,
            UseSsl=False,
            SslCertificate=None,
            User=[],
            Verbose=logging.WARNING,
            ConfigFile=default_cfg_path,
            CreateConfig=False
        )

        # First pass: find config path
        preliminary, _ = parser.parse_known_args()
        cfg_path = os.path.expandvars(os.path.expanduser(
            preliminary.ConfigFile or default_cfg_path
        ))

        # Load YAML if present
        yaml_cfg = {}
        try:
            yaml_cfg = load_yaml_config(cfg_path)
        except Exception as e:
            print(f"Error loading YAML config '{cfg_path}': {e}", file=sys.stderr)
            sys.exit(1)

        # Merge YAML into defaults
        defaults_from_yaml = {}
        for key in ["Address", "Port", "Masquerade", "PassivePorts",
                    "UseSsl", "SslCertificate", "User", "Verbose"]:
            if key in yaml_cfg and yaml_cfg[key] is not None:
                if key == "Verbose":
                    val = yaml_cfg[key]
                    if isinstance(val, str):
                        val_upper = val.upper()
                        level = getattr(logging, val_upper, logging.WARNING)
                        defaults_from_yaml["Verbose"] = level
                    else:
                        defaults_from_yaml["Verbose"] = val
                else:
                    defaults_from_yaml[key] = yaml_cfg[key]

        if defaults_from_yaml:
            parser.set_defaults(**defaults_from_yaml)

        # Final parse: YAML defaults + CLI overrides
        self._options = parser.parse_args()

        # --create-config: write template and exit
        if self._options.CreateConfig:
            try:
                write_default_yaml_config(self._options.ConfigFile)
                print("Created default YAML config at:",
                      os.path.expandvars(os.path.expanduser(self._options.ConfigFile)))
            except Exception as e:
                print(f"Failed to create config: {e}", file=sys.stderr)
                sys.exit(1)
            sys.exit(0)

        # SSL checks
        if self._options.UseSsl and not CRYPTO_AVAILABLE:
            print("SSL is requested but 'cryptography' is not available. Install the 'cryptography' package.",
                  file=sys.stderr)
            sys.exit(1)

        if (self._options.UseSsl and
            self._options.SslCertificate and
            not os.path.isfile(os.path.expandvars(os.path.expanduser(self._options.SslCertificate)))):
            print(f"SSL certificate file doesn't exist: "
                  f"'{self._options.SslCertificate}'", file=sys.stderr)
            sys.exit(1)

        # Normalize certificate path
        if self._options.SslCertificate:
            self._options.SslCertificate = os.path.expandvars(
                os.path.expanduser(self._options.SslCertificate)
            )

    # ------------------------------------------------------------------

    def create_certificate_file(self):
        """
        Create a default self-signed certificate on the fly using cryptography.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography is not available")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sto Plains"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ankh-Morpork"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"The Smoking Gnu"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"spyftpd.local"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        tmp = tempfile.NamedTemporaryFile(
            suffix=".pem",
            prefix="spyFtpDCert",
            delete=False,
            mode="wb"
        )
        self._log.info(f"Writing private key and certificate into file '{tmp.name}'")

        # private key
        tmp.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # certificate
        tmp.write(cert.public_bytes(serialization.Encoding.PEM))
        tmp.close()

        print("SHA-256 Fingerprint of created certificate:",
              cert.fingerprint(hashes.SHA256()).hex())

        return tmp.name


# ----------------------------------------------------------------------

if __name__ == "__main__":
    daemon = SpyFtpD()
    daemon.start()
