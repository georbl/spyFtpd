#!/usr/bin/python


# spyFtpD is distributed under a BSD license.
#
# spyFtpD - Copyright (C)2011 Georg Blaschke (ggb@gmx.de)
# All rights reserved.
#
# Permission  is  hereby granted,  free  of charge,  to  any person
# obtaining a  copy of  this software  and associated documentation
# files  (the  "Software"),  to   deal  in  the  Software   without
# restriction,  including  without limitation  the  rights to  use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies  of  the  Software,  and to  permit  persons  to  whom the
# Software  is  furnished  to  do  so,  subject  to  the  following
# conditions:
#
# The above copyright  notice and this  permission notice shall  be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS  IS", WITHOUT WARRANTY OF ANY  KIND,
# EXPRESS OR IMPLIED, INCLUDING  BUT NOT LIMITED TO  THE WARRANTIES
# OF  MERCHANTABILITY,  FITNESS   FOR  A  PARTICULAR   PURPOSE  AND
# NONINFRINGEMENT.  IN  NO  EVENT SHALL  THE  AUTHORS  OR COPYRIGHT
# HOLDERS  BE LIABLE  FOR ANY  CLAIM, DAMAGES  OR OTHER  LIABILITY,
# WHETHER  IN AN  ACTION OF  CONTRACT, TORT  OR OTHERWISE,  ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# $Id: $


'''
Created on Apr 3, 2011

@author: Georg Blaschke
'''

import os, sys, logging, tempfile
import warnings
from lib.pyftpdlib import ftpserver
from lib.pyftpdlib.contrib.handlers import TLS_FTPHandler
from lib.configparse import OptionParser, OptionGroup
from lib.IndentedHelpFormatterWithNL import IndentedHelpFormatterWithNL
try:
    from OpenSSL import crypto
except ImportError:
    pass

__pname__ = 'spyFtpD (simple python Ftp Daemon)'
__ver__ = '0.1.0'


class SpyFtpD(object):
  '''
  classdocs
  '''

  # location of the this file in the filesystem
  _spyFtpdPath = os.path.dirname(os.path.realpath(__file__))

  # String that separates user from directory settings and
  # different directory settings from each other
  _dSep = ','

    # Object containing all options
  _options = None

  # Logger Object
  _log = None
  _usage = """%prog [OPTIONS]
Start a FTP server without tedious configuration work.

Examples:
  1) Start an FTP server with anonymous read-only access and FTP root directory in
     the current directory:

     %prog -a .


  2) Start an FTP server with anonymous full access and FTP root
     in '${HOME}/public':

     %prog -A ${HOME}/public


  3) Start an FTP server with anynomous read-only access, FTP root
     in '/tmp/ftp' and a writeable 'incoming' directory:

     %prog -u "anonymous::/tmp/ftp:elr,/tmp/incoming:erlmw:False"


Read permissions:

  "e" = change directory (CWD command)
  "l" = list files (LIST, NLST, MLSD commands)
  "r" = retrieve file from the server (RETR command)


Write permissions:

  "a" = append data to an existing file (APPE command)
  "d" = delete file or directory (DELE, RMD commands)
  "f"  = rename file or directory (RNFR, RNTO commands)
  "m" = create directory (MKD command)
  "w" = store a file to the server (STOR, STOU commands)

"""

  def __init__(self):
    '''
    Constructor for spyFtpD
    '''

    #ignore warning
    warnings.filterwarnings("ignore", "Write permissions assigned to anonymous user.", RuntimeWarning)

    # create logger object
    global _log
    _log = logging.getLogger("spyftpd")
    # create console handler with a higher log level
    consoleLogHandler = logging.StreamHandler()
    consoleLogHandler.setFormatter(logging.Formatter("%(levelname)8s: %(message)s"))
    _log.addHandler(consoleLogHandler)
    ftpserver.log = lambda msg: _log.info("%s\n" % (msg))
    ftpserver.logline = lambda msg: _log.info("%s\n" % (msg))

    #Redirect python warnings to logger
    warnings.showwarning = lambda message, category, filename, lineno, file = None, line = None: _log.warn(message)


  def start(self):

    # get options
    self.getOptions()

    # set log level
    _log.setLevel(self._options.Verbose)

    # check if certificate file exits in case SSL is used and file name is given
    createdCertificateFile = False
    if ((self._options.UseSsl == True)
        and (self._options.SslCertificate == None)):
      self._options.SslCertificate = self.createCertificateFile()
      createdCertificateFile = True


    # print information
    _log.info("-------------------------------------")
    _log.info("Address:                 %s" % self._options.Address)
    _log.info("Port:                    %d" % self._options.Port)
    _log.info("Ssl:                     %s" % self._options.UseSsl)
    if (self._options.UseSsl):
      _log.info("Ssl Certificate:         %s" % self._options.SslCertificate)
    _log.info("Users:                               ")
    for user in self._options.User:
      _log.info("  %s" % user)
    _log.info("-------------------------------------")
    _log.info("-------------------------------------")


    # create FTP server handle
    ftp_handler = None
    if (self._options.UseSsl == True):
      ftp_handler = TLS_FTPHandler
      ftp_handler.certfile = self._options.SslCertificate
      ftp_handler.tls_control_required = True
      ftp_handler.tls_data_required = True
    else:
      ftp_handler = ftpserver.FTPHandler

    # setup authorization
    ftp_handler.authorizer = self.createAuthorizer()

    # start ftp server
    _log.info("Starting FTP Server")
    Adress_Port = (self._options.Address, self._options.Port)
    try:
      FtpD = ftpserver.FTPServer(Adress_Port, ftp_handler)
    except Exception, msg:
      _log.error("Failed to start server: %s" % msg)
      sys.exit(1)

    FtpD.serve_forever()

    # Cleanup after FTP server is stopped
    if (createdCertificateFile == True):
      _log.info("Removing certificate file '%s'" % self._options.SslCertificate)
      os.remove(self._options.SslCertificate)



  def createAuthorizer(self):
    '''
    Create authorizer for ftp server using the user information in the options object
    '''

    # create authorizer object
    authorizer = ftpserver.DummyAuthorizer()

    # fill authorizer with information from _options
    for usercfg in self._options.User:
      user = None
      directories = None
      if (usercfg.find(self._dSep) > 0):
        (user, directories) = usercfg.split(self._dSep, 1)
      else:
        user = usercfg

      try:
        (name, passwd, path, perm) = user.split(':', 3)
      except:
        _log.error('Wrong format for user (see help): "%s"' % user)
        sys.exit(1)


      # set default permissions (allow every action)
      if (perm == ""):
        perm = "elradfmw"

      try:
        if (name == "anonymous"):
          _log.info("Allowing anonymous access")
          authorizer.add_anonymous(path, perm=perm)
        else:
          authorizer.add_user(name, passwd, path, perm=perm)
      except ftpserver.Error, msg:
        _log.error('Failed to add user "%s": %s' % (name, msg))
        sys.exit(1)

      if (directories != None):
        for dir in directories.split(self._dSep):

          try:
            (path, perm, recursive) = dir.split(':', 3)
          except:
            _log.error('Wrong format for directory (see help): "%s"' % dir)
            sys.exit(1)

          if (recursive == "True"):
            recursive = True
          else:
            recursive = False

          try:
            _log.info('Overriding directory permissions in "%s" for user "%s"' % (path, name))
            authorizer.override_perm(name, path, perm, recursive)
          except ftpserver.Error, msg:
            _log.error('Failed to override directory permissions in "%s" for user "%s": %s' % (path, name, msg))
            sys.exit(1)

    return authorizer


  def getOptions(self):
    '''
    parse options from on the command line and from the configuration file
    '''

    parser = OptionParser(usage=self._usage, formatter=IndentedHelpFormatterWithNL())

    # Network Settings
    networkSettingGroup = OptionGroup(parser, "Network _options",
                      "Network settings of the FTP server")
    networkSettingGroup.add_option("-i", "--adress",
                    type="string", dest="Address", config="true",
                    help="Address of the server to listen on [default: %default]"
                    )
    networkSettingGroup.add_option("-p", "--port",
                    type="int", dest="Port", config="true",
                    help="Port of the server to listen on [default: %default]"
                    )
    parser.add_option_group(networkSettingGroup)

    # Ssl Settings
    sslSettingGroup = OptionGroup(parser, "SSL options",
                           "SSL settings of the FTP server")
    sslSettingGroup.add_option("-s", "--ssl",
                    action="store_true", dest="UseSsl", config="true",
                    help="Use TLS/SSL [default: %default]"
                    )
    sslSettingGroup.add_option("--ssl-cert",
                    type="string", dest="SslCertificate", config="true",
                    help="Certificate file used by the ssl connection [default: %default]"
                    )

    parser.add_option_group(sslSettingGroup)
    # Authentication Settings
    authSettingGroup = OptionGroup(parser, "Authentication _options",
                      "Authentication setting of the FTP server")
    authSettingGroup.add_option("-u", "--user",
                    type="string", action="append", dest="User", config="true",
                    help="Add a USER with password, FTP root path and permissions.\n * Format:\n   <name>:<password>:<path>:<permissions>[,<d>]\n * <d> : <path>:<permissions>:<recursive>  \n * Password is ignored if user name is 'anonymous'"

                    )

    authSettingGroup.add_option("-a", "--anonymous", dest="path",
                    type="string", action="callback",
                    callback=lambda option, opt_str, value, parser: parser.values.User.append("anonymous::%s:%s" % (value, "elr")),
                    help="""Add anonymous read-only access for path specified as argument.\n * Shortcut for anonymous::<PATH>:elr"""
                    )

    authSettingGroup.add_option("-A", "--anonymous-write", dest="path",
                    type="string", action="callback",
                    callback=lambda option, opt_str, value, parser: parser.values.User.append("anonymous::%s:%s" % (value, "elradfmw")),
                    help="Add anonymous read-write access for path specified as argument.\nShortcut for anonymous::<PATH>:elradfmw"
                    )
    parser.add_option_group(authSettingGroup)

    # Misc Settings
    miscSettingGroup = OptionGroup(parser, "Miscellaneous _options",
                      "Miscellaneous settings for programm behaviour")
    miscSettingGroup.add_option("-v", "--verbose",
                    action="store_const", const=logging.DEBUG, dest="Verbose",
                    help="Print status messages"
                    )
    miscSettingGroup.add_option("-c", "--config",
                    type="string", dest="ConfigFile",
                    help="Use this configuration file"
                    )
    miscSettingGroup.add_option("--create-config",
                    action="store_true", dest="CreateConfig",
                    help="Create configuration file passed as argument of '-c' option or in your HOME directory"
                    )
    parser.add_option_group(miscSettingGroup)


    parser.set_defaults(

        # Network _options
        Address="0.0.0.0",
        Port=2121,

        #SSL Options
        UseSsl=False,
        SslCertificate=None,

        # Authentication Options
        User=[],

        # Misc Options
        Verbose=logging.WARNING,
        ConfigFile="${HOME}/.spyFtpD",
        CreateConfig=False
    )
    (self._options, args) = parser.parse_args()

    # reset list of user so that they don't get added twice 
    parser.set_defaults(User=[])

    # parse options again using a configuration file
    (self._options, args) = parser.parse_args(files=[os.path.expandvars(self._options.ConfigFile)])

    # write configuration file 
    if (self._options.CreateConfig == True):
      configFile = open(os.path.expandvars(self._options.ConfigFile), 'w')
      parser.write(configFile)
      configFile.close()
      sys.exit(0)

    # check if certificate file exits in case SSL is used and file name is given
    if ((self._options.UseSsl == True)
        and (self._options.SslCertificate != None)
        and (os.path.isfile(self._options.SslCertificate) != True)):
      _log.error("SSL certificate file doesn't exist: '%s'" % self._options.SslCertificate)
      sys.exit(1);


  def createCertificateFile(self):
    '''
    create default certificate on the fly
    '''

    ## create key
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)

    # create certificate request
    req = crypto.X509Req()
    subj = req.get_subject()
    attributes = {'ST':'Sto Plains', 'L':'Ankh-Morpork', 'O':'The Smoking Gnu'}

    for (key, value) in attributes.items():
      setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, 'md5')

    # create certificate
    cert = crypto.X509()
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)

    # certificate is valid for 1 day
    cert.gmtime_adj_notAfter(60 * 60 * 24)
    cert.set_issuer(subj)
    cert.set_subject(subj)
    cert.set_pubkey(pkey)
    cert.sign(pkey, 'md5')

    # write certificate to file
    temp = tempfile.NamedTemporaryFile(suffix='.pem',
                                   prefix='spyFtpDCert',
                                   delete=False,
                                   mode='w'
                                   )
    _log.info("Writing private key and certificate into file '%s'" % temp.name)
    temp.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    temp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    temp.close
    return temp.name




# Call the main function
if (__name__ == "__main__"):
  f = SpyFtpD()
  f.start()
