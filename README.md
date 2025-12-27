# spyftpd

spyFtpD (Simple Python FTP Daemon) is a lightweight command‑line wrapper around the [pyftpdlib](https://github.com/giampaolo/pyftpdlib) library, giving you a quick way to launch an FTP server without dealing with configuration files or setup overhead.

## Quick start
- Dependencies:
   - "pyasyncore >= '3.12'"
   - "pyasynchat >= '3.12'"
- Install 
  - Binary: download and add to $PATH
  
## Examples
```bash
# Start FTP server with anonymous read-only access
spyftpd.py -a .
```

## License
- Licensed under the MIT License — see LICENSE.

## Further remarks

Security and hardening are intentionally not priorities of this tool. If you need a robust, secure, and high‑performance FTP server, there are many more suitable alternatives available.


