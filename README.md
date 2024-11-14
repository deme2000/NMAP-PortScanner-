# NMAP-PortScanner

A customizable network scanning script that allows you to:
- Scan a single IP, subnet, or a list of hosts from a file.
- Identify live hosts using various techniques.
- Perform port scans (TCP/UDP) to detect open ports.
- Conduct detailed service discovery on open ports to gather specific service information.

The script includes configurable OPSEC levels for different scanning techniques, ensuring a balance between stealth and thoroughness. Perfect for penetration testing and network reconnaissance tasks.

## Scan Methodology

- Input IP, Subnet or file containing one host per line.
- Scan the input to find aline hosts.
- Scan the alive hosts on all ports to identify open ports.
- Perform a deep scan of the open ports to find the specific details of the services.

## Additional OPSEC flags

Change User Agents when scanning HTTP services:
- `--script-args http.useragent="some ua"`

Change default value on `/usr/share/nmap/nselib/http.lua`:
- `local USER_AGENT = stdnse.get_script_args('http.useragent') or "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"`
