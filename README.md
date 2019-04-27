# enumpossible
Checks a list of SSH servers for password-based auth availability and for the existence of SSH user enumeration  vulnerability (CVE-2018-15473) in those identified.

Uses a slightly modified version of [https://www.exploit-db.com/exploits/45939](https://www.exploit-db.com/exploits/45939) by [@LeapSecurity](https://www.twitter.com/@LeapSecurity) to check for CVE-2018-15473.

![screenshot](https://raw.githubusercontent.com/securemode/enumpossible/master/screenshot.png)

### Usage:
```
git clone https://github.com/securemode/enumpossible.git
```
Takes a list of servers in ip:port format:
```
# ./enumpossible.sh servers.txt
```
