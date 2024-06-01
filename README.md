# Authentication bypass with path parameter in OpenMetadata (CVE-2024-28255) - exploit script

## Introduction

OpenMetadata is an advanced platform designed to unify data discovery, observability, and governance. It leverages a central metadata repository to provide in-depth data lineage, facilitate seamless team collaboration, and ensure robust governance across an organization’s data ecosystem.

The vulnerability (CVE-2024-28255) lies in the JwtFilter, which handles API authentication by verifying JWT tokens. An attacker can exploit this by inserting arbitrary strings into path parameters, bypassing JWT validation, and gaining unauthorized access to any endpoint, including those leading to potential SpEL expression injection. This bypass can lead to severe security breaches, compromising the integrity and confidentiality of the system.

##  Usage
```
usage: exploit.py [-h] --target TARGET --cmd CMD

Exploit script

options:
  -h, --help       show this help message and exit
  --target TARGET  Target URL
  --cmd CMD        Command to execute
```

## Disclaimer

This exploit script has been created solely for research and the development of effective defensive techniques. It is not intended to be used for any malicious or unauthorized activities. The script's author and owner disclaim any responsibility or liability for any misuse or damage caused by this software. Just so you know, users are urged to use this software responsibly and only by applicable laws and regulations. Use responsibly.
