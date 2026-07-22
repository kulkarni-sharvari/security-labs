# security-labs

Personal learning notes and lab write-ups for web application security. This repository is a study log — theory notes, lab solutions, and analyses of real-world CVEs mapped to the vulnerability classes I'm learning about.

## Sources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box](https://www.hackthebox.com/)

## Structure

Organized by source, then by vulnerability class:

```
security-labs/
├── portswigger-labs/
│   ├── sqli/         # SQL injection labs + notes
│   └── xss/          # Cross-site scripting labs + notes
├── tryhackme/        # (planned)
└── hackthebox/       # (planned)
```

Each vulnerability class folder contains:
- **Theory notes** — concepts, attack techniques, defenses
- **Lab write-ups** — one file per lab, with the approach and payload used
- **Real-world exploits** — recent CVEs / incidents that abused this vulnerability class

## Vulnerability classes covered so far

- SQL Injection (login bypass, UNION attacks, retrieving hidden data, determining column count)
- Cross-Site Scripting (reflected, DOM-based)

More classes will be added as I work through the curricula.

## Disclaimer

This repo is for **educational purposes only**. All labs are performed in authorized environments provided by PortSwigger, TryHackMe, and Hack The Box. Do not apply these techniques against systems you do not own or have explicit permission to test.
