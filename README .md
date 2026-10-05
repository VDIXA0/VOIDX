# klcp-offsec

Personal study repository for **Kali Linux Revealed (KLCP / PEN-103)** from OffSec (Offensive Security).

The repository holds my hands-on lab write-ups from working through the course in a Kali Linux virtual machine. Each chapter has its own folder with a report that records the commands I ran, what the output showed, the errors I hit and how I dealt with them, and what I learned.

This is an independent learning portfolio. It is not an official OffSec resource, and it does not claim a certification.

## About the Course

Kali Linux Revealed (PEN-103) is OffSec's course on installing, configuring, using and maintaining Kali Linux, the Debian-based distribution used for penetration testing and security work. It builds the Linux and Kali foundations that later security study depends on.

## Repository Structure

```text
klcp-offsec/
├── README.md
└── chapter-XX/
    ├── README.md        (lab report for that chapter)
    ├── *.pdf            (PDF copy of the report)
    └── images/          (screenshots used as evidence)
```

## Chapters

| Chapter | Lab | Report | Status |
| ------- | --- | ------ | ------ |
| 02 | Practical Linux command-line lab | [chapter-02](chapter-02/README.md) | Complete |

New chapters are added as I complete them.

## How the Reports Are Written

- Everything is based on screenshots of my own terminal sessions. If output is cut off or a result cannot be confirmed, the report says so instead of filling the gap.
- Mistakes and error messages are kept in, together with the troubleshooting.
- Screenshots are reviewed for sensitive data before publishing, and only the specific sensitive values would be redacted.

## Environment

- Kali Linux running as a VirtualBox virtual machine
- Standard Kali default user account

## Disclaimer

This repository contains only my own notes and lab output and does not reproduce OffSec course material. All commands were run in a virtual machine that I own, for learning purposes.
