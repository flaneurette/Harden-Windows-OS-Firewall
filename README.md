# Harden-Windows-OS-Firewall

A Powershell script that hardens firewall rules for Windows OS, and disables many things. Be sure to manually check the file (and possibly translate certain feature names if your locale is different. Currently only supports English/Dutch)

Run this command in Windows Powershell (as administrator), navigate to the location of the harden.ps1 file and type: 

> powershell -ExecutionPolicy Bypass -File .\harden.ps1

# More security

By default, Windows OS allows many incoming services to connect to **any** port from **any** destination. This is very **bad/lazy** security practice. Most people have dozens of open ports on their Windows machine, by **default**.

You can close 95-98% of **all incoming services or ports** it will not affect your system whatsoever.

If you do this, your Windows machine becomes basically unreadable from outside. (=what we want for strong security)

1. Presse Win key (windows symbols) + R key
2. Type: firewall.cpl
3. Click on "advanced settings"
4. Right the first item in the left bar: Windows Defender Firewall with advanced security blah. blah.
5. Click properties
6. At firewall state -> inbound connections, set it to BLOCK.
7. Close dialog

Then: Click **inbound rules** in left menu.

Select **ALL** incoming rules, **except** for these blocks:

- Full list: Block <port no.> (Only present if you followed previous advice)
- Full list: Core Networking
- Full list: Network discovery
- Full list: Tailscale (or other VPN if you run it)
- WFD ASP Coordination
- WFD Driver-only.

When all others are selected, right-click: **Disable Rule(s)** 

This should lock down **ALL** incoming requests. (you don't need them)

Later on, when a service does complain, you could explicity allow the service by opening the firewall again. (never happened to me, though)

### Test it.

Get a **free LAN scanner app** on Google play, and test your local LAN network. Select your PC IP and scan it. All 65550 ports should basically be closed, or unreachable by now.

Making it **impossible** for anyone to connect to your PC.

- That said, if you install malware (by opening attachments or installers), this will not be of any benefit. (your own fault then).

- Never open stuff immediately. Use **multiple** anti-virus software (at least 2 or 3 as not all AV sofware can detect everything).
  
- Then, for the final arbiter, use https://www.virustotal.com to scan an app for free.

- Then run the software in **Sandboxy Plus** to test it, and restrict internet access to it, and write permissions.

  If you follow **all** these steps, you will likely never have a compromised machine.



