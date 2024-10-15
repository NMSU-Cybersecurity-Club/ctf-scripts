![Hivestorm Logo](https://www.hivestorm.org/images/header-hs.png)

# Hivestorm CTF Checklist - Charlie Team

## Pre-checklist

1. Install VMWare Workstation Pro
1. Download competition OVAs
1. Set host system clock to correct time

## General System Checklist

1. If appliciable, read "Forensics Questions" files before modifying system
1. Update system applications

   - Rocky Linux Package Manager - DNF
   - Linux Mint Package Manager - apt

   ```bash
   # Debian/Ubuntu-based systems
   sudo apt update && sudo apt upgrade -y

   # Fedora-based systems (DNF)
   sudo dnf update -y

   # Fedora alternative (YUM)
   sudo yum update -y

   # Arch-based systems
   sudo pacman -Syu --noconfirm

   # openSUSE-based systems
   sudo zypper refresh && sudo zypper update -y

   # Updating Snap packages
   sudo snap refresh

   # Updating Flatpak packages
   flatpak update
   ```

1. Firmware and Unattended Upgrades

   ```bash
     # Unattended-upgrades for Automatic Updates (Ubuntu-based)
     # Install unattended-upgrades package
     sudo apt install unattended-upgrades

     # Configure unattended-upgrades
     sudo dpkg-reconfigure unattended-upgrades

     # Updating Firmware (using fwupd)
     sudo fwupdmgr update
   ```

1. Install and configure hardening tools

   ```bash
   # Install Fail2Ban to protect against brute force attacks
   sudo apt install fail2ban -y         # For Debian/Ubuntu
   sudo dnf install fail2ban -y         # For Fedora/RHEL
   sudo pacman -S fail2ban --noconfirm  # For Arch-based

   # Enable and start Fail2Ban service
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban


   # Disable Telnet
   # Disable and remove telnet service (if installed)
   sudo systemctl disable telnet.socket
   sudo systemctl stop telnet.socket
   sudo apt remove telnet -y            # For Debian/Ubuntu
   sudo dnf remove telnet -y            # For Fedora/RHEL
   sudo pacman -R telnet --noconfirm    # For Arch-based


   # Install and run chkrootkit to check for rootkits
   # Install chkrootkit
   sudo apt install chkrootkit -y                  # For Debian/Ubuntu
   sudo dnf install chkrootkit -y                  # For Fedora/RHEL
   sudo pacman -S chkrootkit --noconfirm           # For Arch-based

   # Run chkrootkit
   sudo chkrootkit
   ```

1. Disable Root login over SSH

   ```bash
   # Open SSH configuration file
   sudo nano /etc/ssh/sshd_config

   # Find and change the line:
   PermitRootLogin no

   # Restart SSH service to apply changes
   sudo systemctl restart sshd
   ```

1. Security policies
   - Account password policies (i.e., password complexity, password length, password history, ...)
   - Remote access policies (i.e., RDP, SSH)
   - Default application policies (i.e., Browser, Antivirus)
   - Firewall policies
1. User and account permissions
   - Remote access
   - Administrator / sudo
1. User account passwords
   - Reset account passwords unless otherwise advised

## IDK other notes that might be important

- Find CNAME
  > nslookup -q=cname domain.com

## Additional Notes

- Only one client may virtualize a system at a time.
- Services, programs, or program files under the name "CCS" (Cyber Competition System) are related to Hivestorm's point system. DO NOT STOP, MODIFY, OR REMOVE ANY CCS RELATED ITEMS.
  - CCS Client files may be stored under "C:\CCS" or "/opt/CCS"
- Not every security issue is scored on each VM. You may find misconfigurations, incorrect
  settings, malware etc. that are not scored even if you address them.
