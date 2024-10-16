![Hivestorm Logo](https://www.hivestorm.org/images/header-hs.png)

# Hivestorm CTF Checklist - Charlie Team

Epiphany is upon you. Your pilgrimage has begun. Enlightenment awaits.

## Pre-checklist

1. Install VMWare Workstation Pro
1. Download competition OVAs
1. Set host system clock to correct time

## General System Checklist

1. If appliciable, read "Forensics Questions" files before modifying system
1. Update system applications

   - Rocky Linux Package Manager - DNF
   - Linux Mint Package Manager - apt

   See [Update System and Application Packages (Linux)](#update-system-and-application-packages-linux)

   See [Update system applications (Windows)](#update-system-applications-windows)

1. Update Firmware and Security Patches

   See [Update System and Application Packages (Linux)](#update-system-and-application-packages-linux) (Step 2)


   See [System and Security Patches (Windows)](#system-and-security-patches-windows)

1. System Hardening

   See [Install and Configure Hardening Tools (Linux)](#install-and-configure-hardening-tools-linux)

1. Configure Remote Access Protocols

   See [Install and Configure SSH (Linux)](#install-and-configure-ssh-linux)

   See [Install and Configure RDP (Windows)](#install-and-configure-rdp-windows)

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

## Linux System Checklist

### Update System and Application Packages (Linux)

   Debian/apt-based systems:
   ```bash
   # Update and install packages
   sudo apt update && sudo apt upgrade -y

   # Install unattended-upgrades
   sudo apt install unattended-upgrades

   # Update Firmware using fwupd
   sudo fwupdmgr update
   ```

   Red Hat Enterprise Linux (RHEL) based systems:
   ```bash
   # DNF update and install packages
   sudo dnf update -y

   # YUM update and install packages
   sudo yum update -y
   ```

   Universal Package Managers (Snap & Flatpak):
   ```bash
   # Update snap packages
   sudo snap refresh

   # Update flatpak packages
   flatpak update
   ```

### Install and Configure Hardening Tools (Linux)

   Install and Configure fail2ban:
   ```bash
   # Install Fail2Ban
   sudo apt install fail2ban -y         # For Debian/Ubuntu
   sudo dnf install fail2ban -y         # For Fedora/RHEL
   sudo pacman -S fail2ban --noconfirm  # For Arch-based

   # Enable and start Fail2Ban service
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

   Disable Telnet:
   ```bash
   # Disable Telnet
   # Disable and remove telnet service (if installed)
   sudo systemctl disable telnet.socket
   sudo systemctl stop telnet.socket
   sudo apt remove telnet -y            # For Debian/Ubuntu
   sudo dnf remove telnet -y            # For Fedora/RHEL
   sudo pacman -R telnet --noconfirm    # For Arch-based
   ```

   Install and run chkrootkit:
   ```bash
   # Install chkrootkit
   sudo apt install chkrootkit -y                  # For Debian/Ubuntu
   sudo dnf install chkrootkit -y                  # For Fedora/RHEL
   sudo pacman -S chkrootkit --noconfirm           # For Arch-based

   # Run chkrootkit
   sudo chkrootkit
   ```

### Password Security (Linux)

   1. Open and edit pam password configuration:
      ```bash
      sudo nano /etc/pam.d/common-password
      ```
   1. Locate pam_unix.so
      ```bash
      minlen=10
      ```

### Install and Configure SSH (Linux)
   
   1. Install OpenSSH (skip if already installed):
      ```bash
      sudo apt install openssh-server
      ```
   1. Open SSH configuration file
      ```bash
      sudo nano /etc/ssh/sshd_config
      ```
   1. Find and modify the following lines:
      ```bash
      PermitRootLogin no
      PermitEmptyPasswords no
      ```
   1. Restart SSH service to apply changes
      ```bash
      sudo systemctl reload sshd
      ```

## Windows System Checklist

### System and Security Patches (Windows)
   Open PowerShell with Administrator privileges

   ```powershell
   # Install and import the Windows update module
   Install-Module PSWindowsUpdate
   Import-Module PSWindowsUpdate

   # Check and install available updates
   Get-WindowsUpdate
   Install-WindowsUpdate -AcceptAll
   ```

### Update system applications (Windows)
   Open PowerShell with Administrator privileges

   ```powershell
   # Source update / troubleshoot
   winget source update

   # Update all packages
   winget upgrade --all --accept-package-agreements --accept-source-agreements
   ```

### Install and Configure RDP (Windows)
   Open PowerShell with Administrator privileges

   ```powershell
   # Source update / troubleshoot
   winget source update

   # Update all packages
   winget upgrade --all --accept-package-agreements --accept-source-agreements
   ```

## Tips

### General

- Find CNAME
  > nslookup -q=cname domain.com

### Linux
- Scan file system for a file:
   ```bash
   sudo find / -name "filename"

   sudo locate "*.fileextension""
   ```

### Windows
- CTT Ultimate Windows Utility
   > iwr -useb https://christitus.com/win | iex

## Additional Notes

- Only one client may virtualize a system at a time.
- Services, programs, or program files under the name "CCS" (Cyber Competition System) are related to Hivestorm's point system. DO NOT STOP, MODIFY, OR REMOVE ANY CCS RELATED ITEMS.
  - CCS Client files may be stored under "C:\CCS" or "/opt/CCS"
- Not every security issue is scored on each VM. You may find misconfigurations, incorrect
  settings, malware etc. that are not scored even if you address them.
