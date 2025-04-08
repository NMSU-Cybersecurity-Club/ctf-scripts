#!/bin/bash

##
# Get Options
##



####################################################################################################
#                                         Define variables                                         #
####################################################################################################
SCRIPT_DIR="$(dirname "$(realpath "$0")")"  # Get the directory of the script
LOG_DIR="$SCRIPT_DIR/Metapod-Logs"           # Define the log directory
mkdir -p "$LOG_DIR"                           # Create the log directory if it doesn't exist
SYSLOG_FILE="$LOG_DIR/metapod-$(date '+%Y-%m-%d %H:%M:%S').log"      # Log file path

# Global variables for later use
PM=


####################################################################################################
#                                           Log function                                           #
####################################################################################################
log_message() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "\e[1;34m[INFO] $TIMESTAMP - $1\e[0m" | tee -a "$SYSLOG_FILE"
}

log_success() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "\e[1;32m[SUCCESS] $TIMESTAMP - $1\e[0m" | tee -a "$SYSLOG_FILE"
}

log_warning() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "\e[1;33m[WARNING] $TIMESTAMP - $1\e[0m" | tee -a "$SYSLOG_FILE"
    WARNINGS+=("$1")
}

log_error() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "\e[1;31m[ERROR] $TIMESTAMP - $1\e[0m" | tee -a "$SYSLOG_FILE"
}

separator=$(printf '%*s' "$(tput cols)" '' | tr ' ' '=')

WARNINGS=()


pm_detect() {
####################################################################################################
#                                    Detect the package manager                                    #
####################################################################################################
if command -v apt-get &>/dev/null; then
    PM="apt-get"
    log_success "Detected Debian/Ubuntu."
elif command -v dnf &>/dev/null; then
    PM="dnf"
    log_success "Detected Fedora."
elif command -v yum &>/dev/null; then
    PM="yum"
    log_success "Detected RHEL/CentOS."
elif command -v pacman &>/dev/null; then
    PM="pacman"
    log_success "Detected Arch Linux."
elif command -v zypper &>/dev/null; then
    PM="zypper"
    log_success "Detected openSUSE."
elif command -v emerge &>/dev/null; then
    PM="emerge"
    log_success "Detected Gentoo."
else
    log_error "Unsupported distribution."
    exit 1
fi
}


pm_update() {
####################################################################################################
#                           Update the system and install security tools                           #
####################################################################################################
log_message "Updating package indexes..."
case $PM in
    apt-get)
        sudo apt-get update -y && sudo apt-get upgrade -y
        ;;
    dnf)
        sudo dnf update -y
        ;;
    yum)
        sudo yum update -y
        ;;
    pacman)
        sudo pacman -Syu
        ;;
    zypper)
        sudo zypper refresh && sudo zypper update
        ;;
    emerge)
        sudo emerge --sync
        sudo emerge -uDN @world
        ;;
esac
log_success "System packages updated."
sudo -k
}


pm_install() {
####################################################################################################
#                      Install necessary packages (UFW, Fail2Ban, Chkrootkit)                      #
####################################################################################################
log_message "Installing necessary packages..."
case $PM in
    apt-get)
        sudo apt-get install ufw fail2ban chkrootkit -y
        ;;
    dnf)
        sudo dnf install firewalld fail2ban chkrootkit -y
        ;;
    yum)
        sudo yum install firewalld fail2ban chkrootkit -y
        ;;
    pacman)
        sudo pacman -S ufw fail2ban chkrootkit
        ;;
    zypper)
        sudo zypper install firewalld fail2ban chkrootkit
        ;;
    emerge)
        sudo emerge net-firewall/ufw net-analyzer/fail2ban net-analyzer/chkrootkit
        ;;
esac
log_success "Necessary packages installed."
sudo -k
}


set_fw() {
####################################################################################################
#                        Set up basic firewall rules using UFW or Firewalld                        #
####################################################################################################
log_message "Setting up firewall rules..."
if [[ $PM == "apt-get" || $PM == "pacman" ]]; then
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw enable
    log_success "UFW firewall rules configured."
elif [[ $PM == "dnf" || $PM == "yum" || $PM == "zypper" ]]; then
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
    sudo firewall-cmd --set-default-zone=drop
    sudo firewall-cmd --permanent --zone=drop --add-service=ssh
    sudo firewall-cmd --reload
    log_success "Firewalld configured."
fi
sudo -k
}


disable_root_ssh() {
####################################################################################################
#                                    Disable root login via SSH                                    #
####################################################################################################
log_message "Disabling root login via SSH..."
if [[ -f /etc/ssh/sshd_config ]]; then
    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    log_success "Root login via SSH disabled."
else
    log_warning "SSH configuration file not found."
fi
sudo -k
}


check_users() {
####################################################################################################
#                               Checking user accounts on the system                               #
####################################################################################################
# Define arrays for different account types
declare -a SYSTEM_ACCOUNTS
declare -a REGULAR_ACCOUNTS
declare -a SERVICE_ACCOUNTS

log_message "Checking user accounts..."
ALL_USERS=$(cut -d: -f1 /etc/passwd)
TOTAL_USERS=$(echo "$ALL_USERS" | wc -l)

# Prepare the formatted list of users
USER_LIST=""
REGULAR_USERS=""
SYSTEM_USERS=""
SERVICE_USERS=""

while IFS= read -r user; do
    USER_LIST+="  - $user\n"
    # Check for user accounts
    UID=$(id -u "$user")

    if [ "$UID" -ge 1000 ]; then
        REGULAR_USERS+="    - $user\n"
        REGULAR_ACCOUNTS+=("$user")
    elif [ "$UID" -ge 1 ] && [ "$UID" -lt 1000 ]; then
        SYSTEM_USERS+="    - $user\n"
        SYSTEM_ACCOUNTS+=("$user")
    fi
done <<< "$ALL_USERS"

# Calculate total regular users and system users
TOTAL_REGULAR_USERS=${#REGULAR_ACCOUNTS[@]}
TOTAL_SYSTEM_USERS=${#SYSTEM_ACCOUNTS[@]}
TOTAL_SERVICE_USERS=${#SERVICE_ACCOUNTS[@]}  # Adjust this if you're tracking service accounts differently

# Display total and list of users
echo -e "\e[1;34m[USER ACCOUNTS]\e[0m"
echo -e "  - Total users: $TOTAL_USERS"
echo -e "  - List of all users:"
echo -e "$USER_LIST"
sudo -k
}


disable_services() {
####################################################################################################
#                          Disable unused services (e.g., telnet, rlogin)                          #
####################################################################################################
log_message "Disabling unused services..."
if [[ $PM == "apt-get" ]]; then
    sudo systemctl disable telnet.socket
    sudo systemctl disable rlogin.socket
    sudo systemctl stop telnet.socket
    sudo systemctl stop rlogin.socket
elif [[ $PM == "dnf" || $PM == "yum" ]]; then
    sudo systemctl disable telnet.socket
    sudo systemctl disable rsh.socket
    sudo systemctl stop telnet.socket
    sudo systemctl stop rsh.socket
fi
log_success "Unused services disabled."
sudo -k
}


assign_pp() {
####################################################################################################
#                                     Assign password policies                                     #
####################################################################################################
log_message "Enforcing password policies..."
case $PM in
    apt-get)
        sudo apt-get install libpam-pwquality -y
        sudo sed -i 's/# minlen = 9/minlen = 12/' /etc/security/pwquality.conf
        sudo sed -i 's/# dcredit = 1/dcredit = -1/' /etc/security/pwquality.conf
        sudo sed -i 's/# ucredit = 1/ucredit = -1/' /etc/security/pwquality.conf
        sudo sed -i 's/# lcredit = 1/lcredit = -1/' /etc/security/pwquality.conf
        sudo sed -i 's/# ocredit = 1/ocredit = -1/' /etc/security/pwquality.conf
        ;;
    dnf | yum)
        sudo dnf install pam_pwquality -y
        sudo sed -i 's/# minlen = 9/minlen = 12/' /etc/security/pwquality.conf
        ;;
    pacman)
        sudo pacman -S libpwquality
        sudo sed -i 's/# minlen = 9/minlen = 12/' /etc/security/pwquality.conf
        ;;
    zypper)
        sudo zypper install pam_pwquality -y
        sudo sed -i 's/# minlen = 9/minlen = 12/' /etc/security/pwquality.conf
        ;;
    emerge)
        sudo emerge sys-libs/pam
        log_warning "Password quality settings can be manually configured in /etc/security."
        ;;
esac
log_success "Password policies enforced."
sudo -k
}


config_f2b() {
####################################################################################################
#                                        Configure Fail2Ban                                        #
####################################################################################################
log_message "Configuring Fail2Ban for SSH protection..."
cat <<EOL | sudo tee /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOL
sudo systemctl restart fail2ban
log_success "Fail2Ban configured and restarted."
sudo -k
}


install_audit() {
####################################################################################################
#                      Install and configure auditd for logging system events                      #
####################################################################################################
log_message "Installing and configuring auditd..."
case $PM in
    apt-get)
        sudo apt-get install auditd audispd-plugins -y
        ;;
    dnf | yum)
        sudo dnf install audit -y
        ;;
    pacman)
        sudo pacman -S audit
        ;;
    zypper)
        sudo zypper install audit
        ;;
    emerge)
        sudo emerge sys-process/audit
        ;;
esac
sudo systemctl enable auditd
sudo systemctl start auditd
log_success "auditd installed and enabled."
sudo -k
}


rootkit_scan() {
####################################################################################################
#                                 Run rootkit scan with chkrootkit                                 #
####################################################################################################
log_message "Running rootkit scan with chkrootkit. This may take some time..."
if command -v chkrootkit &>/dev/null; then
    CHKROOTKIT_OUTPUT=$(sudo chkrootkit 2>&1)
    if echo "$CHKROOTKIT_OUTPUT" | grep -q "INFECTED"; then
        log_warning "chkrootkit found potential infections or issues:"
        echo "$CHKROOTKIT_OUTPUT" | tee -a "$SYSLOG_FILE"
    else
        log_success "chkrootkit found no issues."
    fi
else
    log_warning "chkrootkit is not installed or could not run."
fi
sudo -k
}


set_perms() {
####################################################################################################
#                               Set permissions for key system files                               #
####################################################################################################
log_message "Setting file permissions for sensitive files..."
sudo chmod 644 /etc/ssh/sshd_config /etc/passwd /etc/shadow /var/log/auth.log 2>/dev/null
log_success "File permissions set."
sudo -k
}


unattended_upgrades() {
####################################################################################################
#                                   Enable auto security updates                                   #
####################################################################################################
log_message "Enabling automatic security updates..."
case $PM in
    apt-get)
        sudo apt-get install unattended-upgrades -y
        sudo dpkg-reconfigure --priority=low unattended-upgrades
        ;;
    dnf | yum)
        sudo dnf install dnf-automatic -y
        sudo systemctl enable --now dnf-automatic.timer
        ;;
    pacman)
        # Pacman does not have a default automatic update tool. Could use cron jobs.
        log_warning "No default automatic updates for Arch. Consider using pacman-updater."
        ;;
    zypper)
        sudo zypper install zypper-automatic -y
        sudo systemctl enable --now zypper-automatic.timer
        ;;
    emerge)
        echo "sys-apps/portage sync" >> /etc/crontab
        ;;
esac
log_success "Automatic security updates enabled."
sudo -k
}


pm_autoremove() {
####################################################################################################
#                                     Clean up unused packages                                     #
####################################################################################################
log_message "Removing unused packages..."
case $PM in
    apt-get)
        sudo apt-get autoremove -y
        ;;
    dnf)
        sudo dnf autoremove -y
        ;;
    pacman)
        sudo pacman -Rns $(pacman -Qdtq)
        ;;
    zypper)
        sudo zypper remove --clean-deps
        ;;
    emerge)
        sudo emerge --depclean
        ;;
esac
log_success "Unnecessary packages removed."
sudo -k
}


log_net() {
####################################################################################################
#                                Log open ports and active services                                #
####################################################################################################
log_message "Checking open ports and active services..."
sudo ss -tuln | tee -a $SYSLOG_FILE
sudo systemctl list-units --type=service --state=active | tee -a $SYSLOG_FILE

if command -v ss &>/dev/null; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN)
elif command -v netstat &>/dev/null; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN)
else
    log_warning "Neither 'ss' nor 'netstat' command found to check listening ports."
fi

log_success "Open ports and active services logged."
sudo -k
}


####################################################################################################
#                                          Script Summary                                          #
####################################################################################################
display_summary() {
    echo -e "\n\e[1;36m===== SCRIPT SUMMARY =====\e[0m"

    # Show warnings
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "\e[1;33m[WARNINGS]\e[0m"
        for warning in "${WARNINGS[@]}"; do
            echo -e "  - $warning"
        done
    else
        echo -e "\e[1;32m[SUCCESS] All checks passed without warning!\e[0m"
    fi

    # chkrootkit results summary
    if [ -n "$CHKROOTKIT_OUTPUT" ] && echo "$CHKROOTKIT_OUTPUT" | grep -q "INFECTED"; then
        echo -e "\e[1;31m[CHKROOTKIT RESULTS]\e[0m"
        echo "  - $CHKROOTKIT_OUTPUT" | grep "INFECTED" | tee -a "$SYSLOG_FILE"
    fi

    # Open listening ports summary
    echo -e "\e[1;34m[OPEN LISTENING PORTS]\e[0m"
    if [ -n "$LISTENING_PORTS" ]; then
        echo -e "$LISTENING_PORTS" | awk '{print "  - "$0}' | tee -a "$SYSLOG_FILE"
    else
        echo -e "  - No open listening ports found or could not retrieve them."
    fi

    # User accounts summary
    echo -e "\e[1;34m[USER ACCOUNT SUMMARY]\e[0m"
    echo -e "  - Total users: $TOTAL_USERS"

    # Regular users summary
    echo -e "  - Total regular users: $TOTAL_REGULAR_USERS"
    if [[ $TOTAL_REGULAR_USERS -gt 0 ]]; then
        printf "%b" "$REGULAR_USERS"
    else
        echo "     - No regular users found."
    fi

    # System accounts summary
    echo -e "  - Total system users: $TOTAL_SYSTEM_USERS"
    if [[ $TOTAL_SYSTEM_USERS -gt 0 ]]; then
        printf "%b" "$SYSTEM_USERS"
    else
        echo "     - No system users found."
    fi

    # Service accounts summary
    echo -e "  - Total service users: $TOTAL_SERVICE_USERS"  # Corrected
    if [[ ${#SERVICE_ACCOUNTS[@]} -gt 0 ]]; then
        printf "%b" "$SERVICE_USERS"
    else
        echo "     - No service accounts found."
    fi

    echo -e "\e[1;36m==========================\e[0m\n"
}

usage() {
    echo "Usage: $0 [flags]"
    echo "  -d  Detect package manager (required for some operations)"
    echo "  -u  Update PM indexes"
    echo "  -c  Clean unused packages"
    echo "  -i  Install packages UFW, Fail2Ban, and Chkrootkit"
    echo "  -2  Configure Fail2Ban"
    echo "  -f  Setup firewall"
    echo "  -s  Disable root SSH"
    echo "  -r  Check the user accounts on the system"
    echo "  -w  Disable services such as telnet and rlogin"
    echo "  -p  Assign standard password policies"
    echo "  -a  Install and enable auditd"
    echo "  -k  rootkit scan with chkrootkit"
    echo "  -n  Log network stats and services"
    echo "  -P  Set permissions for system files (passwd, etc.)"
    echo "  -U  Enable unattended upgrades"
    echo
    echo "A complete summary will always be printed after all actions run"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

sudo -k

# Parse the flags
while getopts "duci2fsrwpaknPU" flag; do
    case "${flag}" in
        d) pm_detect ;;
        u) pm_update ;;
        c) pm_autoremove ;;
        i) pm_install ;;
        2) config_f2b ;;
        f) set_fw ;;
        s) disable_root_ssh ;;
        r) check_users ;;
        w) disable_services ;;
        p) assign_pp ;;
        a) install_audit ;;
        k) rootkit_scan ;;
        n) log_net ;;
        P) set_perms ;;
        U) unattended_upgrades ;;
        *) usage ;;
    esac
done

display_summary

