#!/bin/bash

# Ensure script is run with root privileges
if [[ "$EUID" -ne 0 ]]; then
  echo "This script must be run as root. Please use 'sudo'."
  exit 1
fi

# Step 1: Install Zsh, dependencies, and fonts
apt update && apt install -y zsh curl git fonts-powerline fonts-firacode dconf-cli
fc-cache -fv

# Step 2: Install Oh My Zsh system-wide
if [ ! -d "/usr/share/oh-my-zsh" ]; then
    git clone https://github.com/ohmyzsh/ohmyzsh.git /usr/share/oh-my-zsh
    chown -R root:root /usr/share/oh-my-zsh
fi

# Step 3: Download the custom theme to the global theme directory
curl -fsSL "https://raw.githubusercontent.com/clamy54/kali-like-zsh-theme/master/kali-like.zsh-theme" -o /usr/share/oh-my-zsh/themes/kali-like.zsh-theme

# Step 4: Create or append to the global Oh My Zsh configuration file
echo "export ZSH=/usr/share/oh-my-zsh" > /etc/zsh/zshrc
echo "ZSH_THEME=\"kali-like\"" >> /etc/zsh/zshrc
echo "source \$ZSH/oh-my-zsh.sh" >> /etc/zsh/zshrc
echo "alias ls='ls --color=auto'" >> /etc/zsh/zshrc

# Step 5: Configure Zsh for new users
ln -sf /etc/zsh/zshrc /etc/skel/.zshrc
sed -i 's/^DSHELL=.*$/DSHELL=\/bin\/zsh/' /etc/adduser.conf

# Step 6: Create or link .zshrc for existing users
# This bypasses the zsh-newuser-install wizard
for user in $(getent passwd | cut -d: -f1); do
    if [ -d "/home/$user" ]; then
        if [ ! -f "/home/$user/.zshrc" ]; then
            ln -sf /etc/zsh/zshrc "/home/$user/.zshrc"
            chown -h "$user":"$user" "/home/$user/.zshrc"
        fi
    fi
done

# Force creation for the root user if it doesn't exist
if [ ! -f "/root/.zshrc" ]; then
    ln -sf /etc/zsh/zshrc "/root/.zshrc"
fi

# Step 7: Change the default shell for all targeted users
for user in $(getent passwd | cut -d: -f1); do
    if [ -d "/home/$user" ] || [ "$user" == "root" ]; then
        chsh -s "$(which zsh)" "$user"
    fi
done

# Step 8: Configure Fira Code font for specific users using GNOME Terminal
# Set font for 'siftgrab' user
if id "siftgrab" &>/dev/null; then
    sudo -u siftgrab dconf write /org/gnome/terminal/legacy/profiles:/default/use-system-font false
    sudo -u siftgrab dconf write /org/gnome/terminal/legacy/profiles:/default/font "'Fira Code Regular 12'"
    echo "Fira Code font configured for siftgrab in GNOME Terminal."
fi

# Set font for 'root' user
dconf write /org/gnome/terminal/legacy/profiles:/default/use-system-font false
dconf write /org/gnome/terminal/legacy/profiles:/default/font "'Fira Code Regular 12'"
echo "Fira Code font configured for root in GNOME Terminal."

echo "Zsh, Oh My Zsh, and the Kali-like theme have been installed and configured."
echo "Please log out and back in for changes to take full effect."
echo "If using a terminal other than GNOME, the font may need to be set manually."

