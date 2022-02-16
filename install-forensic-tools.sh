#! /bin/bash

<< ////
This is a consolidation of open source tools and custom scripts
It is a basic IR triage tools for examining Windows systems in a
Linux evnironment.  Tested on Ubuntu 20.04, Kali, Windows WSL2 and SANS SiFT

Just run this install script for a basic install
Use the "-t" switch to install additional tools\

There are several installer script if you would like to install the
GUI version of Autopsy, download yara rules or reinstall Regripper.

Downloaded tools are located in /usr/local/src/ some are copied to /usr/local/bin

# Installers:
 forensic-tools-install.sh
 RegRipper30-apt-git-Install.sh
 install-autospy-gui.sh
 get-yara-rules.sh

# General purpose timeline and forensic tools
 plaso/log2timeline
 Sleuthkit/Autopsy (Gui can be installed using install script: install-autospy-gui.sh)
 siftgrab (outputs text file results from a combination of different tools)

# Disk Mounting, Imaging and Carving
 ftkimager,ermount,ewf-tools/libewf-tools,afflib-tools,qemu-utils,libbde-utils/tools,exfat-utils,libvshadow-utils/tools
 xmount,ddrescue,photorec/testdisk,ifuse,afro,apfs-fuse,bulk_extractor

# Parsers
AnalyzeMFT,MFT_Dump,usnparser.py,Regripper 3.0,Tools from WFA 4/e, timeline tools, etc. (Harlan Carvey),
esedbexport,prefetchruncounts.py,lnkinfo,evtx_dump,PyWMIPersistenceFinder.py,CCM_RUA_Finder.py,pff-tools,
jobparser.py,bits_parser.py,Hindsight, Unfurl,Kacos2000/Queries,INDXParse.py,Volatility3,KStrike.py,sqlite_miner

# File Analysis Tools
Didier Stevens Tools,DEXRAY,iocextract,stegosuite,oletools,pefile,Density Scout

# Python Modules (installs python2, python3)
python-registry,python3-libesedb,python-evtx,libscca-python,liblnk-python,libfwsi-python

# Misc
clamav,lf,attr,libesedb-utils,liblnk-utils,libevtx-utils,pff-tools,jq,yara,rar,unrar,p7zip-full,p7zip-rar

# Gui Tools (add using " ./install-forensic-tools.sh -t")
Snap,CyberChef,Bless,Okteta,Brave,SqliteBrowser,R-Linux, LogFileParser,clamtk,Powershell,gparted,feh,eog,glogg,bless,binwalk,samba,remmina,guymager,graphviz

# Yara Rules (fetch using get-yara-rules.sh)
Nextron, ReversingLabs, yararules.com

# Directories created
  /mnt/raw
  /mnt/image_mount
  /mnt/vss
  /mnt/shadow
  /mnt/bde
  /mnt/smb
  /mnt/usb
  /cases


////

function display_usage(){
  clear
  echo "
  install-forensic-tools.sh
  Running this script will download files
  needed to install and run forensic tools on Debian x86_64 based systems

  USAGE: install-forensic-tools.sh -h -t

         -t Installs additional forensic tools
         -h Displays this help text

		 "
    exit
}

function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

function install_gift_ppa(){
  apt remove libewf2 -y
  cat /etc/issue|grep -i kali && \
  apt install gnome-terminal libewf-dev ewf-tools libbde-utils libvshadow-utils libesedb-utils xmount liblnk-utils libevtx-utils python3-libesedb plaso -y
  cat /etc/issue|grep -E "u 20"\|"u 18" && add-apt-repository ppa:gift/stable -y
  apt-get update || pause
  apt-get upgrade -q -y -u  || pause
  cat /etc/issue|grep -Ei "u 20"\|"u 18" && \
  apt install libewf-tools libbde-tools libvshadow-tools libesedb-tools liblnk-tools libevtx-tools plaso-tools bulk-extractor -y
  [ "$1" == "-t" ] && add_tools || apt install autopsy -y
}


function install_powershell(){
  hostname |grep kali && \
  apt install powershell -y || \
  apt install snapd -y &&\
  snap install powershell --classic
  pwsh -v || pause
}

function main_install(){
  apt-get install git curl python2 net-tools vim software-properties-common  -y
  install_gift_ppa

  #Set python3 as python and Install pip and pip3
  echo "Requires python2 for legacy scripts"
  echo "Assumes python3 is installed"
  which python3 && which python2 || pause

  ############### Forensic Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde,smb,usb}
  mkdir -p /cases

  #Install pip3
  pip3 -V 2>/dev/null || apt-get install python3-pip -y
  pip3 -V || pause

  #pip installs
  sift_pip_pkgs="python-evtx usnparser bs4 tabulate regex iocextract oletools bits_parser"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done

  #Install Applications from Apt
  sift_apt_pkgs="fdupes sleuthkit attr dcfldd afflib-tools qemu-utils pigz exfat-utils exif dc3dd python-is-python3 pff-tools python3-lxml sqlite3 jq yara gddrescue unzip rar unrar p7zip-full p7zip-rar stegosuite hashcat foremost testdisk chntpw graphviz ffmpeg mediainfo ifuse clamav"

  for apt_pkg in $sift_apt_pkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  #Git and configure Package Installations and Updates

  #Git analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/ 2>/dev/null)" ] && \
  git -C /usr/local/src/analyzeMFT pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
  cd /usr/local/src/analyzeMFT/
  python2 setup.py install || pause

  #Git DFIR-Script Files
  [ "$(ls -A /usr/local/src/dfir-scripts/ 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/shellscripts pull --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/shellscripts.git /usr/local/src/dfir-scripts/shellscripts
  [ "$(ls -A /usr/local/src/dfir-scripts/shellscripts)" ] && chmod 755 /usr/local/src/dfir-scripts/shellscripts/* || pause

  #Git and configure Harlan Carvey tools
  [ "$(ls -A /usr/local/src/keydet89/tools/ 2>/dev/null)" ] && \
  git -C /usr/local/src/keydet89/tools/ pull --no-rebase 2>/dev/null || \
  git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/
  chmod 755 /usr/local/src/keydet89/tools/source/* || pause
  #set Windows Perl scripts in Keydet89/Tools/source
  find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
  do
    file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
    sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!`which perl`" $d
    cp $d /usr/local/bin/$file_name || pause
  done

   #Git Hindsight
   [ "$(ls -A /usr/local/src/Hindsight/)" ] && \
   git -C /usr/local/src/Hindsight pull --no-rebase 2>/dev/null|| \
   git clone https://github.com/obsidianforensics/hindsight.git /usr/local/src/Hindsight

  #Git and configure WMI Forensics
  [ "$(ls -A /usr/local/src/WMI_Forensics/ 2>/dev/null)" ] && \
  git -C /usr/local/src/WMI_Forensics pull --no-rebase 2>/dev/null || \
  git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
  cp /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py || pause
  cp /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py || pause

  #Git apfs-fuse
  apt install fuse libfuse3-dev bzip2 libbz2-dev cmake gcc libattr1-dev zlib1g-dev -y
  [ "$(ls -A /usr/local/src/apfs-fuse/ 2>/dev/null)" ] && \
  git -C /usr/local/src/apfs-fuse pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/sgan81/apfs-fuse.git /usr/local/src/apfs-fuse && \
  cd /usr/local/src/apfs-fuse && git submodule init && git submodule update && \
  mkdir -p /usr/local/src/apfs-fuse/build && cd /usr/local/src/apfs-fuse/build && \
  cmake .. && make
  cd /usr/local/src/

  #Git Volatility3
  [ "$(ls -A /usr/local/src/volatility/ 2>/dev/null)" ] && \
  git -C /usr/local/src/volatility pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility
  chmod 755  /usr/local/src/volatility/*.py

  #Git kacos2000 Scripts
  [ "$(ls -A /usr/local/src/kacos2000/Queries 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/Queries pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

  [ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/WindowsTimeline pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline

  #Git and configure INDXParse
  [ "$(ls -A /usr/local/src/INDXParse/)" ] && \
  git -C /usr/local/src/INDXParse pull --no-rebase 2>/dev/null||\
  git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse

  #Git and configure Didier Stevens Tools
  [ "$(ls -A /usr/local/src/DidierStevensSuite/)" ] && \
  git -C /usr/local/src/DidierStevensSuite pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite

  #Git sqlite_miner
  [ "$(ls -A /usr/local/src/sqlite_miner/)" ] && \
  git -C /usr/local/src/sqlite_miner pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/threeplanetssoftware/sqlite_miner.git /usr/local/src/sqlite_miner

  #Git Afro
  [ "$(ls -A /usr/local/src/cugu/afro )" ] && \
  git -C /usr/local/src/cugu/afro || \
  git clone https://github.com/cugu/afro.git /usr/local/src/cugu/afro

  #Git Kstrike
  [ "$(ls -A /usr/local/src/KStrike)" ] && \
  git -C /usr/local/src/KStrike || \
  git clone https://github.com/brimorlabs/KStrike.git /usr/local/src/KStrike

  #Git BitsParser
  [ "$(ls -A /usr/local/src/BitsParser)" ] && \
  git -C /usr/local/src/BitsParser || \
  git clone https://github.com/fireeye/BitsParser.git /usr/local/src/

  # Use Wget and curl to download tools
  #Download mft_dump
  rm /usr/local/src/omerbenamram/mft_dump/*  || mkdir -p /usr/local/src/omerbenamram/mft_dump
  curl -s https://api.github.com/repos/omerbenamram/mft/releases/latest| \
  grep -E 'browser_download_url.*64-unknown-linux-musl'|awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/mft_dump/mft_dump "$4) }'  && \
  chmod 755 /usr/local/src/omerbenamram/mft_dump/mft_dump && cp /usr/local/src/omerbenamram/mft_dump/mft_dump /usr/local/bin/mft_dump || pause

  #Download evtx_dump
  rm /usr/local/src/omerbenamram/evtx_dump/*  || mkdir -p /usr/local/src/omerbenamram/evtx_dump
  curl -s https://api.github.com/repos/omerbenamram/evtx/releases/latest| \
  grep -E 'browser_download_url.*64-unknown-linux-musl'|awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/evtx_dump/evtx_dump "$4) }'  && \
  chmod 755 /usr/local/src/omerbenamram/evtx_dump/evtx_dump && cp /usr/local/src/omerbenamram/evtx_dump/evtx_dump /usr/local/bin/evtx_dump || pause

  #Download lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && cp /tmp/lf /usr/local/bin/lf || pause

  # Download Density Scout
  wget -O /tmp/densityscout_build_45_linux.zip https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
  unzip -o /tmp/densityscout_build_45_linux.zip -d /tmp/densityscout/
  chmod 755 /tmp/densityscout/lin64/densityscout && cp /tmp/densityscout/lin64/densityscout /usr/local/bin/

  # Download ftkimager
  wget  https://ad-zip.s3.amazonaws.com/ftkimager.3.1.1_ubuntu64.tar.gz -O - | tar -xzvf - -C /usr/local/src/dfir-scripts/
  chmod 755 /usr/local/src/dfir-scripts/ftkimager && mv /usr/local/src/dfir-scripts/ftkimager /usr/local/bin/  || pause

  #Download and configure DeXRAY
  wget -O /usr/local/src/dfir-scripts/DeXRAY.pl http://hexacorn.com/d/DeXRAY.pl
  chmod 755 /usr/local/src/dfir-scripts/DeXRAY.pl && mv /usr/local/src/dfir-scripts/DeXRAY.pl /usr/local/bin/  || pause
  curl -L http://cpanmin.us | perl - --sudo App::cpanminus
  cpanm Crypt::RC4
  cpanm Digest::CRC
  cpanm Crypt::Blowfish
  cpanm Archive::Zip
  cpanm OLE::Storage_Lite

  # Get Job Parser
  wget -O /usr/local/src/dfir-scripts/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
  mv /usr/local/src/dfir-scripts/jobparser.py /usr/local/bin/

  # Download dfir-scripts Tools
  mkdir -p /usr/local/src/dfir-scripts/{python,installers,ermount,siftgrab}
  wget -O /usr/local/src/dfir-scripts/siftgrab/siftgrab https://raw.githubusercontent.com/dfir-scripts/siftgrab/master/siftgrab || pause 
  wget -O /usr/local/src/dfir-scripts/ermount/ermount.sh https://raw.githubusercontent.com/dfir-scripts/EverReady-Disk-Mount/master/ermount.sh || pause 
  wget -O /usr/local/src/dfir-scripts/python/prefetchruncounts.py https://raw.githubusercontent.com/dfir-scripts/prefetchruncounts/master/prefetchruncounts.py || pause 
  wget -O /usr/local/src/dfir-scripts/python/winservices.py https://raw.githubusercontent.com/dfir-scripts/Python-Registry/master/winservices.py || pause 
  wget -O /usr/local/src/dfir-scripts/installers/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/RegRipper30-apt-git-Install.sh  || pause
  wget -O /usr/local/src/dfir-scripts/installers/install-autospy-gui.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/install-autospy-gui.sh  || pause
  wget -O /usr/local/src/dfir-scripts/installers/get-yara-rules.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/get-yara-rules.sh  || pause 
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_tasks.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_tasks.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_BITS.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_BITS.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_logins.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_logins.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_processes.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_processes.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_account_changes.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_account_changes.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_RDP_Local.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_RDP_Local.py || pause
  wget -O /usr/local/src/dfir-scripts/python/parse_evtx_RDP_Remote.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_RDP_Remote.py || pause
  chmod -R 755 /usr/local/src/dfir-scripts/*  || pause 
  cp /usr/local/src/dfir-scripts/siftgrab/siftgrab /usr/local/bin/siftgrab || pause
  cp /usr/local/src/dfir-scripts/ermount/ermount.sh /usr/local/bin/ermount || pause

  #install RegRipper.git and RegRipper install script
  /usr/local/src/dfir-scripts/installers/RegRipper30-apt-git-Install.sh

  #Create a symbolic link to /opt/share
  [ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share
}

function add_tools(){
  # Extended Tools Install
  #Install tools from apt
  uname -a |grep -i microsoft && exit
  extended_aptpkgs="gparted feh eog glogg bless binwalk samba remmina clamtk gridsite-clients guymager graphviz"

  for apt_pkg in $extended_aptpkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  # Install Powershell
  pwsh -v || install_powershell

  #Install additional tools from snap
  which snap || apt install snapd
  apparmor_status && systemctl enable --now snapd apparmor
  snap install brave || pause
  snap install okteta || pause
  snap install sqlitebrowser || pause


  # Install R-Linux
  wget -O /tmp/RLinux5_x64.deb  https://www.r-studio.com/downloads/RLinux5_x64.deb &&
  dpkg -i /tmp/RLinux5_x64.deb || pause

  #Git LogFileParser
  [ "$(ls -A /usr/local/src/LogFileParser/)" ] && \
  git -C /usr/local/src/LogFileParser pull --no-rebase 2>/dev/null || \
  git clone https://github.com/jschicht/LogFileParser.git /usr/local/src/LogFileParser


  #Get CyberChef
  mkdir -p /usr/local/src/CyberChef
  curl -s https://api.github.com/repos/gchq/CyberChef/releases/latest |\
  grep -E 'browser_download_url'|awk -F'"' '{system("wget -P /tmp "$4) }' && \
  unzip -o /tmp/Cyber*.zip -d /usr/local/src/CyberChef
}

[ $(whoami) != "root" ] && echo "Requires Root!" && exit
echo "cpu check"
arch |grep x86_64 || display_usage
[ "$1" == "-h" ] && display_usage
which apt && main_install || display_usage
history -c
echo ""
cat /etc/issue|grep -i kali && \
echo "*****************************************" && \
echo "To disable disk automount:" && \
echo "set org.gnome.desktop.media-handling automount false"

echo ""
echo  "   Install Complete!"
