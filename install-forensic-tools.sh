#! /bin/bash

<< ////
This is a consolidation of open source tools and custom scripts
It is a basic IR triage tools for examining Windows systems in a 
Linux evnironment.  Tested on Ubuntu 20.04 and Kali Windows WSL2

Just run this install script for a basic install
Use the "-t" switch to install additional tools\

There are several installer script if you would like to install the
GUI version of Autopsy, download yara rules or reinstall Regripper.

Downloaded tools are located in /usr/local/src/ some are copied to /usr/local/bin

Installers:  
# forensic-tools-install.sh
# RegRipper30-apt-git-Install.sh
# install-autospy-gui.sh
# get-yara-rules.sh

General purpose forensic tool
# siftgrab (Repurposed and updated all-in-one triage script I wrote for a SANS gold paper) 

Disk Imaging and mounting
# ftkimager
# ermount
# ewf-tools
# afflib-tools
# qemu-utils 
# libbde-utils 
# exfat-utils
# libvshadow-utils
# xmount
# ddrescue 
# testdisk 
# ifuse
# afro
# apfs-fuse

Artifact			|   Parser 
# $MFT				|	AnalyzeMFT,MFT_Dump
# $USNJRNL			|	usnparser.py
# Registry			|	Regripper 3.0
# Usrclass.dat			|	Regripper 3.0
# amcache.hve			|	Regripper 3.0
# Srudb.dat 			|	esedbexport
# Webcachev0x.dat		|	esedbexport
# Alt. DataStreams		|	ads2tln.sh  
# Prefetch 			|	prefetchruncounts.py
# lnk files			|	lnkinfo
# Index.dat 			|	parseie.pl
# WindowsEvent Logs		|	parse_evtx 
# RecycleBin        		|	siftgrab
# OBJECTS.DATA 			|	PyWMIPersistenceFinder.py,CCM_RUA_Finder.py
# Outlook Mailbox		|	pff-tools
# Scheduled Tasks 		|	jobparser.py
# BITS(qmgr.db)			|	bits_parser.py
# Browser Artifacts		|	Hindsight, Kacos2000/Queries
# $INDX				|	INDXParse.py
# WindowsTimeline		|	Kacos2000/WindowsTimeline
# RAM				|	Volatility3
# User Access Logs		|	KStrike.py
# ADS               		|	siftgrab
# and more!

Windows Event Log Parsers (csv):
# Security.evtx (logins)
# Security.evtx (processes)
# Security.evtx (account changes)
# Microsoft-Windows-Bits-Client/Operational.evtx 
# Microsoft-Windows-TaskScheduler4Operational.evtx
# Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
# Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx

Directories created
#  /mnt/raw 
#  /mnt/image_mount
#  /mnt/vss
#  /mnt/shadow
#  /mnt/bde
#  /mnt/smb
#  /cases

Decoding and Carving Tools
Floss, DEXRAY

Graphic Image
python-registry, pefile, Didier Stevens Tools, iocextract,
DeXRAY, oletools, attr(ADS), python3-libesedb, libesedb-utils,liblnk-utils, libevtx-utils, 
pff-tools,PyWMIPersistenceFinder, CCM_RUA_Finder, kacos2000(WindowsTimeline, Sqlite Scripts),
WFA Tools, LogFileParser, jq  feh yara  rar unrar p7zip-full p7zip-rar python-jinja2 stegosuite,
foremost "

Gui Applications
# CyberChef

# CyLR
# Powershell 
# Sleuthkit  
# Bulk Extractor (Uncoinfigured)

Entropy 
# Density Scout

File Manager
# lf file browser

# graphviz
# clamav, clamtk

Yara Rules
Thor (open source), ReversingLabs, yararules.com

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

function install_powershell(){  
  hostname |grep kali && \
  apt install powershell -y || \
  apt install snapd -y &&\   
  snap install powershell --classic
  pwsh -v || pause
}

function main_install(){
  add-apt-repository ppa:gift/stable -y || pause
  apt-get update || pause
  apt-get upgrade -q -y -u  || pause
  apt-get install git curl python2 net-tools vim mlocate  -y || pause
  
  #Set python3 as python and Install pip and pip3
  echo "Requires python2 for legacy scripts"
  echo "Assumes python3 is installed"
  which python3 && which python2 || pause
  
  ############### Forensic Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde,smb}
  mkdir -p /cases

  #Install pip3
  pip3 -V 2>/dev/null || apt-get install python3-pip -y 
  pip3 -V || pause
  
  #pip installs
  sift_pip_pkgs="usnparser bs4 python-evtx libscca-python liblnk-python python-registry pefile libfwsi-python regex iocextract oletools launchpadlib hindsight unfurl"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done

  #Install Applications from Apt
  sift_apt_pkgs="fdupes sleuthkit attr dcfldd ewf-tools afflib-tools qemu-utils libbde-utils pigz python3-libesedb exfat-utils libvshadow-utils xmount libesedb-utils exif dc3dd python-is-python3 liblnk-utils libevtx-utils pff-tools python3-lxml sqlite3 jq yara gddrescue unzip rar unrar p7zip-full p7zip-rar python-jinja2 stegosuite hashcat foremost testdisk chntpw graphviz ifuse"

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

  #Git IRIT Files
  [ "$(ls -A /usr/local/src/irit/ 2>/dev/null)" ] && \
  git -C /usr/local/src/irit pull --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/irit.git /usr/local/src/irit
  [ "$(ls -A /usr/local/src/irit/)" ] && chmod 755 /usr/local/src/irit/* || pause

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
  #mkdir -p /usr/local/src/kacos2000 \
  git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

  [ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline 2>/dev/null)" ] && \
  git -C /usr/local/src/kacos2000/WindowsTimeline pull --no-rebase 2>/dev/null|| \
  #mkdir -p /usr/local/src/kacos2000
  git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline
  
  #Git and configure INDXParse
  [ "$(ls -A /usr/local/src/INDXParse/)" ] && \
  git -C /usr/local/src/INDXParse pull --no-rebase 2>/dev/null||\
  git clone https://github.com/williballenthin/INDXParse.git /usr/local/src/INDXParse

  #Git and configure Didier Stevens Tools
  [ "$(ls -A /usr/local/src/DidierStevensSuite/)" ] && \
  git -C /usr/local/src/DidierStevensSuite pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/DidierStevens/DidierStevensSuite.git /usr/local/src/DidierStevensSuite
  
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
  #Download MFT_dump
  mkdir -p /usr/local/src/mft_dump
  curl -s https://api.github.com/repos/omerbenamram/mft/releases/latest| \
  grep -E 'browser_download_url.*unknown-linux-gnu.tar.gz'|awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/mft*.gz -C /usr/local/src/
  chmod 755 /usr/local/src/mft_dump/mft_dump && cp /usr/local/src/mft_dump/mft_dump /usr/local/bin/ || pause

  # Download parse_evtx
  wget -O /tmp/parse_evtx https://github.com/KasperskyLab/ForensicsTools/raw/master/BINARIES/Linux_64/parse_evtx || pause
  chmod 755 /tmp/parse_evtx && cp /tmp/parse_evtx /usr/local/bin/

 #Download lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && cp /tmp/lf /usr/local/bin/lf || pause

  # Download Floss
  curl -s https://api.github.com/repos/fireeye/flare-floss/releases/latest | \
  grep -E 'browser_download_url'| grep linux.zip |\
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  unzip -o /tmp/floss*linux.zip -d /tmp/
  chmod 755 /tmp/floss && cp /tmp/floss /usr/local/bin/floss || pause

  # Download Density Scout
  wget -O /tmp/densityscout_build_45_linux.zip https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip || pause
  unzip -o /tmp/densityscout_build_45_linux.zip -d /tmp/densityscout/
  chmod 755 /tmp/densityscout/lin64/densityscout && cp /tmp/densityscout/lin64/densityscout /usr/local/bin/
  
  # Download ftkimager
  wget  https://ad-zip.s3.amazonaws.com/ftkimager.3.1.1_ubuntu64.tar.gz -O - | tar -xzvf - -C /usr/local/src/irit/
  chmod 755 /usr/local/src/irit/ftkimager && mv /usr/local/src/irit/ftkimager /usr/local/bin/  || pause

  #Download and configure DeXRAY
  wget -O /usr/local/src/irit/DeXRAY.pl http://hexacorn.com/d/DeXRAY.pl
  chmod 755 /usr/local/src/irit/DeXRAY.pl && mv /usr/local/src/irit/DeXRAY.pl /usr/local/bin/  || pause
  curl -L http://cpanmin.us | perl - --sudo App::cpanminus
  cpanm Crypt::RC4
  cpanm Digest::CRC
  cpanm Crypt::Blowfish
  cpanm Archive::Zip
  cpanm OLE::Storage_Lite
  
  # Get Job Parser
  wget -O /usr/local/src/irit/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
  mv /usr/local/src/irit/jobparser.py /usr/local/bin/

  # Download Irit Tools
  mkdir -p /usr/local/src/irit
  wget -O /usr/local/src/irit/ermount.sh https://raw.githubusercontent.com/dfir-scripts/EverReady-Disk-Mount/master/ermount.sh || pause 
  wget -O /usr/local/src/irit/prefetchruncounts.py https://raw.githubusercontent.com/dfir-scripts/prefetchruncounts/master/prefetchruncounts.py || pause 
  wget -O /usr/local/src/irit/winservices.py https://raw.githubusercontent.com/dfir-scripts/Python-Registry/master/winservices.py || pause 
  wget -O /usr/local/src/irit/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/RegRipper30-apt-git-Install.sh  || pause
  wget -O /usr/local/src/irit/install-autospy-gui.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/install-autospy-gui.sh  || pause
  wget -O /usr/local/src/irit/get-yara-rules.sh https://raw.githubusercontent.com/dfir-scripts/installers/main/get-yara-rules.sh  || pause 
  wget -O /usr/local/src/irit/parse_evtx_tasks.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_tasks.py || pause
  wget -O /usr/local/src/irit/parse_evtx_BITS.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_BITS.py || pause
  wget -O /usr/local/src/irit/parse_evtx_logins.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_logins.py || pause
  wget -O /usr/local/src/irit/parse_evtx_processes.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_processes.py || pause
  wget -O /usr/local/src/irit/parse_evtx_accounts.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_accounts.py || pause
  wget -O /usr/local/src/irit/parse_evtx_RDP_Local.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_RDP_Local.py || pause
  wget -O /usr/local/src/irit/parse_evtx_RDP_Remote.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_RDP_Remote.py || pause
  #wget -O /usr/local/src/irit/parse_evtx_RDP_Core.py  https://raw.githubusercontent.com/dfir-scripts/WinEventLogs/master/parse_evtx_RDP_Core.py || pause
  wget -O /usr/local/src/irit/grab-winfiles.sh https://raw.githubusercontent.com/dfir-scripts/shellscripts/master/grab-winfiles.sh
  chmod -R 755 /usr/local/src/irit/*  || pause 
  [ -f "/usr/local/bin/irit.sh" ]  || cp /usr/local/src/irit/irit.sh /usr/local/bin/siftgrab || pause 
  [ -f "/usr/local/bin/ermount" ]  ||cp /usr/local/src/irit/ermount.sh /usr/local/bin/ermount || pause 
  [ -f "/usr/local/bin/prefetchruncounts.py" ] || cp /usr/local/src/irit/prefetchruncounts.py /usr/local/bin/prefetchruncounts.py || pause 
  [ -f "/usr/local/bin/winservices.py" ] || cp /usr/local/src/irit/winservices.py /usr/local/bin/winservices.py || pause
  [ -f "/usr/local/bin/grab-winfiles.sh" ] || cp /usr/local/src/irit/winservices.py /usr/local/bin/grab-winfiles || pause  
  cp /usr/local/src/irit/parse_evtx*.py /usr/local/bin/ || pause

  #install RegRipper.git and RegRipper install script
  /usr/local/src/irit/RegRipper30-apt-git-Install.sh

  #Create a symbolic link to /opt/share
  [ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share
}

function add_tools(){
  # Extended Tools Install
  #Install tools from apt
  uname -a |grep -i microsoft && exit
  extended_aptpkgs="gparted feh eog glogg bless binwalk samba remmina clamav clamtk gridsite-clients guymager graphviz wine winetricks"
   
  for apt_pkg in $extended_aptpkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt-get install $apt_pkg -y 
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done
  
  # Install Powershell
  pwsh -v || install_powershell
  
  #Install additional tools from snap
  snap install brave || pause
  snap install okteta || pause
  snap install sqlitebrowser || pause
  
  
  # Install R-Linux
  wget -O /tmp/RLinux5_x64.deb  https://www.r-studio.com/downloads/RLinux5_x64.deb && 
  dpkg -i /tmp/RLinux5_x64.deb || pause
  
  # Install from git
  # git bulk extractor
  [ "$(ls -A /usr/local/src/bulk_extractor/)" ] && \
  git -C /usr/local/src/bulk_extractor pull --no-rebase 2>/dev/null|| \ 
  git clone https://github.com/simsong/bulk_extractor.git /usr/local/src/bulk_extractor 
  # Requires a manual install bulk extractor

  #Git LogFileParser
  [ "$(ls -A /usr/local/src/LogFileParser/)" ] && \
  git -C /usr/local/src/LogFileParser pull --no-rebase 2>/dev/null || \
  git clone https://github.com/jschicht/LogFileParser.git /usr/local/src/LogFileParser

  #Git CyLR
  curl -s https://api.github.com/repos/orlikoski/CyLR/releases/latest | \
  grep browser_download_url | grep CyLR_ | cut -d '"' -f 4| while read d; 
  do 
    wget -NP /usr/local/src/CyLR/ $d;
  done
  [ "$(ls -A /usr/local/src/CyLR/)" ] || pause

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
[ "$1" == "-t" ] && add_tools || apt install autopsy -y
updatedb
history -c
