#! /bin/bash

<< ////
This is a consolidation of open source tools and open source scripts
It is a basic IR triage tools for examining Windows systems in a
Linux evnironment.  Tested on Ubuntu 20.04, Kali 2022.1, Windows WSL2 Ubuntu 20.04 and SANS SiFT

Just run this install script for as root to install requirements.  To update or reinstall, rerun install script.

There are installer scripts to download yara rules and install/reinstall Regripper.

Downloaded tools are located in /usr/local/src/ some are copied to /usr/local/bin

# Installers:
 forensic-tools-install.sh
 RegRipper30-apt-git-Install.sh
 get-yara-rules.sh

# General purpose timeline and forensic tools
 plaso/log2timeline
 Sleuthkit/Autopsy
 siftgrab

# Disk Mounting, Imaging and Carving
 ftkimager,ermount,ewf-tools/libewf-tools,afflib-tools,qemu-utils,libbde-utils/tools,exfat-utils,libvshadow-utils/tools
 xmount,ddrescue,photorec/testdisk,ifuse,afro,bulk_extractor

# Parsers
AnalyzeMFT,MFT_Dump,yarp, usnparser.py,Regripper 3.0,Tools from WFA 4/e, timeline tools, etc. (Harlan Carvey),
esedbexport,srumdump,prefetchruncounts.py,lnkinfo,evtx_dump,PyWMIPersistenceFinder.py,CCM_RUA_Finder.py,pff-tools,
jobparser.py,bits_parser.py,Hindsight, Unfurl,Kacos2000/Queries,INDXParse.py,Volatility3,KStrike.py,sqlite_miner,NTDSExtract

# File Analysis Tools
Didier Stevens Tools,DEXRAY,iocextract,stegosuite,oletools,pefile,Density Scout

# Python (python2, python3)
python-registry,python3-libesedb,python-evtx,libscca-python,liblnk-python,libfwsi-python

# Misc
clamav,lf,attr,libesedb-utils,liblnk-utils,libevtx-utils,pff-tools,jq,yara,rar,unrar,p7zip-full,p7zip-rar

# Gui Tools
# R-Linux, LogFileParser,clamtk,gparted,feh,eog,glogg,bless,binwalk,graphviz,guymager

# Yara Rules (fetch using get-yara-rules.sh)
Nextron, ReversingLabs, yararules.com

# Directories created
  /mnt/raw
  /mnt/image_mount
  /mnt/vss
  /mnt/shadow
  /mnt/bde
  /mnt/smb
  /cases


////

function display_usage(){
  clear
  echo "
  install-forensic-tools.sh
  Downloads forensic tools to /usr/local/src
  fullfills requirements for running siftgrab
  Tested on Ubuntu 18.04, 20.04, Kali 20221 and WSL (Ubuntu 20.04)

  USAGE: install-forensic-tools.sh -h

         -h Displays this help text

		 "
    exit
}

function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

function install_gift_ppa(){
  apt install software-properties-common -y && \
  add-apt-repository ppa:gift/stable -y &&  apt update || pause
  apt upgrade -q -y -u  || pause
  cat /etc/issue|grep -Ei "u 20"\|"u 18" && \
  apt install libewf-tools libbde-tools libvshadow-tools libesedb-tools liblnk-tools libevtx-tools plaso-tools bulk-extractor  exfat-utils -y
}

function main_install(){
  apt remove libewf2 -y
  apt install git curl net-tools vim -y
  cat /etc/issue|grep -E "u 2"\|"u 18" && install_gift_ppa

  cat /etc/issue|grep -i kali && \
  apt install gnome-terminal libewf-dev ewf-tools libbde-utils libvshadow-utils libesedb-utils xmount liblnk-utils libevtx-utils python3-libesedb plaso -y

  #Set python3 as python and Install pip and pip3
  echo "Requires python2 for legacy scripts"
  echo "Assume python3 or fail"
  which python3 || pause
  which python2 || apt install python2 -y 

  ############### Forensic Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde,smb,usb}
  mkdir -p /cases

  #Install pip3
  pip3 -V 2>/dev/null || apt install python3-pip -y
  pip3 -V || pause

  #pip installs
  sift_pip_pkgs="python-evtx python-registry usnparser tabulate regex iocextract oletools bits_parser"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done
  
  #Install yarp
  git_release="https://github.com/msuhanov/yarp/releases/"
  git_download="https://github.com/msuhanov/yarp/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $install_dir $git_download/$latest_ver.tar.gz
  
  #Install dfir_ntfs
  git_release="https://github.com/msuhanov/dfir_ntfs/releases/"
  git_download="https://github.com/msuhanov/dfir_ntfs/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $install_dir $git_download/$latest_ver.tar.gz  
  
  #Install MemProcFS
  mkdir -p /usr/local/src/MemProcFS
  latest_MemProcFS=$(curl -s https://github.com/ufrisk/MemProcFS/releases/|grep -m 1 linux_x64|awk -F'"' '{print $2}')
  wget https://github.com$latest_MemProcFS -O - | tar -xzvf - -C /usr/local/src/MemProcFS
  
  
  #Install Applications from Apt
  sift_apt_pkgs="fdupes sleuthkit attr dcfldd afflib-tools autopsy qemu-utils lvm2 kpartx pigz exif dc3dd python-is-python3 pff-tools python3-lxml sqlite3 jq yara gddrescue unzip rar unrar p7zip-full p7zip-rar stegosuite hashcat foremost testdisk chntpw graphviz ffmpeg mediainfo ifuse clamav geoip-bin geoip-database geoipupdate python3-impacket"

  for apt_pkg in $sift_apt_pkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  #Git and configure Package Installations and Updates

  #Git analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/ 2>/dev/null)" ] && \
  git -C /usr/local/src/analyzeMFT pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
  cd /usr/local/src/analyzeMFT/
  python setup.py install || pause

  #Git DFIR-Script shell scripts
  [ "$(ls -A /usr/local/src/dfir-scripts/ 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/shellscripts pull --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/shellscripts.git /usr/local/src/dfir-scripts/shellscripts
  [ "$(ls -A /usr/local/src/dfir-scripts/shellscripts)" ] && chmod 755 /usr/local/src/dfir-scripts/shellscripts/* || pause
  
    #Git DFIR-Scripts Eventlog parsers
  [ "$(ls -A /usr/local/src/dfir-scripts/ 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/WinEventLogs pull --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/WinEventLogs.git /usr/local/src/dfir-scripts/WinEventLogs
  [ "$(ls -A /usr/local/src/dfir-scripts/WinEventLogs)" ] && chmod -R 755 /usr/local/src/dfir-scripts/WinEventLogs* || pause
  
     #Git DFIR-Scripts Installer
  [ "$(ls -A /usr/local/src/dfir-scripts/ 2>/dev/null)" ] && \
  git -C /usr/local/src/dfir-scripts/installers pull --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/installers.git /usr/local/src/dfir-scripts/installers
  [ "$(ls -A /usr/local/src/dfir-scripts/WinEventLogs)" ] && chmod -R 755 /usr/local/src/dfir-scripts/installers || pause


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
   mkdir /usr/local/src/Hindsight/requirements
   cd /usr/local/src/Hindsight/requirements
   pip3 download -r /usr/local/src/Hindsight/requirements.txt
   cd /usr/local/src


  #Git and configure WMI Forensics
  [ "$(ls -A /usr/local/src/WMI_Forensics/ 2>/dev/null)" ] && \
  git -C /usr/local/src/WMI_Forensics pull --no-rebase 2>/dev/null || \
  git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
  cp /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py || pause
  cp /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py || pause

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
  git clone https://github.com/fireeye/BitsParser.git /usr/local/src/BitsParser

  #Git Srum-Dump
  [ "$(ls -A /usr/local/src/srum-dump)" ] && \
  git -C /usr/local/src/srum-dump || \
  git clone https://github.com/MarkBaggett/srum-dump.git /usr/local/src/srum-dump
  pip install -qr /usr/local/src/srum-dump/requirements.txt

    #Git EventTranscriptParser
  [ "$(ls -A /usr/local/src/EventTranscriptParser)" ] && \
  git -C /usr/local/src/EventTranscriptParser || \
  git clone https://github.com/stuxnet999/EventTranscriptParser.git /usr/local/src/EventTranscriptParser

     #Git ntdsxtract
  [ "$(ls -A /usr/local/src/ntdsxtract)" ] && \
  git -C /usr/local/src/ntdsxtract || \
  git clone https://github.com/csababarta/ntdsxtract.git /usr/local/src/ntdsxtract

  # Use Wget and curl to download tools
#Download mft_dump
  mkdir -p /usr/local/src/omerbenamram/mft_dump/
  git_release="https://api.github.com/repos/omerbenamram/mft/releases/latest"
  install_dir="/usr/local/src/omerbenamram/mft_dump"
  current_ver=$($install_dir/mft_dump -V 2>/dev/null|sed 's/.* /v/')
  latest_ver=$(curl -s "$git_release" | grep -Po '"tag_name": "\K.*?(?=")')
  [ $current_ver ] && updated_status=$(echo -e "$current_ver\n$latest_ver" |sort -V |grep -m 1 $current_ver )
  [ $updated_status ] || curl -s $git_release | \
  grep -E 'browser_download_url.*64-unknown-linux-musl'| \
  awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/mft_dump/mft_dump "$4) }'  && \
  chmod 755 $install_dir/mft_dump && cp $install_dir/mft_dump /usr/local/bin/mft_dump || pause

  #Download evtx_dump
  mkdir -p /usr/local/src/omerbenamram/evtx_dump/
  git_release="https://api.github.com/repos/omerbenamram/evtx/releases/latest"
  install_dir="/usr/local/src/omerbenamram/evtx_dump"
  current_ver=$($install_dir/evtx_dump -V 2>/dev/null|sed 's/.* /v/')
  latest_ver=$(curl -s "$git_release" | grep -Po '"tag_name": "\K.*?(?=")')
  [ $current_ver ] && updated_status=$(echo -e "$current_ver\n$latest_ver" |sort -V |grep -m 1 $current_ver )
  [ $updated_status ] || curl -s $git_release | \
  grep -E 'browser_download_url.*64-unknown-linux-musl'| \
  awk -F'"' '{system("wget -O /usr/local/src/omerbenamram/evtx_dump/evtx_dump "$4) }'  && \
  chmod 755 $install_dir/evtx_dump && cp $install_dir/evtx_dump /usr/local/bin/evtx_dump || pause
   
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
  which ftkimager || \
  wget  https://ad-zip.s3.amazonaws.com/ftkimager.3.1.1_ubuntu64.tar.gz -O - | \
  tar -xzvf - -C /usr/local/src/dfir-scripts/  && \
  chmod 755 /usr/local/src/dfir-scripts/ftkimager && mv /usr/local/src/dfir-scripts/ftkimager /usr/local/bin/

  #Install chainsaw
  git_release="https://github.com/countercept/chainsaw/releases"
  git_download="https://github.com/countercept/chainsaw/releases/download/"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  wget $git_download/$latest_ver/chainsaw_x86_64-unknown-linux-musl.tar.gz -O - | tar -xzvf - -C /usr/local/src


  #Download and configure DeXRAY
  which DeXRAY.pl || \
  wget -O /usr/local/src/dfir-scripts/DeXRAY.pl http://hexacorn.com/d/DeXRAY.pl && \
  chmod 755 /usr/local/src/dfir-scripts/DeXRAY.pl && mv /usr/local/src/dfir-scripts/DeXRAY.pl /usr/local/bin/ &&\
  curl -L http://cpanmin.us | perl - --sudo App::cpanminus && \
  cpanm Crypt::RC4 && \
  cpanm Digest::CRC  && \
  cpanm Crypt::Blowfish && \
  cpanm Archive::Zip && \
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
  chmod -R 755 /usr/local/src/dfir-scripts/*  || pause
  cp /usr/local/src/dfir-scripts/siftgrab/siftgrab /usr/local/bin/siftgrab || pause
  cp /usr/local/src/dfir-scripts/ermount/ermount.sh /usr/local/bin/ermount || pause

  #install RegRipper.git and RegRipper install script
  /usr/local/src/dfir-scripts/installers/RegRipper30-apt-git-Install.sh

  #Create a symbolic link to /opt/share
  [ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share
}

function add_gui_tools(){
  # Extended Tools Install
  #Install tools from apt
  uname -a |grep -i microsoft && exit
  gui_aptpkgs="gparted feh eog glogg binwalk clamtk gridsite-clients graphviz guymager"

  for apt_pkg in $gui_aptpkgs;
  do
    echo "Installing $apt_pkg"
    sudo apt install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  # Install R-Linux
  which rlinux || \
  wget -O /tmp/RLinux5_x64.deb  https://www.r-studio.com/downloads/RLinux5_x64.deb 
  [ "$(ls /tmp/RLinux5_x64.deb)" ] && dpkg -i /tmp/RLinux5_x64.deb
  which rlinux || pause

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
which apt && apt update || pause
ls /usr/share/xsessions/ 2>/dev/null && add_gui_tools
which apt && main_install || display_usage
history -c
echo ""
cat /etc/issue|grep -i kali && \
echo "*****************************************" && \
echo "To disable disk automount:" && \
echo "set org.gnome.desktop.media-handling automount false"

echo ""
echo  "   Install Complete!"
