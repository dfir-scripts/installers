#! /bin/bash

<< ////
This script installs open source forensic and disk tools and scripts on Debian based systems.


##############################################################################################
siftgrab is an automated environment for running multiple open source forensic tools at once to examine Windows systems in a Linux evnironment.
Tested on Ubuntu, Kali, Windows WSL2 Ubuntu


Work flow
  Install:
  To install with all the dependencies and extra tools, download and run the forensics tools install script:
    wget https://raw.githubusercontent.com/dfir-scripts/installers/main/install-forensic-tools.sh
    sudo chmod 755 install-forensic-tools.sh
    sudo ./install-forensic-tools.sh

    # Directories created for disk mounting and evidence
       /mnt/raw
       /mnt/image_mount
       /mnt/vss
       /mnt/shadow
       /mnt/bde
       /mnt/smb
       /cases
       /opt/app/<open source tools directories>

  To access the siftgrab menu simply type: sudo siftgrab



  Disk Image Mounting:
    Mount disk images using the command "ermount" or using the siftgrab menu

    The script searches for Windows files in a given path
    (Point to a mounted disk or for data extracted from tools like KAPE)


  Process Artifacts:
    Use the menu to launch parsers

##############################################################################################
   siftgrab
********************************************************
 Mount and Extract Information From Windows Disk Images
********************************************************
**  1)  Mount a Disk or Disk Image (E01, Raw, AFF, QCOW VMDK, VHDX)
**  2)  Process Windows Artifacts from Mounted Image or Offline Directory
**  3)  Extract and Analyze Windows Event Logs
**  4)  Run Regiripper on a Mounted Volume or Offline Directory
**  5)  Acquire a Copy of Windows Forensic Artifacts from Mounted Image(s)
**  6)  Browse Files (lf)
**  7)  Read me

Select a menu option number or enter to exit.


siftgrab
Automated Processing of Artifacts:
##############################################################################################


Artifact,Tool,Source
------------------------------------------------------------------------------------------------------
usnjrln,usnparser,https://github.com/PoorBillionaire/USN-Journal-Parser
MFT,analyzeMFT,https://github.com/dkovar/analyzeMFT
MFT,mft_dump,https://github.com/omerbenamram/mft
INDX,INDXRipper,https://github.com/harelsegev/INDXRipper
Registry,Regripper,https://github.com/keydet89/RegRipper3.0
Registry,Yarp,https://github.com/msuhanov/yarp
Registry,registryFlush,https://github.com/Silv3rHorn/4n6_misc
LNK,JumpList_Lnk_Parser,https://github.com/salehmuhaysin/JumpList_Lnk_Parser
Jumplist,JumpList_Lnk_Parser,https://github.com/salehmuhaysin/JumpList_Lnk_Parser
amcache.hve,Regripper,https://github.com/keydet89/RegRipper3.0
Windows Prefetch,dfir-script,https://github.com/dfir-scripts/prefetchruncounts
Recycle.bin,dfir-script,https://github.com/dfir-scripts/
Chrome,dfir-script,https://github.com/dfir-scripts/
FireFox,dfir-script,https://github.com/dfir-scripts/
WebcacheV,esedbexport,https://github.com/libyal/libesedb
OBJECTS.DATA,PyWMIPersistenceFinder,https://github.com/davidpany/WMI_Forensics
OBJECTS.DATA,CCM_RUA_Finder,https://github.com/davidpany/WMI_Forensics
Srudb.dat,srumdump,https://github.com/MarkBaggett/srum-dump
current.mdb,kstrike,https://github.com/brimorlabs/KStrike
ActivitiesCache.db,windowstimeline,https://github.com/kacos2000/WindowsTimeline
index.dat,parseie,https://github.com/keydet89/Tools
AlternateDataStreams,dfir-script,https://github.com/dfir-scripts/
Windows Event Logs,evtx_dump,https://github.com/omerbenamram/evtx
Windows Event Logs,Zircolite,https://github.com/wagga40/Zircolite
Windows Event Logs,Hayabusa,https://github.com/Yamato-Security/hayabusa/
Windows Event Logs,dfir-script,https://github.com/dfir-scripts/WinEventLogs


Triage Output:
By default extracted data goes to the /cases directory but can be directed to a network share are other locations
 Triage Output Directories:
    <Computer-Name>/Triage/
    ActivitiesCache
    Alert
    BITS
    Browser_Activity
    Current.mdb
    LNK
    MFT
    OBJECTS.DATA
    PowerShell
    Prefetch
    RDP
    Registry/Regripper
    Registry/Yarp-registryFlush
    ScheduledTasks
    SRUDB.dat
    Services
    Timeline
    USNJRNL
    WindowsEventLogs/evtx_dump


Additional Tools
----------------------------------------------------------------------------------------------------
log2timeline/plaso,https://github.com/log2timeline/plaso
Sleuthkit/Autopsy,https://www.sleuthkit.org/autopsy/
ftkimager,https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1
Guymager,https://guymager.sourceforge.io/
ddrescue,https://www.gnu.org/software/ddrescue/
photorec/testdisk,https://www.cgsecurity.org/
Foremost,http://foremost.sourceforge.net/
dc3dd,https://sourceforge.net/projects/dc3dd/
afro,https://github.com/cugu/
xmount,https://www.pinguin.lu/xmount
afflib-tools,http://www.afflib.org/
exfatprogs,https://launchpad.net/ubuntu/+source/exfatprogs
qemu-utils,https://www.qemu.org/download/
ifuse,https://github.com/libimobiledevice/ifuse
gparted,https://gparted.org/
dfir_ntfs,https://github.com/msuhanov/dfir_ntfs
sqlite_miner,https://github.com/threeplanetssoftware
bulk_extractor,https://github.com/simsong/bulk_extractor
WFA 4/e Tools (Harlan Carvey),https://github.com/keydet89/Tools
jobparser,https://github.com/gleeda
bits_parser,https://github.com/ANSSI-FR/bits_parser
Hindsight,https://github.com/obsidianforensics/hindsight
INDXParse.py,https://github.com/williballenthin/INDXParse
feh,https://feh.finalrewind.org/
eog,https://help.gnome.org/users/eog/stable/
CyberChef,https://github.com/gchq/CyberChef
binwalk,https://github.com/ReFirmLabs/binwalk
graphviz,https://graphviz.org/
geoip-database,https://www.maxmind.com
Volatility3,https://github.com/volatilityfoundation/
Didier Stevens Suite,https://blog.didierstevens.com/didier-stevens-suite/
DEXRAY,https://www.hexacorn.com/products_and_freebies.html
iocextract,https://github.com/InQuest/python-iocextract
oletools,https://github.com/decalage2/oletools
pefile,https://github.com/erocarrera/pefile
Density Scout,https://cert.at/en/downloads/software/software-densityscout
clamav,https://www.clamav.net
ffmpeg,https://github.com/ffmpeg
lf,https://github.com/gokcehan/lf
jq,https://stedolan.github.io/jq/
yara,https://github.com/VirusTotal/yara
python3-impacket,https://github.com/SecureAuthCorp/impacket
hashcat,https://github.com/hashcat
python-evtx,python-registry,https://github.com/williballenthin/
python3-libesedb,https://github.com/libyal
libesedb-utils,https://github.com/libyal
liblnk-utils,https://github.com/libyal
libevtx-utils,https://github.com/libyal
libewf-dev,https://github.com/libyal
ewf-tools/libewf-tools,https://github.com/libyal
libbde-utils/tools,https://github.com/libyal
libvshadow-utils/tools,https://github.com/libyal
pff-tools,https://github.com/libyal
libscca-python,https://github.com/libyal
liblnk-python,https://github.com/libyal
libfwsi-python,https://github.com/libyal
p7zip-full,https://www.7-zip.org

# Yara Rules (fetch using get-yara-rules.sh)
https://github.com/Neo23x0/signature-base
https://github.com/bartblaze/Yara-rules
https://github.com/Yara-Rules
https://github.com/reversinglabs/reversinglabs-yara-rules
##############################################################################################

"
////

function display_usage(){
  clear
  echo "
  install-forensic-tools.sh
  Downloads forensic tools to /usr/local/src
  fullfills requirements for running siftgrab
  Tested on Ubuntu 18.04, 20.04, 22.04 Kali and WSL

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
  cat /etc/issue|grep -Ei "u 2"\|"u 18" && \
  apt install libscca libewf-tools libbde-tools libvshadow-tools libesedb-tools liblnk-tools libevtx-tools plaso-tools bulk-extractor -y
}

function main_install(){
  apt remove libewf2 -y
  apt install git curl net-tools vim fdisk -y
  cat /etc/issue|grep -Ei "u 2"\|"u 18" && install_gift_ppa

  cat /etc/issue|grep -i kali && \
  apt install gnome-terminal libewf-dev ewf-tools libbde-utils libvshadow-utils libesedb-utils xmount liblnk-utils libevtx-utils cifs-utils python3-libesedb plaso -y

  #Set python3 as python and install pip3
  echo "Requires python2 for legacy scripts"
  echo "Assume python3 or fail"
  which python3 || pause
  which python2 || apt install python2 -y

  ############### Forensic Tools Download, Install and Confiuration ##########################
  #Make Disk Mount and Cases Directories
  mkdir -p /mnt/{raw,image_mount,vss,shadow,bde,smb,usb}
  mkdir -p /cases

  #Install pip3
  apt install python3-pip virtualenv -y
  pip3 -V || pause
  mkdir -p /envs
  cd /envs
  virtualenv -p python3 dfir --system-site-packages
  source dfir/bin/activate

  #pip installs
  sift_pip_pkgs="pyarrow setuptools==58.2.0 python-evtx python-registry usnparser tabulate regex iocextract oletools bits_parser pandas construct"
  for pip_pkg in $sift_pip_pkgs;
  do
    pip3 install $pip_pkg || pause
  done

  #Install yarp
  git_release="https://github.com/msuhanov/yarp/releases/"
  git_download="https://github.com/msuhanov/yarp/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $git_download/$latest_ver.tar.gz

  #Install dfir_ntfs
  git_release="https://github.com/msuhanov/dfir_ntfs/releases/"
  git_download="https://github.com/msuhanov/dfir_ntfs/archive"
  latest_ver=$(curl -s "$git_release" |grep -Po -m 1 '(?<=tag/).*(?=" data)')
  pip3 install $git_download/$latest_ver.tar.gz

  #Install Applications from Apt
  sift_apt_pkgs="fdupes sleuthkit attr dcfldd afflib-tools autopsy qemu-utils lvm2 exfatprogs kpartx pigz exif dc3dd python-is-python3 pff-tools python3-lxml sqlite3 jq yara gddrescue unzip p7zip-full p7zip-rar hashcat foremost testdisk chntpw graphviz ffmpeg mediainfo ifuse clamav geoip-bin geoip-database geoipupdate python3-impacket libsnappy-dev gnumeric xxd reglookup"
  for apt_pkg in $sift_apt_pkgs;
  do
    echo "Installing $apt_pkg"
    apt install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

  #Git and configure Package Installations and Updates
  Git analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/ 2>/dev/null)" ] && \
  cd /usr/local/src/analyzeMFT
  git -C /usr/local/src/analyzeMFT pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
  [ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
  cd /usr/local/src/analyzeMFT/
  python3 setup.py install || pause

  #Git BitsParser
  [ "$(ls -A /usr/local/src/BitsParser)" ] && \
  git -C /usr/local/src/BitsParser || \
  git clone https://github.com/fireeye/BitsParser.git /usr/local/src/BitsParser

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


   #Git Hindsight
   [ "$(ls -A /usr/local/src/Hindsight/)" ] && \
   git -C /usr/local/src/Hindsight pull --no-rebase 2>/dev/null|| \
   git clone https://github.com/obsidianforensics/hindsight.git /usr/local/src/Hindsight
   mkdir /usr/local/src/Hindsight/requirements
   cd /usr/local/src/Hindsight/requirements
   pip3 install -r /usr/local/src/Hindsight/requirements.txt
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
  pip3 install -qr /usr/local/src/volatility/requirements.txt

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

  #Git Kstrike
  [ "$(ls -A /usr/local/src/KStrike)" ] && \
  git -C /usr/local/src/KStrike pull --no-rebase 2>/dev/null|| \
  git clone https://github.com/brimorlabs/KStrike.git /usr/local/src/KStrike

  #Git Srum-Dump
  [ "$(ls -A /usr/local/src/srum-dump)" ] && \
  git -C /usr/local/src/srum-dump --no-rebase 2>/dev/null|| \
  git clone https://github.com/dfir-scripts/srum-dump.git /usr/local/src/srum-dump
  pip3 install -qr /usr/local/src/srum-dump/requirements.txt

  #Git JL_Parser
  [ "$(ls -A /usr/local/src/JumpList_Lnk_Parser)" ] && \
  git -C /usr/local/src/JumpList_Lnk_Parser --no-rebase 2>/dev/null || \
  git clone https://github.com/salehmuhaysin/JumpList_Lnk_Parser.git /usr/local/src/JumpList_Lnk_Parser

  #Git Zircolite
  [ "$(ls -A /usr/local/src/Zircolite)" ] && \
  git -C /usr/local/src/Zircolite --no-rebase 2>/dev/null || \
  git clone https://github.com/wagga40/Zircolite.git /usr/local/src/Zircolite
  pip3 install -r /usr/local/src/Zircolite/requirements.txt

  #Git EventTranscriptParser
  [ "$(ls -A /usr/local/src/EventTranscriptParser)" ] && \
  git -C /usr/local/src/EventTranscriptParser --no-rebase 2>/dev/null || \
  git clone https://github.com/stuxnet999/EventTranscriptParser.git /usr/local/src/EventTranscriptParser

  #Git RegistryFlush
  [ "$(ls -A /usr/local/src/Silv3rHorn)" ] && \
  git -C /usr/local/src/Silv3rhorn --no-rebase 2>/dev/null || \
  git clone https://github.com/dfir-scripts/4n6_misc.git /usr/local/src/Silv3rhorn

  #Git Python-Registry
  [ "$(ls -A /usr/local/src/Python-Registry)" ] && \
  git -C /usr/local/src/Python-Registry --no-rebase 2>/dev/null || \
  git clone https://github.com/williballenthin/python-registry.git /usr/local/src/Python-Registry
  
  #Git INDXRipper
  [ "$(ls -A /usr/local/src/INDXRipper)" ] && \
  git -C /usr/local/src/INDXRipper --no-rebase 2>/dev/null || \
  git clone https://github.com/harelsegev/INDXRipper.git /usr/local/src/INDXRipper
  
  #Git and configure Harlan Carvey tools
  [ "$(ls -A /usr/local/src/keydet89/tools/ 2>/dev/null)" ] && \
  git -C /usr/local/src/keydet89/tools/ pull --no-rebase 2>/dev/null || \
  git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/
  chmod 755 /usr/local/src/keydet89/tools/source/* || pause
  
  # Reverted breaks ermount.sh
  #Git and configure apfs-fuse
  #[ "$(ls -A /usr/local/src/apfs-fuse/ 2>/dev/null)" ] && \
  #git -C /usr/local/src/apfs-fuse/ pull --no-rebase 2>/dev/null || \
  #git clone https://github.com/sgan81/apfs-fuse.git /usr/local/src/apfs-fuse/
  #cd /usr/local/src/apfs-fuse/
  #git submodule init
  #git submodule update
  #mkdir build
  #cd build
  #cmake ..
  #make
  #cp /usr/local/src/apfs-fuse/build/apfs-* /usr/local/bin/

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

  #Download Haybusa
  mkdir -p /usr/local/src/Hayabusa
  cd /usr/local/src/Hayabusa
  current_ver=$(hayabusa help 2>/dev/null |head -n 1|awk '{print $2}' 2>/dev/null)
  latest_ver=$(curl -s https://github.com/Yamato-Security/hayabusa/ |grep -Po "(?<=tag/v)[^\">]+")
  [ $current_ver == $latest_ver ] && echo "already updated" || \
  wget -qO - https://github.com/Yamato-Security/hayabusa/releases/download/v$latest_ver/hayabusa-$latest_ver-all-platforms.zip| busybox unzip -
  cp hayabusa-*-lin-x64-musl /usr/local/bin/hayabusa 2>/dev/null
  chmod 755 /usr/local/bin/hayabusa

#Download lf File Browser
  curl -s https://api.github.com/repos/gokcehan/lf/releases/latest | \
  grep browser_download_url | grep lf-linux-amd64.tar.gz | \
  awk -F'"' '{system("wget -P /tmp "$4) }' && \
  tar -xvf /tmp/lf-linux*.gz -C /tmp
  chmod 755 /tmp/lf && mv /tmp/lf /usr/local/bin/lf || pause

  # Download Density Scout
  wget -qO - https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip| \
  busybox unzip -j - lin64/densityscout -d /usr/local/src/dfir-scripts/ && \
  mv /usr/local/src/dfir-scripts/densityscout /usr/local/bin/densityscout && \
  chmod 755 /usr/local/bin/densityscout

  # Download ftkimager
  which ftkimager || \
  wget  https://d1kpmuwb7gvu1i.cloudfront.net/ftkimager.3.1.1_ubuntu64.tar.gz -O - | \
  tar -xzvf - -C /usr/local/src/dfir-scripts/  && \
  chmod 755 /usr/local/src/dfir-scripts/ftkimager && mv /usr/local/src/dfir-scripts/ftkimager /usr/local/bin/
  
  # Download Volatility 2.6
  mkdir -p /usr/local/src/volatility2.6
  wget -qO - http://downloads.volatilityfoundation.org/releases/2.6/volatility-2.6.zip | \
  busybox unzip - -d /usr/local/src/volatility2.6/

  # Download lolbas.csv
  mkdir -p /usr/local/src/lolbas
  wget -O /usr/local/src/lolbas/lolbas.csv https://lolbas-project.github.io/api/lolbas.csv 

  # Download Jumplist APPIDs
  mkdir -p /usr/local/src/EricZimmerman
  wget -O /usr/local/src/EricZimmerman/AppIDs.txt https://raw.githubusercontent.com/EricZimmerman/JumpList/master/JumpList/Resources/AppIDs.txt
  # Convert AppIDs to csv for JLParser
  cat /usr/local/src/EricZimmerman/AppIDs.txt | awk -F'"' '{print "Application IDs,"tolower($2)","$4}' >> /usr/local/src/EricZimmerman/AppIDs.csv

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
  [ -d "/opt/app" ] || ln -s /usr/local/src/ /opt/app
  #set Windows Perl scripts in Keydet89/Tools/source
  find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
  do
    a=$(which perl)
    file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
    sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!$a" $d
    cp $d /usr/local/bin/$file_name || pause
  done
  deactivate
}

function add_gui_tools(){
  # Extended Tools Install
  #Install tools from apt
  uname -a |grep -i microsoft && exit
  gui_aptpkgs="gparted feh eog binwalk gridsite-clients graphviz"

  for apt_pkg in $gui_aptpkgs;
  do
    echo "Installing $apt_pkg"
    apt install $apt_pkg -y
    dpkg -S $apt_pkg && echo "$apt_pkg Installed!"|| pause
  done

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
