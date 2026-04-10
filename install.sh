#!/bin/bash
 
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'
 
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error：${plain} This script must be run with the root user！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}System version not detected, please contact the script author！${plain}\n" && exit 1
fi

arch=$(uname -m)
kernelArch=$arch
case $arch in
	"i386" | "i686")
		kernelArch=32
		;;
	"x86_64" | "amd64" | "x64")
		kernelArch=64
		;;
	"arm64" | "armv8l" | "aarch64")
		kernelArch="arm64-v8a"
		;;
esac

echo "arch: ${kernelArch}"

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Please use CentOS 7 or later!${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Please use Ubuntu 16 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Please use Debian 8 or higher！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
        yum install wget curl unzip tar crontabs socat -y
    else
        apt update -y
        apt install wget curl unzip tar cron socat -y
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/XMBox.service ]]; then
        return 2
    fi
    temp=$(systemctl status XMBox | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_acme() {
    curl https://get.acme.sh | sh
}

install_XMBox() {
    if [[ -e /usr/local/XMBox/ ]]; then
        rm /usr/local/XMBox/ -rf
    fi
	
	if [[ -f /usr/bin/XMBox ]]; then
		rm /usr/bin/XMBox -f
	fi
	
	if [[ -f /usr/bin/xmbox ]]; then
		rm /usr/bin/xmbox -f
	fi
	
    mkdir /usr/local/XMBox/ -p
	
	cd /usr/local/XMBox/

    if  [ $# == 0 ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/XMPlusDev/XMBox/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to detect the XMBox version, it may be because of Github API limit, please try again later, or manually specify the XMBox version to install${plain}"
            exit 1
        fi
        echo -e "XMBox latest version detected：${last_version}，Start Installation"
        wget -N --no-check-certificate -O /usr/local/XMBox/XMBox-linux.zip https://github.com/XMPlusDev/XMBox/releases/download/${last_version}/XMBox-linux-${kernelArch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMBox failed，Please make sure your server can download github file${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/XMPlusDev/XMBox/releases/download/${last_version}/XMBox-linux-${kernelArch}.zip"
        echo -e "Start Installation XMBox v$1"
        wget -N --no-check-certificate -O /usr/local/XMBox/XMBox-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMBox v$1 failed, make sure this version exists${plain}"
            exit 1
        fi
    fi

    unzip XMBox-linux.zip
    rm XMBox-linux.zip -f
    chmod +x XMBox
	
    if [ -e "/etc/systemd/system/" ] ; then
		if [ -e "/usr/lib/systemd/system/XMBox.service" ] ; then
			systemctl stop XMBox
			systemctl disable XMBox
		    rm /etc/systemd/system/XMBox.service -f
		fi
		
		file="https://raw.githubusercontent.com/XMPlusDev/XMBox/script/XMBox.service"
		wget -N --no-check-certificate -O /etc/systemd/system/XMBox.service ${file}
		systemctl daemon-reload
		systemctl stop XMBox
		systemctl enable XMBox
    elif [ -e "/usr/sbin/rc-service" ] ; then
		if [ -e "/etc/init.d/xmbox" ] ; then
			systemctl stop XMBox
			systemctl disable XMBox
			rm /etc/init.d/xmbox/xmbox.rc -f
		else	
			 mkdir /etc/init.d/xmbox/ -p
		fi
		file="https://raw.githubusercontent.com/XMPlusDev/XMBox/script/xmbox.rc"
		wget -N --no-check-certificate -O /etc/init.d/xmbox/xmbox.rc ${file}
		systemctl daemon-reload
		rc-update add xmbox default 
		rc-update --update
		chmod +x /etc/init.d/xmbox/xmbox.rc
		ln -s /etc/XMBox /usr/local/etc/
    else
       echo "not found."
    fi	
	
    mkdir /etc/XMBox/ -p
	
    echo -e "${green}XMBox ${last_version}${plain} The installation is complete，XMBox has restarted"
	
    cp geosite-category-ads-all.srs /etc/XMBox/
	cp geosite-cn.srs /etc/XMBox/ 
    cp geoip-cn.srs /etc/XMBox/ 
	
    if [[ ! -f /etc/XMBox/dns.json ]]; then
		cp dns.json /etc/XMBox/
	fi
	if [[ ! -f /etc/XMBox/route.json ]]; then 
		cp route.json /etc/XMBox/
	fi
	
    if [[ ! -f /etc/XMBox/config.yaml ]]; then
        cp config.yaml /etc/XMBox/
    else
		if [ -e "/etc/systemd/system/" ] ; then
			systemctl start XMBox
		else
			rc-service xmbox start
		fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}XMBox restart successfully${plain}"
        else
            echo -e "${red} XMBox May fail to start, please use [ XMBox log ] View log information ${plain}"
        fi
    fi
    
    curl -o /usr/bin/XMBox -Ls https://raw.githubusercontent.com/XMPlusDev/XMBox/script/XMBox.sh
    chmod +x /usr/bin/XMBox
    ln -s /usr/bin/XMBox /usr/bin/xmbox 
    chmod +x /usr/bin/xmbox

    echo -e ""
    echo "XMBox Management usage method: "
    echo "------------------------------------------"
    echo "XMBox                    - Show menu (more features)"
    echo "XMBox start              - Start XMBox"
    echo "XMBox stop               - Stop XMBox"
    echo "XMBox restart            - Restart XMBox"
    echo "XMBox status             - View XMBox status"
    echo "XMBox enable             - Enable XMBox auto-start"
    echo "XMBox disable            - Disable XMBox auto-start"
    echo "XMBox log                - View XMBox logs"
    echo "XMBox update             - Update XMBox"
    echo "XMBox update vx.x.x      - Update XMBox Specific version"
    echo "XMBox config             - Show configuration file content"
    echo "XMBox install            - Install XMBox"
    echo "XMBox uninstall          - Uninstall XMBox"
    echo "XMBox version            - View XMBox version"
    echo "XMBox x25519             - Generate key pair for X25519 key exchange (REALITY)"
    echo "XMBox ech                - Generate ECH keys with default or custom server name"
    echo "------------------------------------------"
}

echo -e "${green}Start Installation${plain}"
install_base
#install_acme
install_XMBox $1
