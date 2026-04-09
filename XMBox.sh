#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

version="v1.0.0"

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

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error: ${plain} This script must be run with the root user！\n" && exit 1

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
 
confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [Default$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "Whether to restart XMBox " "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press enter to return to the main menu: ${plain} " && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/XMPlusDev/XMBox/script/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    version=$2
    bash <(curl -Ls https://raw.githubusercontent.com/XMPlusDev/XMBox/script/install.sh) $version
}

config() {
    echo "XMBox will automatically try to restart after modifying the configuration"
    vi /etc/XMBox/config.yaml
    sleep 2
    check_status
    case $? in
        0)
            echo -e "XMBox Status: ${green}Running${plain}"
            ;;
        1)
            echo -e "It is detected that you have not started XMBox or XMBox failed to restart automatically, check the log？[Y/n]" && echo
            read -e -p "(Default: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "XMBox Status: ${red}Not Installed${plain}"
    esac
}

uninstall() {
    confirm "Are you sure you want to uninstall XMBox? " "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
	if [ -e "/etc/systemd/system/" ] ; then
		systemctl stop XMBox
		systemctl disable XMBox
		rm /etc/systemd/system/XMBox.service -f
		systemctl daemon-reload
		systemctl reset-failed
	else
		rc-service XMBox stop
		rc-update delete XMBox default 
		rc-update --update
		rm /etc/init.d/XMBox/XMBox.rc -f
		systemctl daemon-reload
	fi
	
    rm /etc/XMBox/ -rf
    rm /usr/local/XMBox/ -rf

    echo ""
    echo -e "The uninstallation is successful. If you want to delete this script, run ssh command ${green}rm -rf /usr/bin/XMBox -f ${plain} to delete"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${green}XMBox aready running, no need to start again, if you need to restart, please select restart${plain}"
    else
		systemctl start XMBox
		sleep 2
		check_status
		if [[ $? == 0 ]]; then
			echo -e "${green}XMBox startup is successful, please use XMBox log to view the operation log${plain}"
		else
			echo -e "${red}XMBox may fail to start, please use XMBox log to check the log information later${plain}"
		fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
	systemctl stop XMBox
	sleep 2
	check_status
	if [[ $? == 1 ]]; then
		echo -e "${green}XMBox stop successful${plain}"
	else
		echo -e "${red}XMBox stop failed, probably because the stop time exceeded two seconds, please check the log information later${plain}"
	fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
	systemctl restart XMBox
	sleep 2
	check_status
	if [[ $? == 0 ]]; then
		echo -e "${green}XMBox restart is successful, please use XMBox log to view the operation log${plain}"
	else
		echo -e "${red}XMBox may fail to start, please use XMBox log to check the log information later${plain}"
	fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
	systemctl status XMBox --no-pager -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
	systemctl enable XMBox
	if [[ $? == 0 ]]; then
		echo -e "${green}start XMBox on system boot successfully enabled${plain}"
	else
		echo -e "${red}start XMBox on system boot failed to enable${plain}"
	fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
	systemctl disable XMBox
	if [[ $? == 0 ]]; then
		echo -e "${green}diable XMBox on system boot successfull${plain}"
	else
		echo -e "${red}diable XMBox on system boot failed${plain}"
	fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u XMBox.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

install_bbr() {
    bash <(curl -L -s https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh)
}

update_script() {
	systemctl stop XMBox
	rm -rf /usr/bin/XMBox
	rm -rf /usr/bin/XMBox
	systemctl daemon-reload
    wget -O /usr/bin/XMBox -N --no-check-certificate https://raw.githubusercontent.com/XMPlusDev/XMBox/script/XMBox.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${red}Failed to download the script, please check whether the machine can connect Github${plain}"
        before_show_menu
    else
        chmod +x /usr/bin/XMBox
		ln -s /usr/bin/XMBox /usr/bin/xmbox 
		chmod +x /usr/bin/XMBox
		systemctl start XMBox
        echo -e "${green}The upgrade script was successful, please run the script again${plain}" && exit 0
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

check_enabled() {
		temp=$(systemctl is-enabled XMBox)
		if [[ x"${temp}" == x"enabled" ]]; then
			return 0
		else
			return 1;
		fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}XMBox already installed, please do not repeat the installation${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}please install XMBox first${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "XMBox Status: ${green}Running${plain}"
            show_enable_status
            ;;
        1)
            echo -e "XMBox Status: ${yellow}Not Running${plain}"
            show_enable_status
            ;;
        2)
            echo -e "XMBox Status: ${red}Not Installed${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Whether to start automatically: ${green}Yes${plain}"
    else
        echo -e "Whether to start automatically: ${red}No${plain}"
    fi
}

show_XMBox_version() {
    echo -n ""
    /usr/local/XMBox/XMBox version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_XMBox_x25519() {
     echo -n ""
    /usr/local/XMBox/XMBox x25519
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_XMBox_ech() {
    echo -n ""
    read -p "Enter serverName: " serverName
    
    /usr/local/XMBox/XMBox ech --serverName "$serverName"
    
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}
 
show_usage() {
    echo "XMBox management script: "
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


show_menu() {
    echo -e "
  ${green}XMBox backend management script，${plain}${red}not applicable to docker${plain}
--- https://github.com/XMPlusDev/XMBox ---
  ${green}0.${plain} Change setting
————————————————
  ${green}1.${plain} Install XMBox
  ${green}2.${plain} Update XMBox
  ${green}3.${plain} Uninstall XMBox
————————————————
  ${green}4.${plain} start XMBox
  ${green}5.${plain} Stop XMBox
  ${green}6.${plain} Restart XMBox
  ${green}7.${plain} View XMBox Status
  ${green}8.${plain} View XMBox log
————————————————
  ${green}9.${plain} Enable XMBox auto-satrt
 ${green}10.${plain} Disable XMBox auto-satrt
————————————————
 ${green}11.${plain} One-click install bbr (latest kernel)
 ${green}12.${plain} View XMBox version 
 ${green}13.${plain} Upgrade maintenance script
————————————————
 ${green}14.${plain} Generate key pair for X25519 key exchange (REALITY
 ${green}15.${plain} Generate ECH keys with default or custom server name
 "
    show_status
    echo && read -p "Please enter selection [0-15]: " num

    case "${num}" in
        0) config
        ;;
        1) check_uninstall && install
        ;;
        2) check_install && update
        ;;
        3) check_install && uninstall
        ;;
        4) check_install && start
        ;;
        5) check_install && stop
        ;;
        6) check_install && restart
        ;;
        7) check_install && status
        ;;
        8) check_install && show_log
        ;;
        9) check_install && enable
        ;;
        10) check_install && disable
        ;;
        11) install_bbr
        ;;
        12) check_install && show_XMBox_version
        ;;
        13) update_script
        ;;
		14) check_install && show_XMBox_x25519
		;;
		15) check_install && show_XMBox_ech
        ;;
        *) echo -e "${red}Please enter the correct number [0-15]${plain}"
        ;;
    esac
}


if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0
        ;;
        "stop") check_install 0 && stop 0
        ;;
        "restart") check_install 0 && restart 0
        ;;
        "status") check_install 0 && status 0
        ;;
        "enable") check_install 0 && enable 0
        ;;
        "disable") check_install 0 && disable 0
        ;;
        "log") check_install 0 && show_log 0
        ;;
        "update") check_install 0 && update 0 $2
        ;;
        "config") config $*
        ;;
        "install") check_uninstall 0 && install 0
        ;;
        "uninstall") check_install 0 && uninstall 0
        ;;
        "version") check_install 0 && show_XMBox_version 0
        ;;
        "update_script") update_script
        ;;
		"x25519") check_install 0 && show_XMBox_x25519 0
        ;;
		"ech") check_install && show_XMBox_ech 0
        ;;
        *) show_usage
    esac
else
    show_menu
fi