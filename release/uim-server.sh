#!/bin/bash

version="v1.0.0"

# check root
[[ $EUID -ne 0 ]] && echo -e "必须使用root用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat|rocky|alma|fedora"; then
    release="rhel"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat|rocky|alma|fedora"; then
    release="rhel"
else
    echo -e "未检测到系统版本！\n" && exit 1
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"rhel" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "请使用 CentOS 8 或更高版本的系统！\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 20 ]]; then
        echo -e "请使用 Ubuntu 20 或更高版本的系统！\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 10 ]]; then
        echo -e "请使用 Debian 10 或更高版本的系统！\n" && exit 1
    fi
fi

confirm() {
    if [[ $# -gt 1 ]]; then
        echo && read -p "$1 [默认$2]: " temp
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
    confirm "是否重启UIM-Server" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "按回车返回主菜单: " && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://github.com/SSPanel-UIM/UIM-Server/raw/main/release/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    if [[ $# == 0 ]]; then
        echo && echo -n -e "输入指定版本(默认最新版): " && read version
    else
        version=$2
    fi
    
    bash <(curl -Ls https://github.com/SSPanel-UIM/UIM-Server/raw/main/release/install.sh) $version
    
    if [[ $? == 0 ]]; then
        echo -e "更新完成，已自动重启 UIM-Server，请使用 UIM-Server log 查看运行日志"
        exit
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

config() {
    echo "UIM-Server在修改配置后会自动尝试重启"
    vi /etc/uim-server/config.yml
    sleep 2
    check_status
    case $? in
        0)
            echo -e "UIM-Server状态: 已运行"
            ;;
        1)
            echo -e "检测到您未启动 UIM-Server 或 UIM-Server 自动重启失败，是否查看日志？[Y/n]" && echo
            read -e -p "(默认: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "UIM-Server 状态: 未安装"
    esac
}

uninstall() {
    confirm "确定要卸载 UIM-Server 吗?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop uim-server
    systemctl disable uim-server
    rm /etc/systemd/system/uim-server.service -f
    systemctl daemon-reload
    systemctl reset-failed
    rm /etc/uim-server/ -rf
    rm /usr/local/uim-server/ -rf

    echo ""
    echo -e "卸载成功，如果你想删除此脚本，则退出脚本后运行 rm /usr/bin/uim-server -f 进行删除"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "UIM-Server已运行，无需再次启动，如需重启请选择重启"
    else
        systemctl start uim-server
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            echo -e "UIM-Server 启动成功，请使用 UIM-Server log 查看运行日志"
        else
            echo -e "UIM-Server 可能启动失败，请稍后使用 UIM-Server log 查看日志信息"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    systemctl stop uim-server
    sleep 2
    check_status
    if [[ $? == 1 ]]; then
        echo -e "UIM-Server 停止成功"
    else
        echo -e "UIM-Server 停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    systemctl restart uim-server
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        echo -e "UIM-Server 重启成功，请使用 UIM-Server log 查看运行日志"
    else
        echo -e "UIM-Server 可能启动失败，请稍后使用 UIM-Server log 查看日志信息"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    systemctl status uim-server --no-pager -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    systemctl enable uim-server
    if [[ $? == 0 ]]; then
        echo -e "UIM-Server 设置开机自启成功"
    else
        echo -e "UIM-Server 设置开机自启失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    systemctl disable uim-server
    if [[ $? == 0 ]]; then
        echo -e "UIM-Server 取消开机自启成功"
    else
        echo -e "UIM-Server 取消开机自启失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u uim-server.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

update_shell() {
    wget -q -O /usr/bin/uim-server https://github.com/SSPanel-UIM/UIM-Server/raw/main/release/uim-server.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "下载脚本失败，请检查本机能否连接 Github"
        before_show_menu
    else
        chmod +x /usr/bin/uim-server
        echo -e "升级脚本成功，请重新运行脚本" && exit 0
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/uim-server.service ]]; then
        return 2
    fi
    temp=$(systemctl status uim-server | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

check_enabled() {
    temp=$(systemctl is-enabled uim-server)
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
        echo -e "UIM-Server 已安装，请不要重复安装"
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
        echo -e "请先安装 UIM-Server"
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
            echo -e "UIM-Server 状态: 已运行"
            show_enable_status
            ;;
        1)
            echo -e "UIM-Server 状态: 未运行"
            show_enable_status
            ;;
        2)
            echo -e "UIM-Server 状态: 未安装"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "是否开机自启: 是"
    else
        echo -e "是否开机自启: 否"
    fi
}

show_uim_server_version() {
    echo -n "UIM-Server 版本："
    /usr/local/UIM-Server/UIM-Server --version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_usage() {
    echo "UIM-Server 管理脚本使用方法: "
    echo "------------------------------------------"
    echo "uim-server                    - 显示管理菜单 (功能更多)"
    echo "uim-server start              - 启动 UIM-Server"
    echo "uim-server stop               - 停止 UIM-Server"
    echo "uim-server restart            - 重启 UIM-Server"
    echo "uim-server status             - 查看 UIM-Server 状态"
    echo "uim-server enable             - 设置 UIM-Server 开机自启"
    echo "uim-server disable            - 取消 UIM-Server 开机自启"
    echo "uim-server log                - 查看 UIM-Server 日志"
    echo "uim-server update             - 更新 UIM-Server"
    echo "uim-server update x.x.x       - 更新 UIM-Server 指定版本"
    echo "uim-server config             - 显示配置文件内容"
    echo "uim-server install            - 安装 UIM-Server"
    echo "uim-server uninstall          - 卸载 UIM-Server"
    echo "uim-server version            - 查看 UIM-Server 版本"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
--- https://github.com/SSPanel-UIM/UIM-Server ---
  0. 修改配置
————————————————
  1. 安装 UIM-Server
  2. 更新 UIM-Server
  3. 卸载 UIM-Server
————————————————
  4. 启动 UIM-Server
  5. 停止 UIM-Server
  6. 重启 UIM-Server
  7. 查看 UIM-Server 状态
  8. 查看 UIM-Server 日志
————————————————
  9. 设置 UIM-Server 开机自启
 10. 取消 UIM-Server 开机自启
————————————————
 12. 查看 UIM-Server 版本 
 13. 升级维护脚本
 "
 #后续更新可加入上方字符串中
    show_status
    echo && read -p "请输入选择 [0-13]: " num

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
        12) check_install && show_uim_server_version
        ;;
        13) update_shell
        ;;
        *) echo -e "请输入正确的数字 [0-12]"
        ;;
    esac
}


if [[ $# -gt 0 ]]; then
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
        "version") check_install 0 && show_uim_server_version 0
        ;;
        "update_shell") update_shell
        ;;
        *) show_usage
    esac
else
    show_menu
fi
