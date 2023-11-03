#!/bin/bash
# shellcheck disable=SC2034

# Parse args
while getopts "hso" currentOpt; do
    case "${currentOpt}" in
        h)
            IFS=: read -r HTTP_USER HTTP_PASSWORD <<< "${OPTARG}"
            ;;
        s)
            IFS=: read -r SOCKS_USER SOCKS_PASSWORD <<< "${OPTARG}"
            ;;
        o)
            IFS=: read -r OPENVPN_USER OPENVPN_PASSWORD <<< "${OPTARG}"
            ;;
        *)
            echo "Usage: ./install-software.sh [-h <HTTP_USER>:<HTTP_PASSWORD>] [-s <SOCKS_USER>:<SOCKS_PASSWORD>] [-o <OPENVPN_USER>:<OPENVPN_PASSWORD>]"
            exit 1
            ;;
    esac
done

# System Update
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

if [[ -n "${HTTP_USER}" ]]; then
    # Install TinyProxy
    apt-get install tinyproxy -y
    # shellcheck disable=SC2016
    sed -i 's/#BasicAuth user password/BasicAuth ${HTTP_USER} ${HTTP_PASSWORD}/' /etc/tinyproxy/tinyproxy.conf
    sed -i 's/^Allow /#Allow /' /etc/tinyproxy/tinyproxy.conf
    service tinyproxy restart
fi

if [[ -n "${SOCKS_PASSWORD}" ]]; then
    # Install Dante
    apt-get install dante-server
    useradd -r -s /bin/false "${SOCKS_USER}"
    # shellcheck disable=SC2154
    echo "${SOCKS_USER}:${SOCKS_PASSWORD}" | chpasswd
    rm /etc/danted.conf
    echo -e "logoutput: syslog\nuser.privileged: root\nuser.unprivileged: nobody\ninternal: 0.0.0.0 port=1080\nexternal: eth0\nsocksmethod: username\nclientmethod: none\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }" > /etc/danted.conf
    systemctl restart danted.service
fi

if [[ -n "${OPENVPN_PASSWORD}" ]]; then
    # Install OpenVPN
    apt install openvpn -y
    curl https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh -o /home/ubuntu/openvpn-install.sh
    chmod +x /home/ubuntu/openvpn-install.sh
    export AUTO_INSTALL=y
    export MENU_OPTION="1"
    export CLIENT="${OPENVPN_USER}"
    # shellcheck disable=SC2154
    export PASS="${OPENVPN_PASSWORD}"
    /home/ubuntu/openvpn-install.sh
    unset CLIENT PASS
fi

# Show confirmation
echo "Userdata script successfully completed execution, this file can be deleted" >> /home/ubuntu/userdata_script_completed
exit 0
