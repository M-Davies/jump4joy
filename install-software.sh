#!/bin/bash
# shellcheck disable=SC2034

# Parse args
HTTP_USER=
HTTP_PASSWORD=
SOCKS_USER=
SOCKS_PASSWORD=
OPENVPN_CLIENT=
echo "[*] Parsing Arguments"
while getopts "h:s:o:" currentOpt; do
    case "${currentOpt}" in
        h)
            IFS=: read -r HTTP_USER HTTP_PASSWORD <<< "${OPTARG}"
            ;;
        s)
            IFS=: read -r SOCKS_USER SOCKS_PASSWORD <<< "${OPTARG}"
            ;;
        o)
            OPENVPN_CLIENT="${OPTARG}"
            ;;
        *)
            echo "Usage: ./install-software.sh [ -h <HTTP_USER>:<HTTP_PASSWORD> ] [ -s <SOCKS_USER>:<SOCKS_PASSWORD> ] [ -o <OPENVPN_CLIENT> ]"
            exit 1
            ;;
    esac
done
shift "$(($OPTIND-1))"

# System Update
export DEBIAN_FRONTEND=noninteractive
echo "[*] Updating System"
apt-get update
apt-get upgrade -y

if [[ -n "$HTTP_USER" ]]; then
    # Install TinyProxy
    echo "[*] Installing TinyProxy"
    apt-get install tinyproxy -y
    # shellcheck disable=SC2016
    echo "[*] Configuring TinyProxy"
    sed -i "s/#BasicAuth user password/BasicAuth $HTTP_USER $HTTP_PASSWORD/" /etc/tinyproxy/tinyproxy.conf
    sed -i "s/^Allow /#Allow /" /etc/tinyproxy/tinyproxy.conf
    echo "[*] Restarting TinyProxy"
    systemctl restart tinyproxy
    systemctl enable tinyproxy
    echo "[+] TinyProxy Running!"
fi

if [[ -n "$SOCKS_PASSWORD" ]]; then
    # Install Dante
    echo "[*] Installing Dante"
    apt-get install dante-server
    echo "[*] Establishing Dante user"
    useradd -r -s /bin/false "$SOCKS_USER"
    # shellcheck disable=SC2154
    echo "$SOCKS_USER:$SOCKS_PASSWORD" | chpasswd
    echo "[*] Configuring Dante"
    rm /etc/danted.conf
    echo -e "logoutput: syslog\nuser.privileged: root\nuser.unprivileged: nobody\ninternal: 0.0.0.0 port=1080\nexternal: eth0\nsocksmethod: username\nclientmethod: none\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }" > /etc/danted.conf
    echo "[*] Restarting Dante"
    systemctl restart danted
    systemctl enable danted
    echo "[+] Dante Running!"
fi

if [[ -n "$OPENVPN_CLIENT" ]]; then
    # Install OpenVPN
    echo "[*] Installing OpenVPN"
    apt install openvpn -y
    echo "[*] Downloading OpenVPN quick install script"
    curl https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh -o /home/ubuntu/openvpn-install.sh
    chmod +x /home/ubuntu/openvpn-install.sh
    chown ubuntu:ubuntu /home/ubuntu/openvpn-install.sh
    echo "[*] Running OpenVPN quick install script"
    export AUTO_INSTALL=y
    export MENU_OPTION="1"
    export CLIENT="$OPENVPN_CLIENT"
    export PASS="1"
    /home/ubuntu/openvpn-install.sh
    chown ubuntu:ubuntu "/home/ubuntu/$OPENVPN_CLIENT.ovpn"
    echo "[+] OpenVPN Running!"
fi

# Show confirmation
echo "Userdata script successfully completed execution, this file can be deleted" >> /home/ubuntu/userdata_script_completed
chown ubuntu:ubuntu /home/ubuntu/userdata_script_completed
echo "[+] Script complete"
exit 0
