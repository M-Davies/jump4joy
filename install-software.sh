#!/bin/bash

# System Update #
apt-get update
apt-get upgrade -y

# Install TinyProxy #
apt-get install tinyproxy -y
# shellcheck disable=SC2016
sed -i 's/#BasicAuth user password/BasicAuth ${HTTP_USER} ${HTTP_PASSWORD}/' /etc/tinyproxy/tinyproxy.conf
sed -i 's/^Allow /#Allow /' /etc/tinyproxy/tinyproxy.conf
service tinyproxy restart

# Install Dante #
apt-get install dante-server
useradd -r -s /bin/false "${SOCKS_USER}"
# shellcheck disable=SC2154
echo "${SOCKS_USER}:${SOCKS_PASSWORD}" | chpasswd
rm /etc/danted.conf
cat <<EOT >> /etc/danted.conf
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

# The listening network interface or address.
internal: 0.0.0.0 port=1080

# The proxying network interface or address.
external: eth0

# socks-rules determine what is proxied through the external interface.
socksmethod: username

# client-rules determine who can connect to the internal interface.
clientmethod: none

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}
EOT
systemctl restart danted.service

# Install OpenVPN
apt install openvpn -y
curl https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh -o /home/ubuntu/openvpn-install.sh
chmod +x /home/ubuntu/openvpn-install.sh
export AUTO_INSTALL=y
export MENU_OPTION="1"
export CLIENT="${OPENVPN_USER}"
# shellcheck disable=SC2154
export PASS="${OPENVPN_PASSWORD}"
bash /home/ubuntu/openvpn-install.sh

# Show confirmation
echo "Userdata script successfully completed execution, this file can be deleted" >> /home/ubuntu/userdata_script_completed
