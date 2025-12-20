USER_NAME=u
USER_PASS=123
CN_NAME="small-CA"
export EASYRSA=/etc/easy-rsa
export EASYRSA_VARS_FILE=${EASYRSA}/vars

OPENVPN_P=/etc/openvpn
OPENVPN_SRV_CFG=${OPENVPN_P}/server.conf
OPENVPN_SERVER_PROTOCOL="tcp"

SERVER_OUT_IF=$(ip r | awk '/default/ {print $5}')
SERVER_OUT_IP=$(ip a show $SERVER_OUT_IF | sed 's/.*inet \([^/]*\).*/\1/;t;d')

WG_P=/etc/wireguard
WG_IF_NAME=wg0
WG_CONF=${WG_P}/${WG_IF_NAME}.conf
WG_IF_NET=10.10.11.0/24

WGA_P=/etc/amnezia/amneziawg
WGA_IF_NAME=wga0
WGA_CONF=${WGA_P}/${WGA_IF_NAME}.conf
WGA_IF_NET=10.10.10.0/24

function rand_free_tcp_port(){
  local OPEN_PORTS=$(awk -F' ' '{print substr($2, 10)}' /proc/net/tcp)
  local PORT=$(shuf -i 1024-65535 -n 1)
  local PORT_HEX=$((16#$PORT))
  while [[ " ${OPEN_PORTS[*]} " =~ [[:space:]]${PORT_HEX}[[:space:]] ]]; do
    local PORT=$(shuf -i 1024-65535 -n 1)
    local PORT_HEX=$((16#$$PORT))
  done
  echo $PORT
}

function rand_free_udp_port(){
  local OPEN_PORTS=$(awk -F' ' '{print substr($2, 10)}' /proc/net/udp)
  local PORT=$(shuf -i 1024-65535 -n 1)
  local PORT_HEX=$((16#$PORT))
  while [[ " ${OPEN_PORTS[*]} " =~ [[:space:]]${PORT_HEX}[[:space:]] ]]; do
    local PORT=$(shuf -i 1024-65535 -n 1)
    local PORT_HEX=$((16#$$PORT))
  done
  echo $PORT
}

function gen_new_ip(){
  local CFG=$1
  local ADR=$(sed -n 's/Address = \(.*\)$/\1/p' ${CFG})
  # local SUB_NET=$(sed 's/.*\/\(.*\)$/\1/' <<< $ADR)
  local BASE_ADR=$(sed 's/^\(.*\).[0-9]*\/[0-9]*$/\1/' <<< $ADR)
  local ADRS=$(sed -n 's/.*'$BASE_ADR'\([0-9]*\).*/\1/pg' ${CFG})
  local NEW_ADR=1
    while [[ " ${ADRS[*]} " =~ [[:space:]]${NEW_ADR}[[:space:]] ]]; do
    local NEW_ADR=$((NEW_ADR + 1))
  done
  # TODO check overflow
  echo ${BASE_ADR}${NEW_ADR}
}

function setup_apps(){
  apt update && apt upgrade
  apt -y install "$@"
  apt autoremove && apt clean && rm -r /var/lib/apt/lists/*
}

function setup_os() {
  setup_apps sudo
  useradd -m $USER_NAME
  usermod -a -G wheel $USER_NAME
  echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers.d/wheel
  passwd $USER_NAME --stdin <<< "$USER_PASS"
}

function setup_openssh() {
  local SSH_SERVER_NEW_PORT=$(rand_free_tcp_port)
  setup_apps openssh
  sudo -u $USER_NAME bash -c "
    ssh-keygen -t rsa -b 4096 ;
    mv ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys ;
    cat ~/.ssh/id_rsa ;
    rm ~/.ssh/id_rsa ;
"
sed -i "s/^PermitRootLogin yes$/#PermitRootLogin yes/" /etc/ssh/sshd_config
sed -i "s/^#PubkeyAuthentication yes$/PubkeyAuthentication yes/" /etc/ssh/sshd_config
sed -i "s/^#PasswordAuthentication yes$/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^UsePAM yes$/UsePAM no/" /etc/ssh/sshd_config
sed -i 's/.*Port [0-9]*/Port '${SSH_SERVER_NEW_PORT}'/' /etc/ssh/sshd_config

echo "Host ${SERVER_OUT_IP}
    HostName ${SERVER_OUT_IP}
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes # see NOTES below
    Port ${SSH_SERVER_NEW_PORT}
    User ${USER_NAME}"

nft_open_tcp_port ${SSH_SERVER_NEW_PORT}
systemctl restart sshd
}

function setup_server_opevpn() {
  setup_apps easy-rsa openvpn
  make-cadir $EASYRSA
  cat << EOF >> ${EASYRSA}/vars
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_ALGO  ed
set_var EASYRSA_CURVE ed25519
EOF

  pushd ${EASYRSA}/
  ./easyrsa init-pki
  ./easyrsa --batch --req-cn=$CN_NAME build-ca nopass
  ./easyrsa --batch build-server-full $CN_NAME nopass
  popd

  openssl dhparam -out ${OPENVPN_P}/server/dh.pem 2048
  openvpn --genkey tls-auth ${OPENVPN_P}/server/ta.key

  cp ${EASYRSA}/pki/private/$CN_NAME.key ${OPENVPN_P}/server/
  cp ${EASYRSA}/pki/ca.crt ${OPENVPN_P}/server/
  cp ${EASYRSA}/pki/issued/$CN_NAME.crt ${OPENVPN_P}/server/

  # chown openvpn:network ${OPENVPN_P}/server/ta.key
  # chown openvpn:network ${OPENVPN_P}/server/ca.crt
  # chown openvpn:network ${OPENVPN_P}/server/$CN_NAME.crt

  openvpn_gen_server
  systemctl enable --now openvpn@server.service
}

function gen_server_openvpn {
  local OPENVPN_SERVER_NEW_PORT=$(rand_free_tcp_port)

  cat <<EOF > $OPENVPN_SRV_CFG
local ${SERVER_OUT_IP}
port ${OPENVPN_SERVER_NEW_PORT}
proto ${OPENVPN_SERVER_PROTOCOL}
dev tun
cipher CHACHA20-POLY1305
data-ciphers CHACHA20-POLY1305
ca ${OPENVPN_P}/server/ca.crt
cert ${OPENVPN_P}/server/${CN_NAME}.crt
key ${OPENVPN_P}/server/${CN_NAME}.key
dh ${OPENVPN_P}/server/dh.pem
tls-auth ${OPENVPN_P}/server/ta.key 0
server 10.11.11.0 255.255.255.0 nopool
ifconfig-pool 10.11.11.11 10.11.11.254
ifconfig-pool-persist /var/log/openvpn/ipp.txt
topology subnet
push "redirect-gateway def1 bypass-dhcp"
keepalive 10 120
max-clients 128
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
mute 20
daemon
mode server
tls-server
comp-lzo
EOF
}

function gen_client_openvpn {
  local NAME=$1
  pushd ${EASYRSA}/
  ./easyrsa build-client-full $NAME nopass
  popd
  local OPENVPN_CLIENT_KEY=$(cat ${EASYRSA}/pki/private/${NAME}.key)
  local OPENVPN_CLIENT_CRT=$(cat ${EASYRSA}/pki/issued/${NAME}.crt | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p')
  local OPENVPN_SERVER_PORT=$(grep port $OPENVPN_SRV_CFG | sed 's/port //')
  local OPENVPN_SERVER_CA=$(cat ${OPENVPN_P}/server/ca.crt)
  local OPENVPN_SERVER_TA=$(cat ${OPENVPN_P}/server/ta.key)

  cat <<EOF > /root/${NAME}.ovpn
client
dev tun
proto ${OPENVPN_SERVER_PROTOCOL}
remote ${SERVER_OUT_IP} ${OPENVPN_SERVER_PORT}
cipher CHACHA20-POLY1305
data-ciphers CHACHA20-POLY1305
key-direction 1
resolv-retry infinite
nobind
mute-replay-warnings
remote-cert-tls server
comp-lzo
verb 3
<ca>
${OPENVPN_SERVER_CA}
</ca>
<tls-auth>
${OPENVPN_SERVER_TA}
</tls-auth>
<cert>
${OPENVPN_CLIENT_CRT}
</cert>
<key>
${OPENVPN_CLIENT_KEY}
</key>
EOF
}

function nft_open_tcp_port() {
  local PORT=$1
  local I=input
  local T=fw
  nft add rule inet $T $I tcp dport ${PORT} ct state new accept
  nft_save_rules
}

function nft_open_udp_port() {
  local PORT=$1
  local I=input
  local T=fw
  nft add rule inet $T $I udp dport ${PORT} accept
  nft_save_rules
}

function nft_inital_set {

  local OPENVPN_SERVER_PORT=$(grep port $OPENVPN_SRV_CFG | sed 's/port //')
  local T=fw
  local N=nat
  local I=input
  local F=forward
  local POR=postrouting
  local PRR=prerouting
  sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  sysctl -p
  nft flush ruleset

  # nft define OPEN_TCP_PORT = ${OPENVPN_SERVER_PORT}

  nft add table inet $T
  nft add chain inet $T $I '{ type filter hook input priority filter ; policy drop ; }'
  nft add rule  inet $T $I ct state vmap '{ established : accept, related : accept, invalid : drop }'
  nft add rule  inet $T $I iifname "lo" accept
  nft add rule  inet $T $I meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second accept

  # nft add set   inet $T ssh_blacklist { type ipv4_addr; flags timeout; }
  # nft add rule  inet $T $I tcp dport ssh ct state new limit rate 10/minute accept
  # nft add rule  inet $T $I tcp dport ssh ct state new add @ssh_blacklist { ip saddr timeout 1h } counter drop
  # nft add rule  inet $T $I ip saddr @ssh_blacklist counter drop
  # nft add chain inet $T $F '{ type filter hook forward priority 50 ; policy drop ; }'

  nft add table ip $N
  nft add chain ip $N $PRR { type nat hook $PRR priority -100 \; }
  nft add chain ip $N $POR { type nat hook $POR priority  100 \; }
  nft add rule     $N $POR ip saddr { $WGA_IF_NET, $WG_IF_NET } oifname "$SERVER_OUT_IF" masquerade
  #  iptables -A FORWARD -i tun0 -o tun0 -j DROP

nft_save_rules
systemctl enable --now nftables
}

function nft_save_rules {
  cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset
$(nft list ruleset)
EOF
}

function setup_server_wg() {
  setup_apps wireguard openresolv

  local WG_SRV_PRI_KEY=$(wg genkey)
  local WG_PORT=$(rand_free_udp_port)
  local WG_SRV_IP=$(sed 's/\([^.]*\).\([^.]*\).\([^.]*\).\([^/]*\)\/\([0-9]*\)$/\1.\2.\3.1\/\5/' <<< $WG_IF_NET)

  mkdir -p $WG_P

  cat << EOF > ${WG_CONF}
[Interface]
Address = ${WG_IF_NET}
ListenPort = ${WG_PORT}
PrivateKey = ${WG_SRV_PRI_KEY}

EOF

  nft_open_udp_port ${WG_PORT}
  systemctl enable --now wg-quick@${WG_IF_NAME}.service
}

function gen_client_wg {
  local NAME=$1
  local WG_PSH_KEY=$(wg genpsk)
  local WG_CLNT_PRI_KEY=$(wg genkey)
  local WG_CLNT_PUB_KEY=$(echo $WG_CLNT_PRI_KEY | wg pubkey)
  local WG_SRV_PUB_KEY=$(grep PrivateKey ${WG_CONF} | sed 's/PrivateKey = //' | wg pubkey)
  local WG_SRV_PORT=$(grep ListenPort ${WG_CONF} | sed 's/ListenPort = //')
  local WG_CLI_IP=$(gen_new_ip ${WG_CONF})

  cat << EOF >> ${WG_CONF}
# ${NAME}
[Peer]
PublicKey = ${WG_CLNT_PUB_KEY}
AllowedIPs = ${WG_CLI_IP}/32
PresharedKey = ${WG_PSH_KEY}

EOF

  cat << EOF > /root/wg_${NAME}.conf
[Interface]
DNS = 8.8.8.8
Address = ${WG_CLI_IP}/32
PrivateKey = ${WG_CLNT_PRI_KEY}

[Peer]
Endpoint = ${SERVER_OUT_IP}:${WG_SRV_PORT}
PublicKey = ${WG_SRV_PUB_KEY}
AllowedIPs = 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 8.8.8.8/32
PresharedKey = ${WG_PSH_KEY}
PersistentKeepalive = 69
EOF

awg syncconf ${WG_IF_NAME} <(awg-quick strip ${WG_IF_NAME})
}

function setup_server_awg() {
  setup_apps software-properties-common openresolv
  add-apt-repository -y ppa:amnezia/ppa
  setup_apps amneziawg
  local WGA_SRV_PRI_KEY=$(wg genkey)
  local WGA_PORT=$(rand_free_udp_port)
  local JC=$(shuf -i 4-9 -n 1)
  local JMIN=$(shuf -i 10-55 -n 1)
  local JMAX=$(shuf -i $(($S1+10))-$(($S1+60)) -n 1)
  local S1=$(shuf -i 10-55 -n 1)
  local S2=$(shuf -i $S1-$(($S1+50)) -n 1)
  local H1=$(shuf -i 1024-2147483647 -n 1)
  local H2=$(shuf -i 1024-2147483647 -n 1)
  local H3=$(shuf -i 1024-2147483647 -n 1)
  local H4=$(shuf -i 1024-2147483647 -n 1)
  WGA_SRV_IP=$(sed 's/\([^.]*\).\([^.]*\).\([^.]*\).\([^/]*\)\/\([0-9]*\)$/\1.\2.\3.1\/\5/' <<< $WGA_IF_NET)

  mkdir -p $WG_P

  cat << EOF > ${WGA_CONF}
[Interface]
Address = ${WGA_SRV_IP}
ListenPort = ${WGA_PORT}
PrivateKey = ${WGA_SRV_PRI_KEY}

Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
# I1 =
# I2 =
# I3 =
# I4 =
# I5 =
# MTU = 1280

EOF

  nft_open_udp_port ${WGA_PORT}
  systemctl enable --now awg-quick@${WGA_IF_NAME}.service
}

function gen_client_awg {
  local NAME=$1
  local WGA_PSH_KEY=$(wg genpsk)
  local WGA_CLNT_PRI_KEY=$(wg genkey)
  local WGA_CLNT_PUB_KEY=$(echo $WGA_CLNT_PRI_KEY | wg pubkey)
  local WGA_SRV_PUB_KEY=$(grep PrivateKey ${WGA_CONF} | sed 's/PrivateKey = //' | wg pubkey)
  local WGA_SRV_PORT=$(grep ListenPort ${WGA_CONF} | sed 's/ListenPort = //')
  local WGA_CLI_IP=$(gen_new_ip ${WGA_CONF})

  local JC=$(grep "Jc = " ${WGA_CONF} | sed 's/Jc = //')
  local JMIN=$(grep "Jmin = " ${WGA_CONF} | sed 's/Jmin = //')
  local JMAX=$(grep "Jmax = " ${WGA_CONF} | sed 's/Jmax = //')
  local S1=$(grep "S1 = " ${WGA_CONF} | sed 's/S1 = //')
  local S2=$(grep "S2 = " ${WGA_CONF} | sed 's/S2 = //')
  local H1=$(grep "H1 = " ${WGA_CONF} | sed 's/H1 = //')
  local H2=$(grep "H2 = " ${WGA_CONF} | sed 's/H2 = //')
  local H3=$(grep "H3 = " ${WGA_CONF} | sed 's/H3 = //')
  local H4=$(grep "H4 = " ${WGA_CONF} | sed 's/H4 = //')

  cat << EOF >> ${WGA_CONF}
# ${NAME}
[Peer]
PublicKey = ${WGA_CLNT_PUB_KEY}
AllowedIPs = ${WGA_CLI_IP}/32
PresharedKey = ${WGA_PSH_KEY}

EOF

  cat << EOF > /root/awg_${NAME}.conf
[Interface]
DNS = 8.8.8.8
Address = ${WGA_CLI_IP}/32
PrivateKey = ${WGA_CLNT_PRI_KEY}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
# I1 =
# I2 =
# I3 =
# I4 =
# I5 =
# MTU = 1280

[Peer]
Endpoint = ${SERVER_OUT_IP}:${WGA_SRV_PORT}
PublicKey = ${WGA_SRV_PUB_KEY}
AllowedIPs = 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 8.8.8.8/32
PresharedKey = ${WGA_PSH_KEY}
PersistentKeepalive = 69
EOF

awg syncconf ${WGA_IF_NAME} <(awg-quick strip ${WGA_IF_NAME})
}
