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
WG_CONF=${WG_P}/wg0.conf
WGA_CONF=${WG_P}/wga0.conf

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
# sed -i "s/^$//" /etc/ssh/sshd_config

}

function setup_opevpn() {
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

function openvpn_gen_server {
  local OPENVPN_SERVER_NEW_PORT=$(shuf -i 1024-65535 -n 1)
  # TODO rework on RANMOD with check /proc/net/tcp
  # OPENVPN_SERVER_NEW_PORT=$(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 ))
  # cat /proc/net/tcp | check local adress port

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

function openvpn_gen_client {
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


function fwall_set {

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
  nft add rule  inet $T $I tcp dport 22 ct state new accept
  nft add rule  inet $T $I tcp dport ${OPENVPN_SERVER_PORT} ct state new accept
  nft add rule  inet $T $I meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second accept

  # nft add set   inet $T ssh_blacklist { type ipv4_addr; flags timeout; }
  # nft add rule  inet $T $I tcp dport ssh ct state new limit rate 10/minute accept
  # nft add rule  inet $T $I tcp dport ssh ct state new add @ssh_blacklist { ip saddr timeout 1h } counter drop
  # nft add rule  inet $T $I ip saddr @ssh_blacklist counter drop
  # nft add chain inet $T $F '{ type filter hook forward priority 50 ; policy drop ; }'

  nft add table ip $N
  nft add chain ip $N $PRR { type nat hook $PRR priority -100 \; }
  nft add chain ip $N $POR { type nat hook $POR priority  100 \; }
  nft add rule     $N $POR ip saddr 10.11.11.0/24 oifname "$SERVER_OUT_IF" masquerade
  #  iptables -A FORWARD -i tun0 -o tun0 -j DROP

cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

$(nft list ruleset)
EOF

systemctl enable --now nftables
}

function setup_wg() {
  setup_apps wireguard openresolv

  local WG_SRV_PRI_KEY=$(wg genkey)

  mkdir -p $WG_P

  cat << EOF > ${WG_CONF}
[Interface]
Address = 10.200.200.1/24
#PostUp =   echo nft add masquerade
#PostDown = echo nft del masquerade
ListenPort = 10203
PrivateKey = ${WG_SRV_PRI_KEY}

EOF

  systemctl enable --now wg-quick@wg0.service
}

function wg_gen_client {
  local NAME=$1
  local WG_PSH_KEY=$(wg genpsk)
  local WG_CLNT_PRI_KEY=$(wg genkey)
  local WG_CLNT_PUB_KEY=$(echo $WG_CLNT_PRI_KEY | wg pubkey)
  local WG_SRV_PUB_KEY=$(grep PrivateKey ${WG_CONF} | sed 's/PrivateKey = //' | wg pubkey)
  local WG_SRV_PORT=$(grep ListenPort ${WG_CONF} | sed 's/ListenPort = //')

  cat << EOF >> ${WG_CONF}
# ${NAME}
[Peer]
Address = 10.200.200.2/24
PublicKey = ${WG_CLNT_PUB_KEY}
PresharedKey = ${WG_PSH_KEY}

EOF

  cat << EOF > /root/wg_${NAME}.conf
[Interface]
DNS = 8.8.8.8
Address = 10.200.200.2/32
PrivateKey = ${WG_CLNT_PRI_KEY}

[Peer]
Endpoint = ${SERVER_OUT_IP}:${WG_SRV_PORT}
PublicKey = ${WG_SRV_PUB_KEY}
AllowedIPs = 0.0.0.0/0
PresharedKey = ${WG_PSH_KEY}
PersistentKeepalive = 21
EOF
}

# TODO: rework opvn / wg local net IPs
