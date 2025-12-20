#!/bin/bash
u=user
function aur_inst() { cd /home/$1;git clone -q https://aur.archlinux.org/$2.git;chmod -R 777 $2;pushd $2;su $1 -c 'makepkg -src';pacman -U *pkg.tar* --noconfirm;popd; rm -R /home/$1/$2; }; export -f aur_inst;

pacman -Syu  --noconfirm \
		gdb cmake \
        mc bash-completion sudo \
        firefox firefox-i18n-ru qbittorrent \
        samba \
        wireguard-tools \
        ttf-dejavu ttf-liberation \
        gparted f2fs-tools gnome-disk-utility ntfs-3g dosfstools mtools \
        mpv vlc putty qalculate-qt featherpad pipewire-pulse \
        libreoffice-still libreoffice-still-ru featherpad \
        qtcreator qbs qt5-websockets qt5-tools qt5-serialport qt5-doc qt5-examples \
        remmina freerdp libvncserver webkit2gtk-4.1 \
        scrcpy xscreensaver network-manager-applet networkmanager-openvpn \
        blueman bluez-utils \
        doublecmd-qt5 libunrar p7zip \
        wine winetricks lib32-vulkan-intel \
        qemu-desktop virt-viewer qemu-user-static-binfmt \
        uboot-tools \
        python-pyelftools python-cryptography \ 
        noto-fonts-cjk noto-fonts-emoji noto-fonts \
        bc swig inetutils \
        rtkit \
        gvfs-smb sshfs cups gnome-keyring \
        squashfs-tools mtd-utils \
        nss-mdns 
         
aur_inst $u yay-bin
aur_inst $u f3
aur_inst $u f3-qt
aur_inst $u pacman-cleanup-hook
aur_inst $u libpamac-aur
aur_inst $u pamac-aur
usermod -aG audio,video,storage,uucp,cups,wheel $u
echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers.d/wheel
sed -E -i 's/(hosts\: mymachines) (resolve \[\!UNAVAIL\=return\] files myhostname dns)/\1 mdns_minimal [NOTFOUND=return] \2/g' /etc/nsswitch.conf
systemctl enable --now avahi-daemon.service
