#!/bin/bash
u=user
function aur_inst() { cd /home/$1;git clone -q https://aur.archlinux.org/$2.git;chmod -R 777 $2;pushd $2;su $1 -c 'makepkg -src';pacman -U *pkg.tar* --noconfirm;popd; rm -R /home/$1/$2; }; export -f aur_inst;

pacman -Syu  --noconfirm \
      	gdb cmake \
        mc bash-completion \
        firefox firefox-i18n-ru qbittorrent \
        samba \
        wireguard-tools \
        ttf-dejavu ttf-liberation \
        gparted f2fs-tools gnome-disk-utility ntfs-3g \
        mpv vlc putty qalculate-qt featherpad \
        libreoffice-still libreoffice-still-ru featherpad \
        qtcreator qbs qt5-websockets qt5-tools qt5-serialport qt5-doc qt5-examples \
        remmina freerdp libvncserver \
        scrcpy xscreensaver network-manager-applet \
        blueman bluez-utils \
        doublecmd-qt5 libunrar p7zip \
        wine winetricks \
        qemu-desktop virt-viewer qemu-user-static-binfmt \
        uboot-tools 

aur_inst $u yay-bin
aur_inst $u f3
aur_inst $u f3-qt
aur_inst $u pacman-cleanup-hook
aur_inst $u libpamac-aur
aur_inst $u pamac-aur
usermod -aG audio,video,storage,uucp $u
