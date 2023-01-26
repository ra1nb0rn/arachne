#!/bin/bash

LINUX_PACKAGE_MANAGER="apt"
CWD=$(pwd)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

install_chromedriver_linux() {
    POSSIBLE_PKGS="chromium-driver chromium-chromedriver"
    SUCCESS=0

    ${LINUX_PACKAGE_MANAGER} update
    for pkg in $POSSIBLE_PKGS; do
        sudo ${LINUX_PACKAGE_MANAGER} install -y $pkg
        if [ $? -eq 0 ]; then
            SUCCESS=1
            sudo ${LINUX_PACKAGE_MANAGER} install --only-upgrade -y $pkg
            break
        fi
    done

    if [ $SUCCESS != 1 ]; then
        printf "Could not install chromedriver. Please install it manually."
        exit 1
    fi
}

OLD_DIR="$(pwd)"
cd "${SCRIPT_DIR}"

# install PIP packages
pip3 install -r requirements.txt

# install linkfinder
if [ ! -d LinkFinder ]; then
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip3 install -r requirements.txt
    cd ..
fi

# install chromedriver for selenium
KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    # if $REAL_USER_NAME is not set, e.g. by parent script, set it
    if [ -z $REAL_USER_NAME ]; then
        REAL_USER_NAME=$(who am i | cut -d" " -f1)
    fi

    sudo -u $REAL_USER_NAME brew cask install chromedriver
    sudo -u $REAL_USER_NAME brew cask upgrade chromedriver

    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "" -e "1s/python$/python3/" LinkFinder/linkfinder.py
elif [ "${KERNEL}" == "Linux" ]; then
    # chromedriver is installed differently on different Linux distros
    install_chromedriver_linux

    # edit the first line to have linkfinder run with Python 3 by default
    sed -i "1s/python$/python3/" LinkFinder/linkfinder.py
else
    printf "Could not identify running OS.\\nPlease install chromedriver manually."
    exit 1
fi

cd "${OLD_DIR}"
