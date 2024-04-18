#!/bin/bash

# Clone the Charm-Crypto repository
git clone https://github.com/JHUISI/charm/ --depth 1 --branch=dev ~/charm
cd ~/charm

# Configure and install Charm-Crypto
./configure.sh --python=python3.10 && make && sudo make install && sudo ldconfig
