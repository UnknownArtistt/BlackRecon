#!/bin/bash

# Check and install Nmap
if ! command -v nmap &> /dev/null; then
    echo "Nmap is not installed. Installing Nmap..."
    sudo apt-get install -y nmap
else
    echo "Nmap is already installed."
fi

# Check and install GCC
if ! command -v gcc &> /dev/null; then
    echo "GCC is not installed. Installing GCC..."
    sudo apt-get install -y gcc
else
    echo "GCC is already installed."
fi

# Check and install Figlet
if ! command -v figlet &> /dev/null; then
    echo "Figlet is not installed. Installing Figlet..."
    sudo apt-get install -y figlet
else
    echo "Figlet is already installed."
fi

# Clone the repository
git clone https://github.com/UnknownArtistt/BlackRecon.git
cd BlackRecon

# Compile the program
gcc -o BlackRecon BlackRecon.c

# Inform the user
echo "BlackRecon has been installed and compiled successfully."
echo "You can run the program using ./BlackRecon or you can run it with sudo for more advanced scanning."
