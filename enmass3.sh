#!/usr/bin/env bash

#bash -n driver.sh  # dry run for syntax
#bash -v driver.sh  # trace
#bash -x driver.sh  # more vergbose trace

# Fail safe mech
set -o errexit  # fail on exit
set -o nounset  # fail on variable issues
set -o pipefail # fail for pipe related stuff

function info() {
    printf "\r  [ \033[00;34m>..\033[0m ] %s\n" "$1"
}

function question() {
    printf "\r  [ \033[0;33m??\033[0m ] %s\n" "$1"
}

function success() {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] %s\n" "$1"
}

function fail() {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] %s\n" "$1"
    echo ''
    exit 1
}

function install_dependencies() {
    # Check if dependencies are already installed
    if command -v git &> /dev/null && command -v make &> /dev/null && command -v gcc &> /dev/null && command -v libpcap-dev &> /dev/null; then
        success "Dependencies already installed"
        return 0
    fi

    sudo apt-get update -qq >/dev/null || fail "Failed to update"
    sudo apt-get install -y -qq git make gcc libpcap-dev >/dev/null || fail "Failed to install dependencies"
}

function check_masscan() {
    if ! command -v masscan &> /dev/null; then
        info "Masscan is not installed, Installing now!!"

        #building from source
        #echo 'Installing Dependancies for masscan'
        #cd /opt && git clone https://github.com/robertdavidgraham/masscan 1>/dev/null 2>./log/depenadancies.error_log.log
        #cd /opt/masscan && make 1>/dev/null 2>./log/depenadancies.error_log.log
        
        sudo apt-get install -y -qq masscan 2>./log/masscan_install.log || fail "Couldn't install Masscan"
        success "Masscan Installed"
    else
        success "Masscan already installed"
    fi
}


function check_nrich() {
    if ! command -v nrich &> /dev/null; then
        info "Nrich is not installed, Installing now!!"

        # mkdir -p /tmp && cd "$_"
        wget -q https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb -O /tmp/nrich_latest_amd64.deb 2>./log/nrich_install.log
        sudo apt-get install -y -qq /tmp/nrich_latest_amd64.deb 2>./log/nrich_install.log || fail "Couldn't install Nrich"

        success "Nrich Installed"
    else
        success "Nrich already installed"
    fi
}

function check_jq() {
    if ! command -v jq &> /dev/null; then
        info "jq is not installed, Installing now!!"

        sudo apt-get install -qq -y jq 2>./log/jq_install.log || fail "Couldn't install jq"
        success "jq Installed"
    else
        success "jq already installed"
    fi
}

function check_inputFile(inputFile) {
    if [[ ! -f "$inputFile" ]]; then
        fail "${inputFile} does not exist, please provide a valid file name"
    fi

    # TODO: Find something more robust
    if ! grep -q -E '[0-9]{1,3}(\.[0-9]{1,3}){0,3}/[0-9]+' "$inputFile"; then
        question "${inputFile} has invalid IP CIDR blocks. Please provide a file with valid IP CIDR blocks in the format: 192.168.1.0/24"
        exit 1
    fi

    success "${inputFile} is valid"
}

function masscan_scan(masscanOutputFormat, inputFile) {
    masscanOutputFormat="${masscanOutputFormat:-json}"  # Default to JSON
    excludeFile="AntiScanIPList.txt"
    
    if [[ "$masscanOutputFormat" == "greppable" ]]; then
        masscan -iL "$inputFile" --excludeFile "$excludeFile" --top-ports 20 --max-rate 100000 -oG masscan_output.txt 2>./log/masscan.log
    elif [[ "$masscanOutputFormat" == "json" ]]; then
        masscan -iL "$inputFile" --excludeFile "$excludeFile" --top-ports 20 --max-rate 100000 -oJ masscan_output.json 2>./log/masscan.log
    else
        fail "Invalid Masscan output format. Please choose 'greppable' or 'json'."
    fi
}

function extract_ips(masscanOutputFormat, inputFile) {
    if [[ "$masscanOutputFormat" == "greppable" ]]; then
        awk '{print $4}' masscan_output.txt > nrich_input.txt
    elif [[ "$masscanOutputFormat" == "json" ]]; then
        #masscan -iL "$inputFile" --excludeFile "$excludeFile" --top-ports 20 --max-rate 100000 -oJ masscan_output.json 2>./log/masscan.log | jq -r '.[].ip' > nrich_input.txt
        jq -r '.[].ip' masscan_output.json >> nrich_input.txt
    fi
}

function nrich_scan(nrichOutputFormat) {
    nrichOutputFormat="${nrichOutputFormat:-json}"  # Default to JSON

    if [[ "$nrichOutputFormat" == "json" ]]; then
        nrich --output json nrich_input.txt 1>enmass3.json 2>./log/nrich.log
    elif [[ "$nrichOutputFormat" == "shell" ]]; then
        nrich --output shell nrich_input.txt 1>enmass3.txt 2>./log/nrich.log
    elif [[ "$nrichOutputFormat" == "ndjson" ]]; then
        nrich --output ndjson nrich_input.txt 1>enmass3.ndjson 2>./log/nrich.log
    else
        fail "Invalid Nrich output format. Please choose 'json', 'shell', or 'ndjson'."
    fi
}

main() {
    trap 'fail "Interrupted"' INT TERM ERR
    clear

    # checking for sudo perms
    # if [ "$EUID" -ne 0 ]; then
    #     question "Run the script as root"
    #     fail "Exitting..."
    # fi

    # checking if inputfile is provided as a parameter
    [[ "$#" -eq "0" ]] && {
        fail "No input file provided"
    }
    # || {
    #     fileName=$1
    #     info "${fileName:?No file} being used as the input file"
    #     echo ""
    # }

    inputFile="$1"

    install_dependencies
    check_masscan
    check_nrich
    check_jq
    check_inputFile "$inputFile"

    read -p "Choose Masscan output format (greppable/json, default: json): " masscanOutputFormat
    read -p "Choose Nrich output format (json/shell/ndjson, default: json): " nrichOutputFormat

    info "Running Masscan..."
    masscan_scan "$masscanOutputFormat" "$inputFile"
    
    info "Extracting IPs..."
    extract_ips "$masscanOutputFormat" "$inputFile"

    info "Running Nrich..."
    nrich_scan "$nrichOutputFormat"

    success "Scanning complete! Look at enmass3.json for the results"
}

# set -x																	# set Debug
# for source issues
if ! (return 0 2>/dev/null); then
    main "$@"
fi
# set +x																	# unset Debug
