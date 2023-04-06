#!/usr/bin/env bash

#bash -n driver.sh 		# dry run for syntax
#bash -v driver.sh 	# trace
#bash -x driver.sh 	# more vergbose trace

#Fail safe
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
    sudo apt-get update -qq >/dev/null
    sudo apt-get install -y -qq git make gcc libpcap-dev >/dev/null || fail "Failed to install dependencies"
    return 0
}

function check_masscan() {
    if ! [ -x "$(command -v masscan)" ]; then
        info "Masscan is not installed, Installing now!!"
        #building from source
        #echo 'Installing Dependancies for masscan'
        #cd /opt && git clone https://github.com/robertdavidgraham/masscan 1>/dev/null 2>depenadancies.error_log.log
        #cd /opt/masscan && make 1>/dev/null 2>depenadancies.error_log.log

        #using repo
        sudo apt-get install -y -qq masscan 2>./log/depenadancies.error_log.log ||
            fail "Couldn't install masscan"

        success "Masscan Installed"

        return 0
    else
        :
        success "Masscan already installed"

        #echo 'masscan installed'
        #return 0
    fi

}

function check_nrich() {
    if ! [ -x "$(command -v nrich)" ]; then
        :

        info "Nrich is not installed, Installing now!!"

        sudo apt-get install -y -qq wget 2>depenadancies.error_log.log
        # mkdir -p /tmp && cd "$_"
        wget -q https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb -O /tmp/nrich_latest_amd64.deb 2>./log/depenadancies.error_log.log

        sudo apt-get install -y -qq /tmp/nrich_latest_amd64.deb 2>./log/depenadancies.error_log.log ||
            fail "Couldn't install Nrich"

        success "Nrich Installed" ||
            return 0
    else
        :
        success "Nrich already installed"

        #echo 'nrich installed'
        #return 0
    fi

}

function check_jq() {
    if ! [ -x "$(command -v jq)" ]; then
        :
        info "jq is not installed, Installing now!!"

        sudo apt-get install -qq -y jq 2>./log/depenadancies.error_log.log ||
            fail "Couldn't install jq"

        success "jq Installed"

        return 0
    else
        :
        success "JQ already installed"

        #echo 'jq already installed'
        #return 0
    fi

}

function check_inputFile() {
    inputFile="$1"
    if [ -f "${inputFile}" ]; then
        success "${inputFile} exists"

        if grep -q -E '[0-9]{1,3}(\.[0-9]{1,3}){0,3}/[0-9]+' "${inputFile}"; then
            info "${inputFile} format is valid"
            return 0
        else
            question "${inputFile} has invalid IP CIDR blocks, provide one in a valid format"
        fi
    else
        fail "${inputFile} does not exist, please provide a valid file name"
    fi
}

# function masscan_grepaableOutput()
# {
#     sudo masscan -iL "$1" --excludeFile AntiScanIPList.txt --top-ports 20 ---max-rate 100000 -oG masscan_output.txt 2>|./log/masscan.error_log.log
# }

function masscan_jsonOutput() {
    sudo masscan -iL "$1" --excludeFile files/AntiScanIPList.txt --top-ports 20 ---max-rate 100000 -oJ masscan_output.json 2>|./log/masscan.error_log.log
}

# function extractIp_awk()
# {
#     while IFS= read -r line || [[ -n "$line" ]]; do
#         awk '{print $4}' >> nrich_input.txt
#     done < masscan_output.txt
# }

function extractIp_jq() {
    jq -r '.[].ip' masscan_output.json >>nrich_input.txt
}

function nrichScan_json() {
    nrich --output json nrich_input.txt 1>|./enmass3.json 2>|./nrich.error_log.log
}

# function nrichScan_ndjson()
# {
#     nrich --output ndjson nrich_input.txt 1>|./enmass3.ndjson 2>|./log/nrich.error_log.log
# }

# function nrichScan_shell()
# {
#     nrich --output shell nrich_input.txt 1>|./enmass3.txt 2>|./log/nrich.error_log.log
# }

trapcleanup() {
    #rm -f nrich_input.txt
    fail 'Trapped!'
}

main() {
    trap trapcleanup INT TERM ERR
    clear

    # checking for sudo perms
    # if [ "$EUID" -ne 0 ]; then
    #     question "Run the script as root"
    #     fail "Exitting..."
    # fi

    # checking if inputfile is provided as a parameter
    [[ "$#" -eq "0" ]] && {
        fail "No inputfile provided"

    }
    # || {
    #     fileName=$1
    #     info "${fileName:?No file} being used as the input file"
    #     echo ""
    # }

    if install_dependencies && check_masscan && check_nrich && check_jq; then
        :
        if check_inputFile "$@"; then
            :
            fileName=$1
            info "Running masscan..."
            masscan_jsonOutput "$fileName"

            info "Extracting Ips"
            extractIp_jq

            info "Running nrich..."
            nrichScan_json

            success "Scanning complete! Look at enmass.json for the results"
            times
        fi
    fi
}

# set -x																	# set Debug
# for source issues
if ! (return 0 2>/dev/null); then
    main "$@"
fi
# set +x																	# unset Debug
