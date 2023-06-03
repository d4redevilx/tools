#!/usr/bin/env bash

# author: d4redevilx
# version: 1.0.0

#Colors
declare -r GREEN="\e[0;32m"
declare -r END_COLOR="\033[0m"
declare -r RED="\e[0;31m"
declare -r BLUE="\e[0;34m"
declare -r YELLOW="\e[0;33m"
declare -r PURPLE="\e[0;35m"
declare -r TURQUOUISE="\e[0;36m"
declare -r GRAY="\e[0;37m"

print_head() {
  echo -e """
  ${BLUE}
  ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                           ${END_COLOR}${YELLOW}by d4redevilx${END_COLOR}
  """
}

sigint_handler() {
  stop_loading_animation
  remove_tmp_files
  tput cnorm
  exit 1  
}

trap sigint_handler SIGINT

loading_animation() {
  chars="/ | \\ -"
  while true;
  do
    for char in $chars;
    do
      printf "\r${YELLOW}[$char] ${END_COLOR}${BLUE}$1${END_COLOR}" 
      sleep 0.15
    done
   done
  printf "\n"
}

start_loading_animation() {
  loading_animation "$1" &
  loading_animation_pid="${!}"
}

stop_loading_animation() {
  kill $loading_animation_pid &> /dev/null
}

valid_ip() {
  if [[ "$ip" = "" ]]; then
    echo -e "${RED}[!] IP Required${END_COLOR}"
    exit 1;
  fi
    
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] The IP address ${END_COLOR}${GRAY}$ip${END}${RED} is not valid${END_COLOR}"
    exit 1;
  fi
}

get_ttl() {
  local ip="$1"
  
  timeout 2 ping -c 1 "$ip" 1>icmp_response 2>/dev/null

  if [[ $? -ne 0 ]]; then
    echo -e "\n${RED}[!] The IP $ip doesn't respond to the ICMP trace${END_COLOR}\n"
    sigint_handler
  fi

  ttl=$(cat icmp_response | grep -oP "ttl=\K[0-9]+")
}

get_os() {
  if [[ $ttl -ge 0 && $ttl -le 64 ]]; then
    os="Linux"
  elif [[ $ttl -ge 65 && $ttl -le 128 ]]; then
    os="Windows"
  else
    os="Not Found"
  fi
  
  echo -e "\n${YELLOW}[*]${END_COLOR}${GRAY} Operating System:${END_COLOR} ${GREEN}$os${END}\n" 
}

extract_ports() {
  if [[ ! -f all_ports ]]; then
    echo -e "${RED}[!] No existe el fichero ${GRAY}port${END_COLOR}\n"
    sigint_handler
  fi

  ports=$(cat all_ports | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')
 
  if [[ ! ${#ports[@]} ]]; then
    echo -e "\n${RED}[!] No ports open${END_COLOR}\n"
    sigint_handler
  fi

  echo -e "\n\n${YELLOW}[*]${END_COLOR} ${GRAY}Open ports:${END_COLOR} ${GREEN}$ports${END_COLOR}\n"
}

scan_ports() {
  ip="$1"
  protocol="$2"
  port_scannig_technique=''
  
  if [[ "$protocol" = 'tcp' ]]; then
    port_scanning_technique='-sS'
  elif [[ "$protocol" = 'udp' ]]; then
    port_scanning_technique="-sU"
  fi

  start_loading_animation "Starting ${protocol^^} port scan"
  sudo nmap $port_scanning_technique -p- --open --min-rate 5000 -n -Pn $ip -oG all_ports &>/dev/null
  stop_loading_animation
}

scan_service_version() {
  start_loading_animation "Starting basic recognition (Service & Version)"
  sudo nmap -sCV -p "$ports" "$ip" -oN targeted &>/dev/null
  stop_loading_animation
}

extract_vulnerability_info() {
  awk '/^[0-9]+\/tcp/ {split($0, fields, " "); port = gensub(/\/tcp/, "", "g", fields[1]); service = fields[3]; version = substr($0, index($0, fields[4])); printf "%s:%s:%s\n", port, service, version }' targeted > targeted2

  echo -e "\n\n${YELLOW}PORT${END_COLOR}${GREEN}\tSERVICE${END_COLOR}\t${BLUE}VERSION${END_COLOR}\n"
  echo -e "Operating System: $os\n\n" > scan_summary
  echo -e "PORT\tSERVICE\tVERSION\n" >> scan_summary
  
  while read line; do
    port=$(echo "$line" | awk -F':' '{print $1}')
    service=$(echo "$line" | awk -F':' '{print $2}')
    version=$(echo "$line" | awk -F':' '{print $3}')
    echo -e "$port\t$service\t$version\n" >> scan_summary
    echo -e "${YELLOW}$port${GREEN}\t$service${GRAY}\t$version${END_COLOR}"
  done < targeted2
}

remove_tmp_files() {
  rm -rf icmp_response all_ports targeted targeted2 &>/dev/null
}

main () {
  tput civis

  ip="$1"
  protocol="$2"
  get_ttl $ip
  get_os
  
  scan_ports $ip $protocol
  extract_ports 
  scan_service_version
  extract_vulnerability_info
  sigint_handler
}

usage() {
  echo -e "\n${BLUE}Usage:${END_COLOR} ${GRAY_COLOR}$0${END_COLOR}${GREEN} [options] ${END_COLOR}${RED}<ip-address>${END_COLOR}\n"
  echo -e "${GREEN}Options:${END_COLOR}"
  echo -e "    ${GRAY}-p${END_COLOR}${YELLOW} Protocol (tcp,udp,all)${END_COLOR}"
  echo -e "    ${GRAY}-h${END_COLOR}${YELLOW} Show this help${END_COLOR}"
  exit 1
}

if [[ ${#} -eq 0 ]]; then
  usage
fi

clear
print_head

protocol=''
while getopts ":hp:" opt; do
  case "${opt}" in
    p)
      if [[ "${OPTARG}" != 'tcp' && "${OPTARG}" != 'udp' && "${OPTARG}" != 'all' ]]; then
        echo -e "\n${RED}[!] Invalid value for parameter -p ${END_COLOR}\n"
        exit 1
      fi
      
      protocol="${OPTARG}"
      shift 2
      ;;   
    h|*)
      usage
      ;;
  esac
done

ip="$1"
valid_ip $ip
main $ip $protocol

