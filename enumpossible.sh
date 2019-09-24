#!/bin/bash
# This script does two things:
# 1. Checks a list of SSH servers for password-based auth capability
# 2. Checks those servers identified for the SSH user enumeration vulnerability (CVE-2018-15473)
# Takes a list of SSH servers in ip:port format.
# Author: Fabrizio Siciliano (@0rbz_)

cat << "EOF"
         _________________________.
        / _____________________  /|
       / / ___________________/ / |
      / / /| |               / /  |
     / / / | |              / / . |
    / / /| | |             / / /| |
   / / / | | |            / / / | |
  / / /  | | |           / / /| | |
 / /_/___| | |__________/ / / | | |
/________| | |___________/ /  | | |
| _______| | |__________ | |  | | |
| | |    | | |_________| | |__| | |
| | |    | |___________| | |____| |
| | |   / / ___________| | |_  / /
| | |  / / /           | | |/ / /
| | | / / /            | | | / /
| | |/ / /             | | |/ /
| | | / /              | | ' /
| | |/_/enumpossible v0.1|  /
| |_______(@0rbz_)_____| | /
|________________________|/
EOF

# colors and formatting
g=`tput setaf 2`  # green
w=`tput setaf 7`  # white
ul=`tput smul`    # underline
b=`tput bold`     # bold
e=`tput sgr0`     # end
ba=`tput setab 1` # red background

if [[ $1 == "" ]]; then
	echo "Usage: $0 servers.txt"
	exit
fi

ssh_services="$1"
OUTPUT_DIR="output"

if [[ -d $OUTPUT_DIR ]]; then
	read -p "${b}${w}${ba}[?] $OUTPUT_DIR directory already exists. Delete it? [y/n]:${e} " answer
	if [[ $answer = y ]]; then
		rm -r $OUTPUT_DIR
	fi
fi

mkdir $OUTPUT_DIR 2>/dev/null

user () {
	u=qtcxijzb
	for l in {1..8} ; do
		echo -n "${u:RANDOM%${#u}:1}"
	done
}
rand_user=$(user)

line () {
	printf '+%.0s' {1..68}
	echo
}

auth_response () {
	echo "Authentications that can continue: publickey,keyboard-interactive,password|Authentications that can continue: publickey,gssapi-with-mic,password,keyboard-interactive|Authentications that can continue: password|Authentications that can continue: publickey,password|Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password|Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,keyboard-interactive|Authentications that can continue: gssapi-keyex,gssapi-with-mic,publickey,keyboard-interactive"
}

line
echo -e "[+] Checking for password-based auth..."
for server in $(cat $ssh_services); do
	ip=$(echo $server | cut -f1 -d":")
	port=$(echo $server | cut -f2 -d":")
	ssh -v -o "BatchMode yes" -o "StrictHostKeyChecking no" -o ConnectTimeout=5 $rand_user@$ip -p $port 2> $OUTPUT_DIR/$ip:$port.PASSWORD_AUTH_DEBUG.txt
	password_auth_true=$(grep -E "$(auth_response)" $OUTPUT_DIR/$ip:$port.PASSWORD_AUTH_DEBUG.txt)
	if [[ $password_auth_true ]]; then
		grep -E "$(auth_response)" $OUTPUT_DIR/$ip:$port.PASSWORD_AUTH_DEBUG.txt > $OUTPUT_DIR/$ip:$port.PASSWORD_AUTH_TRUE.txt
	fi
done

# comment out the next line to keep debug files
rm $OUTPUT_DIR/*DEBUG*

if [[ $(ls $OUTPUT_DIR/*TRUE* 2>/dev/null) ]]; then
	num_servers=$(ls $OUTPUT_DIR/*TRUE* | wc -l)
	echo "${g}[+] $(echo $num_servers) SERVERS ACCEPT PASSWORD-BASED AUTHENTICATION.${e}"
	find $OUTPUT_DIR/*TRUE* -exec basename {} \; | cut -f1,2,3,4 -d"." >> $OUTPUT_DIR/PASSWORD_BASED_AUTH_HOSTS.txt
	echo "[+] Results written to $OUTPUT_DIR/PASSWORD_BASED_AUTH_HOSTS.txt"
	line
	# comment out the next line to keep separate results files
	rm $OUTPUT_DIR/*TRUE* 2>/dev/null
else
	echo -e "NO SERVERS FOUND THAT ACCEPT PASSWORD-BASED AUTHENTICATION."
	exit
fi

if [[ -e $OUTPUT_DIR/PASSWORD_BASED_AUTH_HOSTS.txt ]]; then
	echo -e "[+] Checking for user enumeration vulnerability (CVE-2018-15473)..."
	for server in $(cat $OUTPUT_DIR/PASSWORD_BASED_AUTH_HOSTS.txt); do
		ip=$(echo $server | cut -f1 -d":")
		port=$(echo $server | cut -f2 -d":")
		./ssh_enum -p $port $ip root > $OUTPUT_DIR/$ip:$port.SSH_ENUM.txt
		./ssh_enum -p $port $ip $rand_user >> $OUTPUT_DIR/$ip:$port.SSH_ENUM.txt
		rootisvalid=$(grep "root is a valid username" $OUTPUT_DIR/$ip:$port.SSH_ENUM.txt)
		randomisinvalid=$(grep "$rand_user is an invalid username" $OUTPUT_DIR/$ip:$port.SSH_ENUM.txt)
		if [[ $rootisvalid ]] && [[ $randomisinvalid ]]; then
			echo "${g}[+] SSH USER ENUMERATION POSSIBLE WITH${e} $ip:$port." | tee $OUTPUT_DIR/$ip:$port.SSH_ENUM_POSSIBLE.txt
		fi
	done
fi
possibles=$(ls $OUTPUT_DIR/*SSH_ENUM_POSSIBLE.txt 2> /dev/null)
if [[ $possibles ]]; then
	find $OUTPUT_DIR/*SSH_ENUM_POSSIBLE.txt -exec basename {} \; | cut -f1,2,3,4 -d"." >> $OUTPUT_DIR/ENUM_POSSIBLE_HOSTS.txt
	rm $OUTPUT_DIR/*SSH_ENUM_POSSIBLE.txt 2>/dev/null
	echo "[+] Results written to $OUTPUT_DIR/ENUM_POSSIBLE_HOSTS.txt"
else
	echo "NO SERVERS FOUND VULNERABLE TO USER ENUMERATION."
	line
fi
