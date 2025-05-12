#!/bin/bash
# ===============================
#  name: firewall_deamon.sh
#
#  Description: 
#
# ===============================

# uncomment next line for debugging
#set -x #tracing-option


TESTPORT=80

#array, that stores all unique ip-addresses of logged in users
#if a user is logged in several times with the same ipaddress, the ip-address is stored only once
logged_in_unique_ip_addresses=()


function add_ipaddress_to_array_of_logged_in_unique_ip_addresses () { #tested

	local ipaddress_already_exists=FALSE
	#echo $1

	#check, if ipaddress is already in array
	for ipaddress in ${logged_in_unique_ip_addresses[*]}
	do
	    if [ "$ipaddress" = "$1" ] ; then    	
		ipaddress_already_exists=TRUE  
		break
	    fi
	done

	#if ipaddress is not in array, store it there
	if [ "$ipaddress_already_exists" = "FALSE" ]
	then
		#add ipaddress to array
		logged_in_unique_ip_addresses[${#logged_in_unique_ip_addresses[@]}]="$1"
		return 0
	else 
		return 1
	fi
}




# function allow_ipaddress_port_access
# $1: ipaddress
# $2: Port
function allow_port_access_for_ipaddress () { #tested

	#if the ipaddress is not already granted port access
	if ! nft -a list table inet secure_port_guard | grep "tcp dport $2 ip saddr $1 accept"
	then
		#get the handle number in the nft firewall for the rule, that drops all packets for the specified port $2
		handle_number_for_drop_all_rule=$(nft -a list table inet secure_port_guard | grep "tcp dport $2 drop" | awk '{print $7}')

		#allow port access for port $2, for ipaddress $1, place the rule before drop all rule 
		nft insert rule inet secure_port_guard INPUT position $handle_number_for_drop_all_rule tcp dport $2 ip saddr { $1 } accept
		
		
		printf "port access granted for ipaddress %s port %s\n" $1 $2
	fi
}


# function remove_port_access_for_ipaddress
# $1: ipaddress
# $2: Port
function remove_port_access_for_ipaddress () { #tested

	#get the handle number in the nft firewall for the rule, that allows port access for the specified ipaddress
	handle_number_port_access=$(nft -a list table inet secure_port_guard | grep "tcp dport $2 ip saddr $1 accept" | awk 'NR==1 {print $10}')

	#delete rule with handle six
	nft delete rule inet secure_port_guard INPUT handle $handle_number_port_access
	
	printf "port access removed for ipaddress %s port %s\n" $1 $2
}



function main () {

	local TEST_TYPE=close_session

	#if [ "$PAM_TYPE" = "open_session" ]
	if [ "$TEST_TYPE" = "open_session" ]
	then
	    	echo "Open Session $(hostname -I)"
	       
		#iterate through ipaddresses of logged in users
		w | awk 'NR > 2 {print $2}'  | while read ipaddress
		do
			allow_port_access_for_ipaddress $ipaddress $TESTPORT
				
			#we can leave the loop here, because each new connection calls this function. hence only one new ipaddress at a time
			break
		done
	    
	elif [ "$TEST_TYPE" = "close_session" ]; then
	#elif [ "$PAM_TYPE" = "close_session" ]; then
	    #echo "Closed Session $(hostname -I)"
	    
	    	#iterate through the ip addresses of the logged in users and add them to an array
	    	who | awk '{print $5}' | tr -d '()' | while read ipaddress
		do
	    		add_ipaddress_to_array_of_logged_in_unique_ip_addresses $ipaddress
	    		printf "logged in user with ipaddress: %s\n" $ipaddress
	    	done
	    	
	    	#iterate through the ip addresses in the firewall, that have port access, hence all logged in ip adresses of the last script call
	    	nft -a list table inet secure_port_guard | while read line
	    	do
	    		#if the specific line of the firewall config handles an ipaddress
	    		if echo $line | grep "saddr" 
	    		then
	    			#extract only the ip address
	    			ipaddress_in_firewall=$(echo $line | awk '{print $6}')
	    			
	    			local ipaddress_in_firewall_belongs_to_logged_in_user=FALSE
	    			
	    			#read in ip addresses of all logged in users
	    			readarray -t ipaddresses_of_logged_in_user < <(who | awk '{print $5}' | tr -d '()')
	    		
	    			#iterate through ip addresses of all logged in users
				for ip_address_user in ${ipaddresses_of_logged_in_user[*]}
				do
					#if the ip address in the firewall belongs to a logged in user
					if [ "$ip_address_user" = "$ipaddress_in_firewall" ]
					then    	
						ipaddress_in_firewall_belongs_to_logged_in_user=TRUE  
						break
	   				fi
				done 
	    			
	    			#if the ip-address in the firewall belongs not to a currently logged in user
	    			if [ "$ipaddress_in_firewall_belongs_to_logged_in_user" = "FALSE" ]
				then
					remove_port_access_for_ipaddress $ipaddress_in_firewall $TESTPORT
				fi
	    			
	    		fi
	    	done
	fi

} 


function port_process_is_docker () {

	#teste, ob ein docker-container auf dem port lauscht
	if ss -tap | grep $TESTPORT | grep docker
	then
		configure_firewall_for_docker_container
	else
		configure_firewall
	fi

}

#extrahiere den process, der auf dem port lauscht
#process=ss -tap | grep $TESTPORT | awk '{print $6}' | sed -n 's/.*"\([^"]*\)".*/\1/p'

function configure_firewall_with_nft () {
	return 0
}

function setup_nftables () {

#block all other for port
nft add rule inet secure_port_guard INPUT tcp dport $TESTPORT drop

}



#file that holds the ip_addresses of the previous iteration of this script, hence the logged in user at that time
IP_ADDRESSES_PAST_CYCLE_STORAGE_FILE="logged_in_users.txt"

#array_that holds the ip_addresses of the previous iteration of this script, hence the logged in user at that time
ip_addresses_past_cycle=()

#this function reads in the ip-addresses of the past cycle of this script from a text-file, 
#hence the logged in user at that time
function read_in_ip_addresses_past_cycle () {

	if [ ! -e $IP_ADDRESSES_PAST_CYCLE_STORAGE_FILE ]
	then
		touch $IP_ADDRESSES_PAST_CYCLE_STORAGE_FILE
	fi
	
	
	mapfile -n 0 ZEILEN< "$IP_ADDRESSES_PAST_CYCLE_STORAGE_FILE"
	local array_length=$(echo ${#ZEILEN[*]})
	
	
	for (( i=0 ; i<$array_length; i++))
	do
		ip_addresses_past_cycle+=(${#ZEILEN[$i]})
	done
}



main
