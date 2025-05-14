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


function check_if_docker_is_installed () {

	if nft list ruleset | grep DOCKER-USER
	then
		printf "Docker is installed!\n"
		return 0
	else
		"Docker is not installed!\n"
		return 1
	fi
}

# $1: ipaddress
# $2: Port
function allow_port_access_for_ipaddress_in_docker () {
	
	#if the ipaddress is not already granted port access
	if ! iptables -n -L DOCKER-USER  | grep $2 | grep $1
	then
		#allow packets for port $2 and ip-address $1, 
		# -m conntrack --ctorigdstpo references the external port that is mapped to the docker port
		iptables -I DOCKER-USER -i $(get_external_network_interface) -m conntrack --ctorigdstpo $2 -s $1 -j ACCEPT
		
		printf "port access granted for ipaddress %s port %s\n in DOCKER-USER" $1 $2
	fi
}

# $1: ipaddress
# $2: Port
function remove_port_access_for_ipaddress_in_docker() {

	#extract line number of rule to remove
	line_number_rule_to_remove=$(iptables -L DOCKER-USER --line-numbers | grep $1 | grep $2 | awk  '{print $1}') 
	
	#remove the rule
	iptables -D DOCKER-USER $line_number_rule_to_remove
	
	if [ $? -eq 0 ]
	then
		printf "port access removed for ipaddress %s port %s in DOCKER-USER\n" $1 $2
	else
		printf "Error in removing Docker port access for %s %s \n" $1 $2
	fi
}


# $1: Port
function insert_drop_all_packets_rule_for_port_in_docker () {
	
	iptables -A DOCKER-USER -i $(get_external_network_interface) -m conntrack --ctorigdstpo $1 -j DROP
}



# function allow_ipaddress_port_access
# $1: ipaddress
# $2: Port
function allow_port_access_for_ipaddress () { 

	check_if_docker_is_installed
	
	#if docker is installed
	if [ $? -eq 0 ]
	then
		allow_port_access_for_ipaddress_in_docker $1 $2
	fi
	
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
function remove_port_access_for_ipaddress () { 

	check_if_docker_is_installed
	
	#if docker is installed
	if [ $? -eq 0 ]
	then
		remove_port_access_for_ipaddress_in_docker $1 $2
	fi

	#get the handle number in the nft firewall for the rule, that allows port access for the specified ipaddress
	handle_number_port_access=$(nft -a list table inet secure_port_guard | grep "tcp dport $2 ip saddr $1 accept" | awk 'NR==1 {print $10}')

	#delete rule with handle six
	nft delete rule inet secure_port_guard INPUT handle $handle_number_port_access
	
	printf "port access removed for ipaddress %s port %s\n" $1 $2
}


# $1: Port
function insert_drop_all_packets_rule_for_port () {

	#block all other for port
	nft add rule inet secure_port_guard INPUT tcp dport $1 drop

}

function inital_setup_nft_firewall_table () {

	nft add table inet secure_port_guard

	nft add chain inet secure_port_guard INPUT { type filter hook input priority 0 \; policy accept \; }
}


function delete_nft_firewall_table () {

	#MAKE SURE CHAIN IS EMPTY!

	nft delete chain inet secure_port_guard INPUT
	nft delete table inet secure_port_guard
}





function get_external_network_interface() {
	echo $(ip route get 8.8.8.8 | awk '{print $5}')
}


function main () {

	#local TEST_TYPE=open_session
	local TEST_TYPE=close_session

	#if a session was open, grant access to port for all ip address of logged in users
	if [ "$PAM_TYPE" = "open_session" ]
	#if [ "$TEST_TYPE" = "open_session" ]
	then
	    	echo "Open Session $(hostname -I)"
	       
		#iterate through ipaddresses of logged in users
		w | awk 'NR > 2 {print $2}'  | while read ipaddress
		do
			allow_port_access_for_ipaddress $ipaddress $TESTPORT
									
			#we can leave the loop here, because each new connection calls this function. hence only one new ipaddress at a time
			#break
		done
	    
	#elif [ "$TEST_TYPE" = "close_session" ]; then
	
	#if a session was closed, remove all ipaddress from port access that are not logged in
	elif [ "$PAM_TYPE" = "close_session" ]; then
	    #echo "Closed Session $(hostname -I)"
	    
	    	
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



main
