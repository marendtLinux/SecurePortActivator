#!/bin/bash
# ===============================
#  name: firewall_deamon.sh
#
#  Description: 
#
# ===============================

# uncomment next line for debugging
#set -x #tracing-option

TEST_PORTS=(80 443 3306) 

#exec >> /root/ausgabe.log 2>&1

exec >> /root/stdout.log 

nft_table_name=secure_port_guard

verbose=true
verbose_debug=true

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
function allow_port_access_for_ipaddress_in_docker () {
	
	#iterate through ports
	for port in ${TEST_PORTS[*]}
	do
		#if the ipaddress is not already granted port access
		if ! iptables -n -L DOCKER-USER  | grep "$1.*ctorigdstport $port"
		then
			#allow packets for port $2 and ip-address $1, 
			# -m conntrack --ctorigdstpo references the external port that is mapped to the docker port
			iptables -I DOCKER-USER -i $(get_external_network_interface) -m conntrack --ctorigdstpo $port -s $1 -j ACCEPT
			
			if [ "$verbose" = "true" ]; then printf "port access granted for ipaddress %s port %s\n in DOCKER-USER" $1 $port; fi
		fi
	done
}

# $1: ipaddress
function remove_port_access_for_ipaddress_in_docker() {

	#iterate through ports
	for port in ${TEST_PORTS[*]}
	do

		#extract line number of rule to remove
		line_number_rule_to_remove=$(iptables -n -L DOCKER-USER --line-numbers | grep "$1.*ctorigdstport $port" | awk  '{print $1}') 
		
		#remove the rule
		iptables -D DOCKER-USER $line_number_rule_to_remove
		
		if [ $? -eq 0 ]
		then
			printf "port access removed for ipaddress %s port %s in DOCKER-USER\n" $1 $port
		else
			printf "Error in removing Docker port access for %s %s \n" $1 $port
		fi
	
	done
}


# $1: regex
#WARNING: using a regex that is not used exlusively by a rule 
#(meaning iptables -n -L DOCKER-USER --line-numbers prints out a line containing the regex and is not a rule) will result in a infinite loop
#because it cant be removed
function remove_all_rules_in_docker_by_regex() {

	if [ "$verbose_debug" = "true" ]; then printf "function remove_all_rules_in_docker_by_regex() called, regex is: $1\n" ; fi

	#loop as long, as there are Rules in the DOCKER-USER table, that contain the regex $1
	while iptables -n -L DOCKER-USER --line-numbers | grep "$1" &> /dev/null
	do
		#iterate over all rules in DOCKER-USER
		iptables -n -L DOCKER-USER --line-numbers | while read line 
	    	do
	    		#if a rule contain the regex $1
			if echo $line | grep "$1" &> /dev/null
			then
				#extract line number of rule to remove
				line_number_rule_to_remove=$(echo $line | awk  '{print $1}') 
			
				#remove the rule
				iptables -D DOCKER-USER $line_number_rule_to_remove
				
				if [ "$verbose" = "true" ]; then printf "removed rule in table DOCKER-USER:\n $line\n" ; fi
				
				#the loop must end here, because the handle numbers can change after removing a rule
				break
			fi
	
		done
	done
}


# $1: Port
function insert_drop_all_packets_rule_for_port_in_docker () {
	
	iptables -A DOCKER-USER -i $(get_external_network_interface) -m conntrack --ctorigdstpo $1 -j DROP
}



# function allow_ipaddress_port_access
# $1: ipaddress
function allow_port_access_for_ipaddress () { 

	check_if_docker_is_installed
	
	#if docker is installed
	if [ $? -eq 0 ]
	then
		allow_port_access_for_ipaddress_in_docker $1
	fi
	
	#iterate through ports
	for port in ${TEST_PORTS[*]}
	do
					
		#if the ipaddress is not already granted port access
		if ! nft -a list table inet $nft_table_name | grep "tcp dport $port ip saddr $1 accept"
		then
			#allow port access for ipaddress $1, place the rule at the top with insert
			nft insert rule inet $nft_table_name INPUT tcp dport $port ip saddr { $1 } accept
			
			printf "port access granted for ipaddress %s port %s\n" $1 $port
		fi
	done
	
}


# function remove_port_access_for_ipaddress
# $1: ipaddress
function remove_port_access_for_ipaddress () { 

	check_if_docker_is_installed
	
	#if docker is installed
	if [ $? -eq 0 ]
	then
		remove_port_access_for_ipaddress_in_docker $1
	fi

	#iterate through ports
	for port in ${TEST_PORTS[*]}
	do
		#get the handle number in the nft firewall for the rule, that allows port access for the specified ipaddress
		handle_number_port_access=$(nft -a list table inet $nft_table_name | grep "tcp dport $port ip saddr $1 accept" | awk 'NR==1 {print $10}')

		#delete rule with the handle
		nft delete rule inet $nft_table_name INPUT handle $handle_number_port_access
		
		printf "port access removed for ipaddress %s port %s\n" $1 $port
	
	done
}


# $1: regex
#WARNING: using a regex that is not used exlusively by a rule 
#(meaning nft -a list table inet $nft_table_name prints out a line containing the regex and is not a rule) will result in a infinite loop
#because it cant be removed
function remove_all_rules_by_regex() {

	if [ "$verbose_debug" = "true" ]; then printf "function remove_all_rules_by_regex called, regex is: $1\n" ; fi

	#loop as long, as there are Rules in the nft-table, that contains the regex $1
	while nft -a list table inet $nft_table_name  | grep "$1" &> /dev/null
	do
		#iterate over all rules
		nft -a list table inet $nft_table_name | while read line 
	    	do
	    		#if a rule contains the regex $1
			if echo $line | grep "$1" &> /dev/null
			then
				
				#get the handle number in the nft firewall for the rule containing the regex
				handle_number=$(echo $line | grep -o 'handle [0-9]\+' | awk '{print $2}')

				#delete rule with the handle
				nft delete rule inet $nft_table_name INPUT handle $handle_number
				
				if [ "$verbose" = "true" ]; then printf "removed rule in table $nft_table_name:\n $line\n" ; fi
				
				#the loop must end here, because the handle numbers can change after removing a rule
				break
			fi
	
		done
	done
}



# $1: Port
function insert_drop_all_packets_rule_for_port () {

	#block all other for port
	nft add rule inet $nft_table_name INPUT tcp dport $1 drop

}

function inital_setup_nft_firewall_table () {

	nft add table inet $nft_table_name

	nft add chain inet $nft_table_name INPUT { type filter hook input priority 0 \; policy accept \; }
}


function delete_nft_firewall_table () {

	#MAKE SURE CHAIN IS EMPTY!

	nft delete chain inet $nft_table_name INPUT
	nft delete table inet $nft_table_name
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
		if [ "$verbose" = "true" ]; then printf "PAM detected a opened session for $(hostname -I)\n" ; fi
	       
		#iterate through ipaddresses of logged in users
		w | awk 'NR > 2 {print $2}'  | while read ipaddress
		do
			allow_port_access_for_ipaddress $ipaddress
									
			#we can leave the loop here, because each new connection calls this function. hence only one new ipaddress at a time
			#break
		done
	    
	#elif [ "$TEST_TYPE" = "close_session" ]; then
	
		
	#if a session was closed, remove all ipaddress from port access that are not logged in
	elif [ "$PAM_TYPE" = "close_session" ]; then
	
	    	if [ "$verbose" = "true" ]; then printf "PAM detected a closed session\n" ; fi
	    
	    	#if nobody is logged in the system, flush all accept rules
	    	#this is a fallback mechanism/defensive programming, to avoid rules staying in the tables through some kind of error or interrupted script execution
	    	if ! who | grep -q . 
	    	then
	    		if [ "$verbose_debug" = "true" ]; then printf "No users are logged in the system, call both remove_all_rules - functions" ; fi
	    		
	    		remove_all_rules_by_regex "accept # handle"
	    		remove_all_rules_in_docker_by_regex "ACCEPT"
	    	#if there are user logged in
	    	else
	    	
		    	#iterate through the ip addresses in the firewall, that have port access, hence all logged in ip adresses of the last script call
		    	nft -a list table inet $nft_table_name | while read line
		    	do
		    		#if the specific line of the firewall config handles an ipaddress
		    		if echo $line | grep "saddr" 
		    		then
		    			#extract only the ip address
		    			ipaddress_in_firewall=$(echo $line | awk '{print $6}')
		    			
		    			local ipaddress_in_firewall_belongs_to_logged_in_user=false
		    			
		    			#read in ip addresses of all logged in users
		    			readarray -t ipaddresses_of_logged_in_user < <(who | awk '{print $5}' | tr -d '()')
		    		
		    			#iterate through ip addresses of all logged in users
					for ip_address_user in ${ipaddresses_of_logged_in_user[*]}
					do
						#if the ip address in the firewall belongs to a logged in user
						if [ "$ip_address_user" = "$ipaddress_in_firewall" ]
						then    	
							ipaddress_in_firewall_belongs_to_logged_in_user=true  
							break
		   				fi
					done 
		    			
		    			#if the ip-address in the firewall belongs not to a currently logged in user
		    			if [ "$ipaddress_in_firewall_belongs_to_logged_in_user" = "false" ]
					then
						remove_port_access_for_ipaddress $ipaddress_in_firewall
						
					fi
		    			
		    		fi
		    	done
	    	
	    	fi
	fi

} 



main

