#!/bin/bash

# Paths and file names of the hosts list and the result.
hosts_list='dnsblock_hosts_'$(date '+%Y%m%d')'.txt' # One FQDN per line in file.
result='dnsblock_result_'$(date '+%Y%m%d')'.csv' # CSV result file.

#
# Download the most recent hosts lists and combine to one file.
# 
sample_size=400 #numeros dominios de amostras
echo -e "### Downloading hosts lists."

# List 1. Source: Abuse.ch URLhaus. URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.
wget --quiet -O "dnsblock_test_list_1.txt" "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"

# List 2. Source: cert.pl. List of malicious domains.
wget --quiet -O "dnsblock_test_list_2.txt" "https://hole.cert.pl/domains/domains.txt"

cat dnsblock_test_list_1.txt dnsblock_test_list_2.txt > dnsblock_test_list_concat.txt
sed -i '/^[[:blank:]]*#/d;s/#.*//' dnsblock_test_list_concat.txt # Remove comments.
sed -i 's/^0.0.0.0 //; /^#.*$/d; /^ *$/d; s/\t*//g' "dnsblock_test_list_concat.txt" # Remove '0' IPs; comments, empty space lines, and tabs.
# Gere a lista de amostragem
sort dnsblock_test_list_concat.txt | uniq > $hosts_list # Create a list with unique hosts.
# Gere a lista de amostragem
shuf -n "$sample_size" "$hosts_list" > sampled_hosts_list.txt
# Atualize a variável para usar a nova lista de amostragem
hosts_list="sampled_hosts_list.txt"

echo "### Lista de amostragem gerada com $sample_size domínios."

totalhosts=$(wc -l < $hosts_list)
timeexpected=`echo "$totalhosts" / 1.6 / 3600 | bc -l | awk '{printf("%.0f \n",$1)}'`
echo -e "### Hosts to test: $totalhosts"

#
# Define IP address of the nameserver used for lookups.
#

ns0_sp='Cloudflare unfiltered'
ns0_ip='1.1.1.1'

ns1_sp='NextDns'
ns1_ip='10.11.7.11'

ns2_sp='ControlD Malware'
ns2_ip='76.76.10.2'

ns3_sp='OpenDns FamilyShield'
ns3_ip='208.67.222.123'

ns4_sp='Quad9'
ns4_ip='9.9.9.9'

ns5_sp='Adguard Family'
ns5_ip='94.140.14.15'

ns6_sp='Cloudflare for Families'
ns6_ip='1.1.1.3'

ns7_sp='dns0.eu'
ns7_ip='193.110.81.0'

ns8_sp='AdguardHome'
ns8_ip='10.11.11.11'

ns9_sp='CleanBrowsing Security Filter'
ns9_ip='185.228.169.9'

ns10_sp='Mx9 Grafana'
ns10_ip='10.11.13.11'

echo -e ", $ns0_sp - $ns0_ip,$ns1_sp - $ns1_ip,$ns2_sp - $ns2_ip,$ns3_sp - $ns3_ip,$ns4_sp - $ns4_ip,$ns5_sp - $ns5_ip,$ns6_sp - $ns6_ip,$ns7_sp - $ns7_ip,$ns8_sp - $ns8_ip,$ns9_sp - $ns9_ip,$ns10_sp - $ns10_ip" > "$result";

#
# Take the average ping to the nameservers.
#

echo "### Checking average ping to nameservers."

ip0=`ping -c 10 -q $ns0_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip1=`ping -c 10 -q $ns1_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip2=`ping -c 10 -q $ns2_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip3=`ping -c 10 -q $ns3_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip4=`ping -c 10 -q $ns4_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip5=`ping -c 10 -q $ns5_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip6=`ping -c 10 -q $ns6_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip7=`ping -c 10 -q $ns7_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip8=`ping -c 10 -q $ns8_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip9=`ping -c 10 -q $ns9_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`
ip10=`ping -c 10 -q $ns10_ip | grep ^rtt | cut -d ' ' -f 4 | cut -d '/' -f 1`

echo -en "PING (ms),$ip0,$ip1,$ip2,$ip3,$ip4,$ip5,$ip6,$ip7,$ip8,$ip9,$ip10\n" >> "$result";

#
# Test a list of safe hosts to ensure that the nameservers are responding well.
#

echo "### Testing safe hosts to ensure nameservers are responding."

safe_hosts=( nexxwave.be nasa.gov google.com cloudflare.com microsoft.com ) # Declare a list with some known safe domains. Separated with a space.
for domain in "${safe_hosts[@]}"
do
  ip0=`dig @$ns0_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip1=`dig @$ns1_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip2=`dig @$ns2_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip3=`dig @$ns3_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip4=`dig @$ns4_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip5=`dig @$ns5_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip6=`dig @$ns6_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip7=`dig @$ns7_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip8=`dig @$ns8_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip9=`dig @$ns9_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
  ip10=`dig @$ns10_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`

  echo -e "Testing $domain";
  echo -en "$domain (safe domain),$ip0,$ip1,$ip2,$ip3,$ip4,$ip5,$ip6,$ip7,$ip8,$ip9,$ip10\n" >> "$result";
done

#
# Do the test.
#

echo "### Start test of hosts at $(date). This will take ~$timeexpected hours."

echo -e "\n" >> "$result";
echo -e "Domain name, $ns0_sp - $ns0_ip,$ns1_sp - $ns1_ip,$ns2_sp - $ns2_ip,$ns3_sp - $ns3_ip,$ns4_sp - $ns4_ip,$ns5_sp - $ns5_ip,$ns6_sp - $ns6_ip,$ns7_sp - $ns7_ip,$ns8_sp - $ns8_ip,$ns9_sp - $ns9_ip,$ns10_sp - $ns10_ip" >> "$result";

while IFS= read -r domain
do
  if [ "$domain" != "" ]; then # Ensure the line is not empty.
    ip0=`dig @$ns0_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`; # IP address lookup with unfiltered DNS with a longer timeout.
    if [ -n "$ip0" ] && [ "$ip0" != "0.0.0.0" ] && [ "$ip0" != "127.0.0.1" ]; then # Only run additional lookups if the domain is returning a valid IP address.

      ip1=`dig @$ns1_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip2=`dig @$ns2_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip3=`dig @$ns3_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip4=`dig @$ns4_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip5=`dig @$ns5_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip6=`dig @$ns6_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip7=`dig @$ns7_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip8=`dig @$ns8_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip9=`dig @$ns9_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`
      ip10=`dig @$ns10_ip +noadflag +noedns +short $domain | grep '^[.0-9]*$' | tail -n1`

      # Blank out any localhost or 0'ed IP addresses.
      if [ "$ip1" = "127.0.0.1" ] || [ "$ip1" = "0.0.0.0" ]; then
        ip1=""
      fi
      if [ "$ip2" = "127.0.0.1" ] || [ "$ip2" = "0.0.0.0" ]; then
        ip2=""
      fi
      if [ "$ip3" = "127.0.0.1" ] || [ "$ip3" = "0.0.0.0" ]; then
        ip3=""
      fi
      if [ "$ip4" = "127.0.0.1" ] || [ "$ip4" = "0.0.0.0" ]; then
        ip4=""
      fi
      if [ "$ip5" = "127.0.0.1" ] || [ "$ip5" = "0.0.0.0" ]; then
        ip5=""
      fi
      if [ "$ip6" = "127.0.0.1" ] || [ "$ip6" = "0.0.0.0" ]; then
        ip6=""
      fi
      if [ "$ip7" = "127.0.0.1" ] || [ "$ip7" = "0.0.0.0" ]; then
        ip7=""
      fi
      if [ "$ip8" = "127.0.0.1" ] || [ "$ip8" = "0.0.0.0" ]; then
        ip8=""
      fi
      if [ "$ip9" = "127.0.0.1" ] || [ "$ip9" = "0.0.0.0" ]; then
        ip9=""
      fi
      if [ "$ip10" = "127.0.0.1" ] || [ "$ip10" = "0.0.0.0" ]; then
        ip10=""
      fi

      echo -e "Testing $domain";
      echo -en "$domain,$ip0,$ip1,$ip2,$ip3,$ip4,$ip5,$ip6,$ip7,$ip8,$ip9,$ip10\n" >> "$result";

    fi

    sleep 0.1 # Don't hammer the public resolver.

  fi
done < "$hosts_list"

echo "### End test of hosts at $(date)"
