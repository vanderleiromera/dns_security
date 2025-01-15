#!/bin/bash
#Copyright (c) 2023 Divested Computing Group
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Define the number of threads
THREADS=8

function resolveHost() {
    local resolver="$1"
    local domain="$2"
    local response

    # Obter resposta do comando dig
    response=$(/usr/bin/dig +timeout=2 "$resolver" +short A "$domain")

    # Verificar resposta vazia
    if [ -z "$response" ]; then
        echo "Error: Empty response for $domain" >> "results/$resultTime/errors.log"
        return 1
    fi

    # Verificar se é uma resposta bloqueada (0.0.0.0)
    if [[ "$response" == "0.0.0.0" ]]; then
        echo "Error: Blocked domain (0.0.0.0) for $domain" >> "results/$resultTime/errors.log"
        return 1
    fi
    
        # Verificar se é uma resposta Adguard Ip (94.140.14.33)
    if [[ "$response" == "94.140.14.33" ]]; then
        echo "Error: Blocked domain (94.140.14.33) for $domain" >> "results/$resultTime/errors.log"
        return 1
    fi

    # Verificar se a resposta contém um endereço IP válido
    if echo "$response" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        return 0
    else
        echo "Error: Unexpected response for $domain: $response" >> "results/$resultTime/errors.log"
        return 1
    fi
}

export -f resolveHost;

function testResolver(){
	local resolver="$1";
	local domainList="$2";
	local prettyname="$3";
	local name="$resolver";
	if [ -n "$prettyname" ]; then name="$prettyname"; fi;
	local countPositive=0;
	local countNegative=0;
	
    	# Create a named pipe (FIFO) for the thread pool
    	PIPE="/tmp/thread_pool.$$"
    	mkfifo "$PIPE"
    	exec 200<>"$PIPE"
    	rm -f "$PIPE"

    	# Initialize the thread pool
    	for ((i = 0; i < THREADS; i++)); do
            echo "Thread $i ready" >&200
    	done	
	# Process each domain
	while read line; do
		if [ -f "0ABORT0" ]; then break; fi;
		
		# Wait for an available thread
        	read -u 200
        	
		if resolveHost "$resolver" "$line"; then
			countPositive=$((countPositive+1));
		else
			countNegative=$((countNegative+1));
		fi;
	
            	# Release the thread back to the pool
            	echo "Thread released" >&200	
		
	done < "$domainList";
   	 # Wait for all background processes to complete
   	 wait

    	# Close the FD
    	exec 200>&-	
	
	echo -e "Results for $name against $domainList:\n\tResolved: $countPositive\n\tUnresolved: $countNegative" | tee -a "results/$resultTime/$name.txt";
}
export -f testResolver;

function runAllLists(){
	local resolver="$1";
	local prettyname="$2";
	#export resultTime=$(date +%s);
	#mkdir -p "results/$resultTime";
	testResolver "$resolver" "domains-good.txt" "$prettyname";
	testResolver "$resolver" "domains-bad-abusech-shuf.txt" "$prettyname";
	testResolver "$resolver" "domains-bad-certpl-shuf.txt" "$prettyname";
	testResolver "$resolver" "domains-bad-disconnect_ads-shuf.txt" "$prettyname";
}
export -f runAllLists;

function runAllTests(){
        #amostras
	shuffleBad 100;
	export resultTime=$(date +%s);
	mkdir -p "results/$resultTime";

	runAllLists "@208.67.222.123" "OpenDns [FamilyShield]";

	#runAllLists "@1.1.1.1" "Cloudflare";
	runAllLists "@1.1.1.3" "Cloudflare (Adult)";

	runAllLists "@10.11.11.11" "AdguardHome (local)";
	runAllLists "@9.9.9.9" "Quad9 (Security)";

	runAllLists "@193.110.81.0" "DNS0";
	#runAllLists "@193.110.81.9" "DNS0 (ZERO)";

	runAllLists "@10.11.7.11" "Nextdns (local)";
	runAllLists "@10.11.13.11" "Techdns (local)";

	runAllLists "@94.140.14.15" "Adguard Family";

	#runAllLists "@76.76.10.1" "ControlD (malware)";
	runAllLists "@76.76.10.2" "ControlD (ads-trackers-malware)";

	runAllLists "@185.228.168.168" "CleanBrowse (Security)";
	#runAllLists "@156.154.70.2" "Neustar";

	#runAllLists "@77.88.8.8" "Yandex";
	#runAllLists "@77.88.8.88" "Yandex (Safe)";

	#echo "Started all tests in background";
	collateResults;
}
export -f runAllTests;

function collateResults(){
	if [ -n "$resultTime" ]; then
		echo "last updated: $(date -uI -d @$resultTime)" > results/$resultTime.txt;
		cat results/$resultTime/*.txt >> results/$resultTime.txt;
	else
		echo "results unavailable";
	fi;
}
export -f collateResults;

function haltTests(){
	touch 0ABORT0;
	echo "Remember to remove the abort file before running again";
}
export -f haltTests;

function shuffleBad(){
    # Verifica se o domínio responde no DNS do Cloudflare com timeout
    check_domain() {
        domain="$1"
        if timeout 3 dig +short @"1.1.1.1" "$domain" A | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || \
           timeout 3 dig +short @"1.1.1.1" "$domain" AAAA | grep -qE '^[0-9a-fA-F:]+$'; then
            echo "$domain"
        fi
    }

    echo "🔍 Filtrando até $1 domínios aleatórios de domains-bad-abusech.txt..."
    > "domains-bad-abusech-shuf.txt"
    # Embaralha e filtra até o número de domínios especificado
    shuf "domains-bad-abusech.txt" | head -n "$1" | while IFS= read -r domain; do
        check_domain "$domain" >> "domains-bad-abusech-shuf.txt"
    done

    echo "🔍 Filtrando até $1 domínios aleatórios de domains-bad-certpl.txt..."
    > "domains-bad-certpl-shuf.txt"
    # Embaralha e filtra até o número de domínios especificado
    shuf "domains-bad-certpl.txt" | head -n "$1" | while IFS= read -r domain; do
        check_domain "$domain" >> "domains-bad-certpl-shuf.txt"
    done
    
    echo "🔍 Filtrando até $1 domínios aleatórios de domains-bad-disconnect_ads.txt..."
    > "domains-bad-disconnect_ads-shuf.txt"
    # Embaralha e filtra até o número de domínios especificado
    shuf "domains-bad-disconnect_ads.txt" | head -n "$1" | while IFS= read -r domain; do
        check_domain "$domain" >> "domains-bad-disconnect_ads-shuf.txt"
    done

    # Ajuste de formatação
    dos2unix domains-bad*-shuf.txt

    echo "✅ Filtragem concluída com até $1 domínios."
}

export -f shuffleBad;

function downloadLists(){
	wget "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt" -O "domains-bad-abusech.txt"
	sed -i '/^[[:blank:]]*#/d;s/#.*//' "domains-bad-abusech.txt"  # Remove comentários.
	sed -i 's/^0.0.0.0 //; /^#.*$/d; /^ *$/d; s/\t*//g' "domains-bad-abusech.txt"  # Remove IPs 0.0.0.0, comentários, linhas vazias e tabs.
	
	wget "https://hole.cert.pl/domains/domains.txt" -O "domains-bad-certpl.txt"
	dos2unix domains-bad*.txt  # Corrige o formato dos arquivos.
	
	wget "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" -O "domains-bad-disconnect_ads.txt"
	sed -i '/^[[:blank:]]*#/d;s/#.*//' "domains-bad-disconnect_ads.txt"  # Remove comentários.
	
	wget "https://raw.githubusercontent.com/vanderleiromera/dns_security/refs/heads/main/dns_comparator/domains-good.txt" -O "domains-good.txt"
}

export -f downloadLists;

#Download das listas
downloadLists

# Chama a função principal
runAllTests
