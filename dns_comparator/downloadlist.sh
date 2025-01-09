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
#https://github.com/divestedcg/circumnavigator/blob/master/test.sh


function downloadLists(){
	wget "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt" -O - | grep -i -v -e '^#' | sed 's|127.0.0.1\t||' > "domains-bad-abusech.txt";
	wget "https://hole.cert.pl/domains/domains.txt" -O "domains-bad-certpl.txt";
	wget "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" -O - | grep -i -v -e '^#' | sed '/^$/d' > "domains-bad-disconnect_ads.txt";
	dos2unix domains-bad*.txt; #Fixup
}
export -f downloadLists;

# Chama a função principal
downloadLists
