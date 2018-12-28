#!/bin/bash
c=0
hashes=${#@}
unset no_entries
unset hits
no_entries=()
declare -A hits

for myHash in $@
do
    unset rawAns
    unset param
    declare -A param
    printf "%s (%d/%d)" $myHash $((c+1)) $hashes
    printf ' %.0s' {1..100}
    printf '\n'
    c=$((c+1))
    #echo ${VT_API_KEY}
    #echo ${myHash}
    #exit
    while [[ "$rawAns" = ""  ]]
        do
#printf "dbg: curling\n"
            rawAns=`curl --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=${VT_API_KEY} -d 'resource='${myHash} 2> /dev/null `
            if [[ "$rawAns" = ""  ]]
                then
                    sleep 16
            fi
        done
    
    wrk=${rawAns#\{}
    wrk=${wrk%\}}
    #wrk=${wrk//\}, \"/\}, '\n'\"}
    #echo -e $wrk
    #c=0
    #echo "BGN: $wrk"
    while [[ "$wrk" =~ ":" ]] 
        do 
            #pop off the next key
            x=${wrk%%\": *}
            x=${x##\"}
            #shorten the buffer
            wrk=${wrk#\"$x\": }
            if [[ "${wrk:0:1}" == "{" ]]
                then
                    y=${wrk%\}*}"}"
                    #shorten the buffer
                    wrk=${wrk#$y, }
                elif [[ "${wrk:0:1}" == "\"" ]]
                then
                    y=${wrk#\"}
                    y=${y%%\"*}
                    #shorten the buffer
                    wrk=${wrk#\"$y\", }
                else
                    y=${wrk%%\, \"*}
                    #shorten the buffer
                    wrk=${wrk#$y, }
            fi
            #printf "\$x: >%s<\n\$y: >%s<\n\$wrk: >%s<\n==============\n" "$x" "$y" "$wrk"
            param[$x]="$y"
        done
#    for p in ${!param[*]}
#        do 
           # printf "key: %s\nvalue: %s\n\n" "$p" "${param[$p]}" 
#        done
    printf "\tresponse code: %d\n\tpositives: %d\n" ${param[response_code]} ${param[positives]}
    if [[ ${param[response_code]} -eq 0 ]]
        then
            no_entries+=($myHash)
    fi
    if [[ ${param[positives]} -gt 0 ]]
        then
            hits[$myHash]=${param[positives]}
    fi
    
    
    #printf "raw: %s" "$rawAns"

    if [[ $c -lt $hashes ]]
        then 
        if [[ $c -ge 4 ]]
            then 
                printf "pausing for rate limit"
                for ((x=0;x<16;x++))
                    do sleep 1
                        printf " ."
                    done
                printf "\r"
        fi
    fi
done
printf ' %.0s' {1..100}
printf '\r'
printf 'No records found for the following hashes:\n'
printf '\t%s\n' "${no_entries[@]}"
printf 'Hit found for the following hashes:\n' 
printf '\t%s\n' "${!hits[@]}"
#export param
