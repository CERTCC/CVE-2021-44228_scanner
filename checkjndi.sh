#!/bin/bash

tld="$1"

if [ -z "$tld" ]; then
    tld='.'
fi

unzip=$(which unzip)
if [ -z "$unzip" ]; then
    echo "This script requires unzip to function properly"
    exit 1
fi

process_jar() {
    patched=""
    hasjndi=""
    printed=""
    if [ -z "$2" ]; then
        parent="$1"
    else
        parent="$2"
    fi

    if [ -z "$3" ]; then
        subjarfilename=""
    else
        subjarfilename="$3"
    fi


    jndifile=$(unzip -l "$1" 2> /dev/null | grep -E "JndiLookup.class$" | awk '{print $NF}')
    mpcfile=$(unzip -l "$1" 2> /dev/null | grep -E "MessagePatternConverter.class$" | awk '{print $NF}')
    jarfiles=$(unzip -l "$1" 2> /dev/null | grep -Ei  ".jar$|.war$|.ear$|.zip$" | grep -v "Archive: " | awk '{print $NF}')
    if [ -n "$mpcfile" ]; then
        local outfile="$(mktemp)"
        unzip -p "$1" "$mpcfile" 2> /dev/null > "$outfile"
        ispatched=$(grep 'Message Lookups are no longer supported' "$outfile")
        if [ -n "$ispatched" ]; then
            # 2.16 is patched
            # https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97
            patched=1
        fi
        if [ -f "$outfile" ]; then
            rm "$outfile"
        fi
    fi

    if [ -n "$jndifile" ]; then
        hasjndi=1
        if [ -n "$subjarfilename" ]; then
            outputstring="$parent contains $subjarfilename contains JndiLookup.class"
        else
            outputstring="$parent contains JndiLookup.class"
        fi
        local jndioutfile="$(mktemp)"
        unzip -p "$1" "$jndifile" 2> /dev/null > "$jndioutfile"
        ispatched=$(grep 'JNDI is not supported' "$jndioutfile")
        if [ -n "$ispatched" ]; then
            # 2.12.2 is patched
            # https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37
            patched=1
        fi
        if [ -f "$jndioutfile" ]; then
            rm "$jndioutfile"
        fi
    fi

    if [ ! -z "$jarfiles" ]; then
        for subjar in $jarfiles
            do
                local subjarfile="$(mktemp)"
                unzip -p "$1" "$subjar" 2> /dev/null > "$subjarfile"
                process_jar "$subjarfile" "$parent" "$subjar"
                if [ -f "$subjarfile" ]; then
                    rm "$subjarfile"
                fi
            done

    fi

    if [ -n "$patched" ]; then
        outputstring="$outputstring ** BUT APPEARS TO BE PATCHED **"
    fi

    if [ -z "$printed" ]; then
        if [ -n "$hasjndi" ]; then
            if [ -n "$patched" ]; then
                echo "$outputstring"
            else
                foundvulnerable=1
                echo "WARNING: $outputstring"
            fi
            printed=1
        fi
    fi
}

checkfiles=$(find "$tld" -mount -type f \( -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" -o -iname "*.zip" -o -iname "JndiLookup.class" \))


OLDIFS=$IFS
IFS=$'\n'
for checkfile in $checkfiles
    do
        if [[ $checkfile == *JndiLookup.class ]]; then
            echo "$checkfile *IS* JndiLookup.class"
        else
            process_jar "$checkfile"
        fi
    done
IFS=$OLDIFS

if [ ! "$foundvulnerable" == "1" ]; then
    echo "No vulnerable components found"
    exit 0
else
    exit 1
fi
