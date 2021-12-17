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
        outfile="$(mktemp)"
        unzip -p "$1" "$mpcfile" 2> /dev/null > "$outfile"
        ispatched=$(grep 'Message Lookups are no longer supported' "$outfile")
        if [ -n "$ispatched" ]; then
            patched=1
        fi
    fi

    if [ -n "$jndifile" ]; then
        hasjndi=1
        if [ -n "$subjarfilename" ]; then
            outputstring="$parent contains $subjarfilename contains JndiLookup.class"
        else
            outputstring="$parent contains JndiLookup.class"
        fi
        jndioutfile="$(mktemp)"
        unzip -p "$1" "$jndifile" 2> /dev/null > "$jndioutfile"
        ispatched=$(grep 'JNDI is not supported' "$jndioutfile")
        if [ -n "$ispatched" ]; then
            patched=1
        fi
    fi

    if [ ! -z "$jarfiles" ]; then
        for subjar in $jarfiles
            do
                subjarfile="$(mktemp)"
                unzip -p "$1" "$subjar" 2> /dev/null > "$subjarfile"
                process_jar "$subjarfile" "$parent" "$subjar"
                rm "$subjarfile" 2> /dev/null
            done

    fi

    if [ -n "$mpcfile" ]; then
        rm "$outfile" 2> /dev/null
    fi

    if [ -n "$jndifile" ]; then
        rm "$jndioutfile" 2> /dev/null
    fi

    if [ -n "$patched" ]; then
        outputstring="$outputstring ** BUT APPEARS TO BE PATCHED **"
    fi

    if [ -z "$printed" ]; then
        if [ -n "$hasjndi" ]; then
            if [ -n "$patched" ]; then
                echo "$outputstring"
            else
                echo "WARNING: $outputstring"
            fi
            printed=1
        fi
    fi
}

if [[ $OSTYPE == 'darwin'* ]]; then
    checkfiles=$(find "$tld" -fstype local -type f \( -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" -o -iname "*.zip" -o -iname "JndiLookup.class" \))
else
    checkfiles=$(find "$tld" -mount -type f \( -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" -o -iname "*.zip" -o -iname "JndiLookup.class" \))
fi

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
