#!/bin/sh

# Make the version.h file based on the directory name for Deadwood

        pwd | awk -F/ '{print $(NF - 1)}' | \
                awk -F- '{
                if($2 == "H" || $2 == "S" || $2 == "Q") {
                print "#define VERSION \""$(NF-3)"-"$(NF-2)"-"$(NF-1)"-"$NF"\""
                } else {
                        print "#define VERSION \""$NF"\""
                        } }' > version.h
