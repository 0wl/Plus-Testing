#!/bin/sh
echo "call tracelogger";
tracelogger -f /tmp/Trace.kev -s 60 -c -k 64 -b 128 -M -S 200M;
cp -f /tmp/Trace.kev /media/mp000/Trace.kev;
ls -al /media/mp000;
rm -f /tmp/Trace.kev;
### ende ###
