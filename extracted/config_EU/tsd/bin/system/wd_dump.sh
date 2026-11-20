#!/bin/ksh

# ATTENTION: be very careful with what you do in this script. Dfilter will
# execute this script and is blocked on its output. Any direct or indirect
# access to /proc/dumper will thus lead to a dead lock.

inferior_by_pid()
{
   INFERIOR_PID="$1"
   INFERIOR_NAME="$(ps -p "$1" -o cmd | tail -n+1)"
}

inferior_by_name()
{
   INFERIOR_PID="$1"
   INFERIOR_NAME="$1"
}

###############################################################################

INFERIOR_PID=
INFERIOR_NAME=

case "$1" in
      "hmi")
         inferior_by_name "j9"
         ;;
      "cmq")
         inferior_by_pid "$2"
         ;;
      "apw")
         case "$3" in
            # J9/HMI is special as it is started though a shell script
	         "iMX6.J9/HMI" | "HMI")
               inferior_by_name "j9"
               ;;
            *)
               inferior_by_pid "$2"
               ;;
         esac
         ;;
esac

# no pid, no dump
[[ -z "$INFERIOR_PID" ]] && exit 0

# don't dump anything if GDB is attached
if ! slay -p pdebug >/dev/null 2>&1 ; then
   echo "wd_dump.sh: active remote GDB found, i'm not dumping watchdogs." >&2
   exit 0
fi

# dump the inferior
echo "$INFERIOR_PID"
