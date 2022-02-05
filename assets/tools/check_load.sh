#!/usr/bin/env bash

# shellcheck shell=bash

# Check syntax: shellcheck -s bash -e 1072,1094,1107,2145 check_load.sh

# Bash 'Strict Mode':
#   errexit  - exit the script if any statement returns a non-true return value
#   pipefail - exit the script if any command in a pipeline errors
#   nounset  - exit the script if you try to use an uninitialised variable
#   xtrace   - display debugging information
set -o errexit
set -o pipefail

# PATH env variable setup:
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Setting permissions in the script environment:
#   0022 - less restrictive settings (default value)
#   0027 - for better security than above
#   0077 - only for user access (more restrictive)
umask 0027

# shellcheck disable=SC2034
__init_params=()
__script_params=("$@")

# Tasks for specific system version.
if [[ "$OSTYPE" == "linux-gnu" ]] ; then

  # shellcheck disable=SC2034
  command -v yum > /dev/null 2>&1      && _DIST_VERSION="rhel"
  command -v apt-get > /dev/null 2>&1  && _DIST_VERSION="debian"

  readonly _init_name="$(basename "$0")"
  # shellcheck disable=SC2001,SC2005,SC2034
  readonly _init_directory=$(dirname "$(readlink -f "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")

  # shellcheck disable=SC2155
  export _vcpu=$(nproc) # getconf _NPROCESSORS_ONLN
  # shellcheck disable=SC2155
  export _loadavg=$(awk '{print $1,$2,$3}' /proc/loadavg)
  # shellcheck disable=SC2155
  export _task_running=$(awk '/procs_running/ { print $2 }' /proc/stat)
  # shellcheck disable=SC2155
  export _task_unint=$(ps auxf | awk '{if($8=="D") print $0;}' | wc -l)

elif [[ "$OSTYPE" == *"freebsd"* ]] ; then

  # shellcheck disable=SC2034
  command -v pkg > /dev/null 2>&1      && _DIST_VERSION="bsd"

  readonly _init_name="$(basename "$0")"
  # shellcheck disable=SC2001,SC2005,SC2034
  readonly _init_directory=$(dirname "$(readlink -f "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")

  # shellcheck disable=SC2155
  export _vcpu=$(sysctl -n hw.ncpu) # getconf _NPROCESSORS_ONLN
  # shellcheck disable=SC2155
  export _loadavg=$(sysctl vm.loadavg | awk '{print $3,$4,$5}')

elif [[ "$OSTYPE" == *"openbsd"* ]] ; then

  # shellcheck disable=SC2034
  command -v pkg > /dev/null 2>&1      && _DIST_VERSION="bsd"

  readonly _init_name="$(basename "$0")"
  # shellcheck disable=SC2001,SC2005,SC2034
  readonly _init_directory=$(dirname "$(readlink -f "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")

  # shellcheck disable=SC2155
  export _vcpu=$(sysctl -n hw.ncpu)
  # shellcheck disable=SC2155
  export _loadavg=$(sysctl vm.loadavg | cut -d "=" -f2 | awk '{print $1,$2,$3}')

else

  printf '%s\n' \
         "Unsupported system"
  exit 1

fi

while getopts hw:c:-: OPT ; do

  if [[ "$OPT" = "-" ]] ; then

    OPT="${OPTARG%%=*}"
    OPTARG="${OPTARG#$OPT}"
    OPTARG="${OPTARG#=}"

  fi

  case "$OPT" in

    h | help )

    # shellcheck disable=SC2154
    printf "%s" "
    $_init_name (loadavg monitoring plugin)

  Usage:

    $_init_name <option|long-option> [value]

  Examples:

    $_init_name -w 1.5,1.0,0.7 -c 1.8,1.2,0.9
    $_init_name -w 1.5,1.0,0.7 -c 2.0,1.4,1.0
    $_init_name -w 1.5,1.1,0.8 -c 2.0,1.45,1.0

  Options:

        -h|--help         show this message
        -w|--warning WLOAD1,WLOAD5,WLOAD15
                          Exit with WARNING status if load average exceeds WLOADn
        -c|--critical CLOAD1,CLOAD5,CLOAD15
                          Exit with CRITICAL status if load average exceed CLOADn

  Values:

        WLOADn (format: 00.00), eg. 0.8, 1.2, 1.81
        CLOADn (format: 00.00), eg. 1, 1.51, 2.29

"

    exit 0 ;;

    w | warning )
      export _warn_wg="${OPTARG}" ;;

    c | critical )
      export _crit_wg="${OPTARG}" ;;

    ??* )
      printf "illegal option --$OPT"
      exit 2 ;;
    \? )
      exit 2 ;;

  esac

done

shift $((OPTIND-1))

_w_tresh=()
_c_tresh=()

st=1
en=3

for ((i=st; i<=en; i++)) ; do

  _la_tmp=$(echo "$_loadavg" | cut -d " " -f"${i}")
  _la_tresh+=("$_la_tmp")

  if [[ -z "$_la_tmp" ]] ; then

    printf "invalid option value -- '%s'\\n" "_la_tmp (loadavg)"
    exit 1

  fi

done

st=1
en=3

for ((i=st; i<=en; i++)) ; do

  _w_tmp=$(echo "$_warn_wg" | cut -d "," -f"${i}")
  _w_tresh+=("$_w_tmp")

  if [[ -z "$_w_tmp" ]] ; then

    printf "invalid option value -- '%s'\\n" "_w_tmp (-w)"
    exit 1

  fi

done

st=1
en=3

for ((i=st; i<=en; i++)) ; do

  _c_tmp=$(echo "$_crit_wg" | cut -d "," -f"${i}")
  _c_tresh+=("$_c_tmp")

  if [[ -z "$_c_tmp" ]] ; then

    printf "invalid option value -- '%s'\\n" "_c_tmp (-c)"
    exit 1

  fi

done

# LOADAVG1
# shellcheck disable=SC2046,SC2116
_loadavg1=$(echo "${_la_tresh[0]}")

# LOADAVG5
# shellcheck disable=SC2046,SC2116
_loadavg5=$(echo "${_la_tresh[1]}")

# LOADAVG15
# shellcheck disable=SC2046,SC2116
_loadavg15=$(echo "${_la_tresh[2]}")

# WLOAD1
# shellcheck disable=SC2046
_wload1=$(echo "${_vcpu}" "${_w_tresh[0]}" | awk '{printf "%.2f\n", $1*$2}')

# WLOAD5
# shellcheck disable=SC2046
_wload5=$(echo "${_vcpu}" "${_w_tresh[1]}" | awk '{printf "%.2f\n", $1*$2}')

# WLOAD15
# shellcheck disable=SC2046
_wload15=$(echo "${_vcpu}" "${_w_tresh[2]}" | awk '{printf "%.2f\n", $1*$2}')

# CLOAD1
# shellcheck disable=SC2046
_cload1=$(echo "${_vcpu}" "${_c_tresh[0]}" | awk '{printf "%.2f\n", $1*$2}')

# CLOAD5
# shellcheck disable=SC2046
_cload5=$(echo "${_vcpu}" "${_c_tresh[1]}" | awk '{printf "%.2f\n", $1*$2}')

# CLOAD15
# shellcheck disable=SC2046
_cload15=$(echo "${_vcpu}" "${_c_tresh[2]}" | awk '{printf "%.2f\n", $1*$2}')

function _get_stats() {

  printf "|vcpu=%s load1=%s,%s,%s load5=%s,%s,%s load15=%s,%s,%s\\n" \
         "$_vcpu" \
         "$_loadavg1" \
         "$_wload1" \
         "$_cload1" \
         "$_loadavg5" \
         "$_wload5" \
         "$_cload5" \
         "$_loadavg15" \
         "$_wload15" \
         "$_cload15"

}

if (( $(echo "$_loadavg15" "$_cload15" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "CRITICAL - loadavg15: $_loadavg15 ($_cload15)"
  _get_stats

  exit 2

elif (( $(echo "$_loadavg5" "$_cload5" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "CRITICAL - loadavg5: $_loadavg5 ($_cload5)"
  _get_stats

  exit 2

elif (( $(echo "$_loadavg1" "$_cload1" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "CRITICAL - loadavg1: $_loadavg1 ($_cload1)"
  _get_stats

  exit 2

elif (( $(echo "$_loadavg15" "$_wload15" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "WARNING - loadavg15: $_loadavg15 ($_wload15)"
  _get_stats

  exit 1

elif (( $(echo "$_loadavg5" "$_wload5" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "WARNING - loadavg5: $_loadavg5 ($_wload5)"
  _get_stats

  exit 1

elif (( $(echo "$_loadavg1" "$_wload1" | awk '{if ($1 > $2) print 1;}') )) ; then

  echo -en "WARNING - loadavg1: $_loadavg1 ($_wload1)"
  _get_stats

  exit 1

else

  echo -en "OK - loadavg: $_loadavg"
  _get_stats

  exit 0

fi
