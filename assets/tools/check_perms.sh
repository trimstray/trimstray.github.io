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

elif [[ "$OSTYPE" == *"bsd"* ]] ; then

  # shellcheck disable=SC2034
  command -v pkg > /dev/null 2>&1      && _DIST_VERSION="bsd"

  readonly _init_name="$(basename "$0")"
  # shellcheck disable=SC2001,SC2005,SC2034
  readonly _init_directory=$(dirname "$(readlink -f "$0" || echo "$(echo "$0" | sed -e 's,\\,/,g')")")

else

  printf '%s\n' \
         "Unsupported system"
  exit 1

fi

_st_o="0"
_st_p="0"

while getopts hp:u:g:d:f:-: OPT ; do

  if [[ "$OPT" = "-" ]] ; then

    OPT="${OPTARG%%=*}"
    OPTARG="${OPTARG#$OPT}"
    OPTARG="${OPTARG#=}"

  fi

  case "$OPT" in

    h | help )

    # shellcheck disable=SC2154
    printf "%s" "
    $_init_name (permissions monitoring plugin)

  Usage:

    $_init_name <option|long-option> [value]

  Examples:

    $_init_name -p /etc/ssl/keys -u nginx -g nginx -d 0700 -f 0400

  Options:

        -h|--help            show this message
        -p|--path            set path to scan
        -u|--user <value>    check user of file/directory
        -g|--group <value>   check group of file/directory
        -d|--dperm <value>   check directory permissions
        -f|--fperm <value>   check file permissions

"

    exit 0 ;;

    p | path )
      export _path="${OPTARG}" ;;

    u | user )
      export _user="${OPTARG}" ;;

    g | group )
      export _group="${OPTARG}" ;;

    d | directory )
      export _d_perm="${OPTARG}" ;;

    f | file )
      export _f_perm="${OPTARG}" ;;

    ??* )
      printf "illegal option --$OPT"
      exit 2 ;;
    \? )
      exit 2 ;;

  esac

done

shift $((OPTIND-1))

if [[ ! -d "$_path" ]] ; then

  printf "path not exist -- _path: '%s'\\n" "$_path"
  exit 1

fi

if [[ $(grep -q "^${_user}:" /etc/passwd) -ne 0 ]] ; then

  printf "invalid option value for '-u|--user' -- '%s'\\n" "$_user"
  exit 1

fi

if [[ $(grep -q "^${_group}:" /etc/group) -ne 0 ]] ; then

  printf "invalid option value for '-g|--group' -- '%s'\\n" "$_group"
  exit 1

fi

nu='^[0-9]+$'

if ! [[ $_d_perm =~ $nu ]] ; then

  printf "invalid option value for '-d|--dperm' -- '%s'\\n" "$_d_perm"
  exit 1

fi

if ! [[ $_f_perm =~ $nu ]] ; then

  printf "invalid option value for '-d|--fperm' -- '%s'\\n" "$_f_perm"
  exit 1

fi

_st_o=$(find "${_path}" ! -user "${_user}" -o ! -group "${_group}" | wc -l | sed "s/ //g")
_st_p=$(find "${_path}" -type d -not -perm "${_d_perm}" -o -type f -not -perm "${_f_perm}" | wc -l | sed "s/ //g")

if [[ "$_st_o" -ne 0 ]] || [[ "$_st_p" -ne 0 ]] ; then

  echo -en "CRITICAL: ${_st_o} insecure id/gid, ${_st_p} insecure perms\\n"

  exit 2

else

  echo -en "OK: not found insecure id/gid and perms\\n"

  exit 0

fi
