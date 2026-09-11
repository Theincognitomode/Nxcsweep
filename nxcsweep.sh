#!/bin/bash
#
# nxcsweep.sh
# Validates a given username/password (or username/NTLM hash) against
# SMB, WinRM, RDP, and WMI on a single IP or a full network range using
# NetExec (nxc).
#
# Usage (matches nxc's own flag style):
#   ./nxcsweep.sh <target> -u <username> -p <password> [--local-auth] [--no-show]
#   ./nxcsweep.sh <target> -u <username> -H <ntlm_hash> [--local-auth] [--no-show]
#
# Examples:
#   ./nxcsweep.sh 10.10.10.5 -u administrator -p 'P@ssw0rd!'
#   ./nxcsweep.sh 10.10.10.0/24 -u j.doe -p 'Summer2024!'
#   ./nxcsweep.sh 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
#   ./nxcsweep.sh 10.10.10.5 -u Administrator -p 'P@ssw0rd!' --local-auth   # local (non-domain) account
#   ./nxcsweep.sh 10.10.10.0/24 -u j.doe -p 'Summer2024!' --no-show        # just the pass/fail status, no connect-command block
#
# Requires: netexec (nxc) - https://github.com/Pennyw0rth/NetExec

set -euo pipefail

# ---- colors ----
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREY='\033[0;37m'
NC='\033[0m'

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 <target_ip_or_cidr> -u <username> -p <password> [--local-auth] [--no-show]"
    echo -e "       $0 <target_ip_or_cidr> -u <username> -H <ntlm_hash> [--local-auth] [--no-show]"
    echo -e ""
    echo -e "  e.g. $0 10.10.10.0/24 -u administrator -p 'Password123!'"
    echo -e "  e.g. $0 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    echo -e "  e.g. $0 10.10.10.5 -u Administrator -p 'P@ssw0rd!' --local-auth"
    echo -e "  e.g. $0 10.10.10.0/24 -u j.doe -p 'Summer2024!' --no-show"
    echo -e ""
    echo -e "  --local-auth   authenticate as a local account instead of a domain one (passed straight to nxc)"
    echo -e "  --no-show      only print pass/fail status per protocol - skip the connect-command suggestions block"
    exit 1
}

# ---- args ----
if [ "$#" -lt 1 ]; then
    usage
fi

TARGET="$1"
shift

# pre-scan for boolean long-flags anywhere in the remaining args, then hand
# whatever's left to getopts for the -u/-p/-H short flags (getopts alone
# can't parse long options like --local-auth)
LOCAL_AUTH=false
NO_SHOW=false
REMAINING_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --local-auth) LOCAL_AUTH=true ;;
        --no-show) NO_SHOW=true ;;
        *) REMAINING_ARGS+=("$arg") ;;
    esac
done
set -- "${REMAINING_ARGS[@]}"

USERNAME=""
SECRET=""
MODE=""

while getopts ":u:p:H:" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        p) SECRET="$OPTARG"; MODE="password" ;;
        H) SECRET="$OPTARG"; MODE="hash" ;;
        *) usage ;;
    esac
done

if [ -z "$USERNAME" ] || [ -z "$SECRET" ] || [ -z "$MODE" ]; then
    usage
fi

# ---- check nxc is installed ----
if ! command -v nxc &> /dev/null; then
    echo -e "${RED}[!] netexec (nxc) not found in PATH. Install it first: pip install netexec${NC}"
    exit 1
fi

PROTOCOLS=("smb" "winrm" "rdp" "wmi")

echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN} nxcsweep - Protocol Credential Validator${NC}"
echo -e "${CYAN}=========================================${NC}"
echo -e "Target   : ${YELLOW}${TARGET}${NC}"
echo -e "Username : ${YELLOW}${USERNAME}${NC}"
if [ "$MODE" = "hash" ]; then
    echo -e "NTLM Hash: ${YELLOW}${SECRET}${NC}"
else
    echo -e "Password : ${YELLOW}${SECRET}${NC}"
fi
if [ "$LOCAL_AUTH" = true ]; then
    echo -e "Auth type: ${YELLOW}local${NC}"
fi
echo ""

# reused later to keep the suggested nxc follow-up commands (--shares, -x whoami)
# consistent with how the sweep itself authenticated
LOCAL_AUTH_SUFFIX=""
if [ "$LOCAL_AUTH" = true ]; then
    LOCAL_AUTH_SUFFIX=" --local-auth"
fi

# deduplicated hit tracking: key = "proto|ip", value = "yes"/"no" (Pwn3d status)
# HIT_ORDER preserves first-seen order so output stays grouped sensibly
declare -A HITMAP=()
declare -a HIT_ORDER=()

for proto in "${PROTOCOLS[@]}"; do
    echo -e "${CYAN}[*] Checking protocol: ${proto^^}${NC}"

    NXC_ARGS=("$proto" "$TARGET" -u "$USERNAME")
    if [ "$MODE" = "hash" ]; then
        NXC_ARGS+=(-H "$SECRET")
    else
        NXC_ARGS+=(-p "$SECRET")
    fi
    if [ "$LOCAL_AUTH" = true ]; then
        NXC_ARGS+=(--local-auth)
    fi

    if command -v script &> /dev/null; then
        esc_cmd="nxc"
        for a in "${NXC_ARGS[@]}"; do
            esc_cmd="$esc_cmd $(printf '%q' "$a")"
        done
        OUTPUT=$(script -qec "$esc_cmd" /dev/null 2>&1 || true)
    else
        OUTPUT=$(nxc "${NXC_ARGS[@]}" 2>&1 || true)
    fi

    # color-free copy used only for our own [+]/Pwn3d! parsing logic below
    PLAIN=$(echo "$OUTPUT" | sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g')

    # Highlight based on nxc's typical output markers
    if echo "$PLAIN" | grep -qi "(Pwn3d!)"; then
        echo -e "${GREEN}[+] $proto: Admin access confirmed (Pwn3d!)${NC}"
    elif echo "$PLAIN" | grep -qi "\[+\]"; then
        echo -e "${GREEN}[+] $proto: Valid credentials${NC}"
    elif echo "$PLAIN" | grep -qi "\[-\]"; then
        echo -e "${RED}[-] $proto: Failed / invalid credentials${NC}"
    else
        echo -e "${YELLOW}[?] $proto: No response / host(s) unreachable on this protocol${NC}"
    fi

    echo "$OUTPUT" | sed 's/^/    /'
    echo ""

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1 || true)
        [ -z "$ip" ] && continue
        key="${proto}|${ip}"
        if echo "$line" | grep -qi "(Pwn3d!)"; then
            pwn="yes"
        else
            pwn="no"
        fi

        if [ -z "${HITMAP[$key]:-}" ]; then
            HITMAP["$key"]="$pwn"
            HIT_ORDER+=("$key")
        elif [ "$pwn" = "yes" ]; then
            HITMAP["$key"]="yes"
        fi
    done < <(echo "$PLAIN" | grep -i "\[+\]")
done

if [ "$NO_SHOW" = true ]; then
    :
elif [ "${#HIT_ORDER[@]}" -gt 0 ]; then
    echo ""
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${CYAN} Valid credential hits - connect commands${NC}"
    echo -e "${CYAN}=========================================${NC}"

    for key in "${HIT_ORDER[@]}"; do
        IFS='|' read -r hproto hip <<< "$key"
        hpwn="${HITMAP[$key]}"
        case "$hproto" in
            winrm)
                if [ "$hpwn" = "yes" ]; then
                    echo -e "${GREEN}[+] WinRM (Pwn3d!) on ${hip}${NC}"
                else
                    echo -e "${GREEN}[+] WinRM valid on ${hip}${NC}"
                fi
                if [ "$MODE" = "hash" ]; then
                    echo -e "    ${GREY}evil-winrm -i ${hip} -u '${USERNAME}' -H '${SECRET}'${NC}"
                else
                    echo -e "    ${GREY}evil-winrm -i ${hip} -u '${USERNAME}' -p '${SECRET}'${NC}"
                fi
                ;;
            smb)
                if [ "$hpwn" = "yes" ]; then
                    echo -e "${GREEN}[+] SMB admin (Pwn3d!) on ${hip}${NC}"
                    if [ "$MODE" = "hash" ]; then
                        echo -e "    ${GREY}impacket-psexec -hashes ':${SECRET}' '${USERNAME}@${hip}'${NC}"
                        echo -e "    ${GREY}impacket-wmiexec -hashes ':${SECRET}' '${USERNAME}@${hip}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -H '${SECRET}' -x whoami${LOCAL_AUTH_SUFFIX}${NC}"
                    else
                        echo -e "    ${GREY}impacket-psexec '${USERNAME}:${SECRET}@${hip}'${NC}"
                        echo -e "    ${GREY}impacket-wmiexec '${USERNAME}:${SECRET}@${hip}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -p '${SECRET}' -x whoami${LOCAL_AUTH_SUFFIX}${NC}"
                    fi
                    echo ""
                    echo -e "    ${CYAN}You can dump credentials as well using nxc modules (--sam, --lsa, --ntds, -M lsassy, -M dpapi)${NC}"
                else
                    echo -e "${GREEN}[+] SMB valid (non-admin) on ${hip}${NC}"
                    if [ "$MODE" = "hash" ]; then
                        echo -e "    ${GREY}impacket-smbclient -hashes ':${SECRET}' '${USERNAME}@${hip}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -H '${SECRET}' --shares${LOCAL_AUTH_SUFFIX}${NC}"
                    else
                        echo -e "    ${GREY}smbclient -L //${hip}/ -U '${USERNAME}%${SECRET}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -p '${SECRET}' --shares${LOCAL_AUTH_SUFFIX}${NC}"
                    fi
                fi
                ;;
            rdp)
                echo -e "${GREEN}[+] RDP valid on ${hip}${NC}"
                if [ "$MODE" = "hash" ]; then
                    echo -e "    ${GREY}xfreerdp3 /v:${hip} /u:${USERNAME} /pth:${SECRET} +dynamic-resolution${NC}"
                else
                    echo -e "    ${GREY}xfreerdp3 /v:${hip} /u:${USERNAME} /p:'${SECRET}' +dynamic-resolution${NC}"
                fi
                ;;
            wmi)
                echo -e "${GREEN}[+] WMI valid on ${hip}${NC}"
                if [ "$MODE" = "hash" ]; then
                    echo -e "    ${GREY}impacket-wmiexec -hashes ':${SECRET}' '${USERNAME}@${hip}'${NC}"
                else
                    echo -e "    ${GREY}impacket-wmiexec '${USERNAME}:${SECRET}@${hip}'${NC}"
                fi
                ;;
        esac
        echo ""
    done
else
    echo ""
    echo -e "${YELLOW}[!] No valid credential hits across any protocol.${NC}"
fi
