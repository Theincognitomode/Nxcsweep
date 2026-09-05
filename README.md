# Nxcsweep

A small Bash wrapper around [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) that validates one set of credentials against **SMB, WinRM, RDP, and WMI** in a single run against a single host or a full CIDR range and hands you ready-to-paste connection commands for every hit.

Built for CTF / OSCP-style workflows where you land a password or a hash and want to know, in one shot, everywhere it works and how to actually get in.

## Features

- Checks all four protocols (`smb`, `winrm`, `rdp`, `wmi`) against a single IP **or** a CIDR range
- Supports both password and pass-the-hash auth, using nxc's own `-p` / `-H` flag style
- Preserves NetExec's native colored output (via a pseudo-tty), instead of flattening it
- Deduplicates hosts that produce multiple `[+]` lines — one clean block per host, not a mess of repeats
- Auto-generates the actual next command to run for every valid hit:
  - `evil-winrm` for WinRM
  - `impacket-psexec` / `impacket-wmiexec` for SMB admin (`Pwn3d!`)
  - `smbclient` / `nxc --shares` for SMB non-admin
  - `xfreerdp3` for RDP (including pass-the-hash via `/pth`)
  - `impacket-wmiexec` for WMI
- Flags SMB admin (`Pwn3d!`) hits with a pointer toward nxc's credential-dumping modules (`--sam`, `--lsa`, `--ntds`, `-M lsassy`, `-M dpapi`)
- Nothing is written to disk output only streams to your terminal

## Requirements

- [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) on your `PATH` (which is installed by default in most of the case)
  ```bash
  pip install netexec
  ```
- `script` (from `util-linux`) preinstalled on virtually every Linux distro, including Kali. Used to preserve nxc's native coloring; the script still works without it, just without color.
- Optional, only needed if you actually run the suggested connect commands:
  - [`evil-winrm`](https://github.com/Hackplayers/evil-winrm)
  - [Impacket](https://github.com/fortra/impacket) (`impacket-psexec`, `impacket-wmiexec`, `impacket-smbclient`)
  - [FreeRDP3](https://github.com/FreeRDP/FreeRDP) (`xfreerdp3`)

## How to use

Clone or download the script, then make it executable:

```bash
git clone https://github.com/Theincognitomode/nxcsweep.git
cd nxcsweep
chmod +x nxcsweep.sh
```

## Usage

```bash
./nxcsweep.sh <ip/cidr> -u <user> -p <password>
./nxcsweep.sh <ip/cidr> -u <user> -H <ntlm_hash>
```

### Examples

Single host, password:
```bash
./nxcsweep.sh 10.10.10.5 -u administrator -p 'P@ssw0rd!'
```

Full subnet sweep, password:
```bash
./nxcsweep.sh 10.10.10.0/24 -u j.doe -p 'Summer2024!'
```

Pass-the-hash:
```bash
./nxcsweep.sh 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

## Example output

You will see such commands at the end when the script is completed (If you know what this is then you know :O)
<img width="957" height="698" alt="image" src="https://github.com/user-attachments/assets/12aecb2c-98f9-4694-a687-71abf7328057" />


## Running it from anywhere

If you don't want to `cd` into this folder or type `./nxcsweep.sh` every time, install it globally so it's just `nxcsweep` on your `PATH` from any directory.

**Option A: symlink (recommended if you plan to keep tweaking the script):**

```bash
sudo ln -sf "$(pwd)/nxcsweep.sh" /usr/local/bin/nxcsweep
```

Any edits you make to your working copy take effect immediately — no need to reinstall.

**Option B: plain copy:**

```bash
sudo cp nxcsweep.sh /usr/local/bin/nxcsweep
sudo chmod +x /usr/local/bin/nxcsweep
```

Simpler, but if you edit the script afterward you'll need to re-run the `cp` to update the installed copy.

Either way, `/usr/local/bin` is on `PATH` by default on virtually all Linux distros, so once installed you can drop the `./` entirely and run it as:

```bash
nxcsweep <ip/cidr> -u <user> -p <password>
nxcsweep <ip/cidr> -u <user> -H <ntlm_hash>
```

from any directory, no navigating to this folder required.

## Notes & caveats

- **RDP `Pwn3d!` is unreliable.** NetExec has a known open issue where RDP sometimes tags low-privileged users as `Pwn3d!` too. Treat a plain `[+]` on RDP as "credentials are valid and the account can open an interactive session" rather than reading too much into the tag either way.
- **RDP pass-the-hash (`/pth`) requires Restricted Admin Mode** to be enabled on the target. It's not on by default, so this specific suggested command can fail even when the hash is correct.
- **Standard `smbclient` can't pass-the-hash.** In hash mode, the script swaps that suggestion for `impacket-smbclient`, which can.
- The generated `xfreerdp3` command includes a hardcoded `/drive:` mount (`privtools,/home/offo/windowspriv/tools`) — **edit this path in the script** to match your own local tools directory before using it, or remove the flag entirely if you don't need drive redirection.
- Nothing is logged to disk by design — if you want a persistent record of a run, redirect output yourself:
  ```bash
  ./nxcsweep.sh 10.10.10.0/24 -u administrator -p 'P@ssw0rd!' | tee run.log
  ```
