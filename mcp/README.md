# IPAM MCP server

This lets Claude answer IP address questions straight from IPAM, for example:

- "what's the subnet for VLAN_OT_SERVER at X9?"
- "what VLANs do we have for security?"
- "where does 10.1.13.61 belong?"
- "next free DC address at X9?"

It's a small local server (spec §9). It runs on your workstation over stdio and talks only to the IPAM API, with its own API key. It never touches the database, and every call is in the IPAM audit log as client `ClaudeCowork-MCP`.

**All tools are read-only.** None can reserve, confirm, retire or delete sites, or change templates or the library. Those stay in the IPAM UI, behind sign-in and 2FA.

## Tools

| Tool | Use it for |
|---|---|
| `ipam_find_vlans` | Search the VLAN library by key, name, alias, ID, class or description |
| `ipam_get_vlan` | One VLAN's definition (ID, name, aliases, class, zone) and where it's used |
| `ipam_get_vlan_at_site` | The subnet a VLAN has at a site, with every attribute (CIDR, gateway, mask, prefix, network portion, broadcast, usable range, DNS) and its standard hosts. Pass `field` for one value |
| `ipam_list_site_subnets` | **Every** subnet at a site, with its VLAN where one is assigned (`assigned` true/false) and counts. `subnets` = `all` (default), `assigned` or `unassigned`; optionally one section |
| `ipam_lookup_host` | A standard host's IP, by member (WDC01) or role + instance |
| `ipam_next_available` | Next free address for a host type at a site (doesn't reserve anything) |
| `ipam_search` | Anything: an IP, CIDR, hostname, VLAN, site or template |
| `ipam_list_sites`, `ipam_get_site` | Sites, their blocks, status and template |
| `ipam_list_templates`, `ipam_preview_template` | Templates, and **every** subnet one produces at a base IP (same `subnets` and `section` options) |

## Set-up (Windows)

1. **Install** it into its own virtual environment. From the `mcp` folder of the repo:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\pip install .
   ```

2. **Issue a key.** In the IPAM UI, go to **API keys** and choose **Issue key**:
   - Owner: you.
   - Purpose: "Claude MCP".
   - Client name: `ClaudeCowork-MCP`.
   - Scope: **read only**.

3. **Store the key** in Windows Credential Manager, so it's never written into a config file. Copy the key (the **Copy key** button when it's issued), then:

   ```powershell
   Get-Clipboard | .\.venv\Scripts\ipam-mcp-setkey
   ```

   Don't paste the key at the PowerShell prompt itself: it would end up in your shell history.

   It checks the key against IPAM before storing it.

4. **Register it with Claude.**
   - **Claude Code**, from any terminal:

     ```powershell
     claude mcp add --scope user ipam -- "C:\Users\Craig.McDonald\source\repos\nextdc-ipam\mcp\.venv\Scripts\ipam-mcp.exe"
     ```

   - **Claude Desktop**: run this from a normal PowerShell window, then quit Claude Desktop from the system tray (right-click the Claude icon, then **Quit**):

     ```powershell
     .\scripts\Register-IpamMcp.ps1
     ```

     The script waits for Claude Desktop to close, backs up `%APPDATA%\Claude\claude_desktop_config.json`, adds `mcpServers.ipam` and reopens Claude. Don't edit that file while Claude Desktop is running: the app rewrites it from memory and drops changes made underneath it.

IPAM has to be running (`docker compose up -d` in the repo root).

**Updating the server.** `ipam-mcp.exe` is locked while any Claude session has the server running, so pip can't reinstall over it. This venv loads `ipam_mcp` straight from the repo (an `ipam_mcp_repo.pth` file in its site-packages), so after `git pull` just start a new Claude session (or `/mcp` → reconnect in Claude Code). For a fresh install with no Claude running, `.\.venv\Scripts\pip install -e .` does the same.

## Settings (environment variables, all optional)

| Variable | Default | Purpose |
|---|---|---|
| `IPAM_URL` | `http://127.0.0.1:8820/api/v1` | Where IPAM's API is |
| `IPAM_API_KEY` | Credential Manager entry `ipam-mcp` | The key, if you'd rather not use Credential Manager |
| `IPAM_CLIENT_NAME` | `ClaudeCowork-MCP/0.1` | How calls appear in the audit log |

## Not yet

These are the next steps, if wanted:
- `ipam_reserve_host`, which reserves an address for 24 hours, only after you've agreed to the address Claude proposes;
- a remote (HTTP) transport with sign-in, so others can use it without a local install.
