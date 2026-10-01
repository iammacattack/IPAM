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
| `ipam_list_site_vlans` | Every VLAN-to-subnet mapping at a site, optionally for one section |
| `ipam_lookup_host` | A standard host's IP, by member (WDC01) or role + instance |
| `ipam_next_available` | Next free address for a host type at a site (doesn't reserve anything) |
| `ipam_search` | Anything: an IP, CIDR, hostname, VLAN, site or template |
| `ipam_list_sites`, `ipam_get_site` | Sites, their blocks, status and template |
| `ipam_list_templates`, `ipam_preview_template` | Templates and what one produces at a base IP |

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

3. **Store the key** in Windows Credential Manager, so it's never written into a config file:

   ```powershell
   .\.venv\Scripts\ipam-mcp-setkey
   ```

   Paste the key when asked. It checks the key against IPAM before storing it.

4. **Register it with Claude.**
   - **Claude Code**, from any terminal:

     ```powershell
     claude mcp add --scope user ipam -- "C:\Users\Craig.McDonald\source\repos\nextdc-ipam\mcp\.venv\Scripts\ipam-mcp.exe"
     ```

   - **Claude Desktop**: add this to `%APPDATA%\Claude\claude_desktop_config.json` under `mcpServers`, then restart Claude Desktop:

     ```json
     "ipam": {
       "command": "C:\\Users\\Craig.McDonald\\source\\repos\\nextdc-ipam\\mcp\\.venv\\Scripts\\ipam-mcp.exe"
     }
     ```

IPAM has to be running (`docker compose up -d` in the repo root).

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
