# Instagram DM MCP server

This is a Model Context Protocol (MCP) server for sending instagram Direct Messages.

With this you can send Instagram Direct Messages from your account (more capabilities coming soon).

Here's an example of what you can do when it's connected to Claude.


https://github.com/user-attachments/assets/9c945f25-4484-4223-8d6b-5bf31243464c


> To get updates on this and other projects we work on [enter your email here](https://tally.so/r/np6rYy)

---

## Installation

### Prerequisites

- Python 3.11+
- Anthropic Claude Desktop app (or Cursor)
- Pip (Python package manager), install with `python -m pip install`
- An instagram account

### Steps

1. **Clone this repository**

   ```bash
   git clone https://github.com/trypeggy/instagram_dm_mcp.git
   cd instagram_dm_mcp
   ```

2. **Install dependencies**

  - Using uv (recommended):
    ```bash
    uv sync
    ```
  - Using Pip:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Instagram credentials**

   You have two options for providing your Instagram credentials:

   **Option A: Environment Variables (Recommended)**
   
   **Quick Setup (Recommended):**
   
   Run the helper script:
   
   ```bash
   python setup_env.py
   ```
   
   This will interactively prompt you for your credentials and create the `.env` file securely.
   
   **Manual Setup:**
   
   Create a `.env` file in the project root:
   
   ```bash
   cp env.example .env
   ```
   
   Then edit `.env` with your actual credentials:
   
   ```
   INSTAGRAM_USERNAME=your_instagram_username
   INSTAGRAM_PASSWORD=your_instagram_password
   ```
   
   **Option B: Command Line Arguments**
   
   You can still pass credentials as command line arguments (less secure).

4. **Connect to the MCP server**

   **For Claude Desktop:**
   
   Save this as `claude_desktop_config.json` in your Claude Desktop configuration directory at:

   ```
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

   **For Cursor:**
   
   Save this as `mcp.json` in your Cursor configuration directory at:

   ```
   ~/.cursor/mcp.json
   ```

   **Configuration with Environment Variables (Recommended):**
   - Using uv
   
   ```json
   {
     "mcpServers": {
       "instagram_dms": {
           "command": "uv",
           "args": [
             "run",
             "--directory",
             "PATH/TO/instagram_dm_mcp",
             "python",
             "src/mcp_server.py"
           ]
        }
      }
    }
   ```

   - Using Python
    ```json
    {
      "mcpServers": {
        "instagram_dms": {
          "command": "python",
          "args": [
            "{{PATH_TO_SRC}}/instagram_dm_mcp/src/ mcp_server.py"
          ]
        }
      }
    }
    ```

   **Configuration with Command Line Arguments:**
   
   ```json
   {
     "mcpServers": {
       "instagram_dms": {
         "command": "python",
         "args": [
           "{{PATH_TO_SRC}}/instagram_dm_mcp/src/mcp_server.py",
           "--username",
           "{{YOUR_INSTAGRAM_USERNAME}}",
          "--password",
          "{{YOUR_INSTAGRAM_PASSWORD}}"
         ]
       }
     }
   }
   ```

5. **Restart Claude Desktop / Cursor**
   
   Open Claude Desktop and you should now see the Instagram DM MCP as an available integration.

   Or restart Cursor.
---

## Transports

The server speaks **stdio** (default) and **streamable-http**; legacy **sse** is also available.
Every flag has an environment-variable equivalent.

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `--transport` | `MCP_TRANSPORT` | `stdio` | `stdio`, `streamable-http`, or `sse` |
| `--host` | `MCP_HOST` | `127.0.0.1` | HTTP transports only |
| `--port` | `MCP_PORT` | `8000` | HTTP transports only |
| `--path` | `MCP_PATH` | `/mcp` (`/sse` for sse) | Endpoint mount path |
| — | `MCP_AUTH_TOKEN` | unset | Bearer token callers must present. **Required** for any non-loopback bind |

Run it over HTTP:

```bash
python src/mcp_server.py --transport streamable-http --port 8000
# → serving at http://127.0.0.1:8000/mcp
```

Then point a client at the URL instead of spawning a subprocess:

```json
{
  "mcpServers": {
    "instagram_dms": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

**Mind the trailing slash.** The endpoint is `/mcp`; `/mcp/` answers `307 Temporary
Redirect`. Clients that don't follow redirects on POST report that as a connection
failure, so use the exact path.

### Authenticating callers

MCP has no caller authentication of its own, and this server holds a live Instagram
session — so anything that can reach the port can read every DM and send messages as the
account, with no Instagram credential of its own. A bind to `0.0.0.0` plus an ingress
route is enough to put that on the public internet.

So the server **refuses to start on a non-loopback address without `MCP_AUTH_TOKEN`**:

```bash
MCP_AUTH_TOKEN=$(openssl rand -hex 32) python src/mcp_server.py \
  --transport streamable-http --host 0.0.0.0
```

Callers then send `Authorization: Bearer <token>`; anything else gets a 401. Binding to
`127.0.0.1` without a token still works for local use, with a warning.

```json
{
  "mcpServers": {
    "instagram_dms": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer <your token>" }
    }
  }
}
```

---

## Docker

The image defaults to `streamable-http` on port 8000, since stdio can't be reached from
outside a container.

```bash
docker build -t instagram-dm-mcp .
```

Session state and rate-limit counters are both written under `$HOME`, which the image
points at `/data`. Mount a volume there so a sign-in survives container restarts —
without it, every restart requires a fresh login (and repeated logins is exactly what
gets Instagram accounts flagged). The volume has to be writable by uid 10001: if the
counters can't be written, rate-limited tools block rather than run uncounted, since
the in-memory tally can't see what another container on the same volume has spent.

**1. Sign in once** — interactive, because Instagram may prompt for a 2FA code:

```bash
docker run -it --rm -v ig-mcp-data:/data instagram-dm-mcp auth.py
```

**2. Run the server:**

```bash
docker run -d --name instagram-dm-mcp \
  -p 127.0.0.1:8000:8000 \
  -e MCP_AUTH_TOKEN="$(openssl rand -hex 32)" \
  -v ig-mcp-data:/data \
  instagram-dm-mcp
```

Point your client at `http://127.0.0.1:8000/mcp` (see the trailing-slash note above).

The image binds `0.0.0.0` inside the container, so **`MCP_AUTH_TOKEN` is required** — the
container exits at startup without one. Publishing as `-p 127.0.0.1:8000:8000` rather than
`-p 8000:8000` additionally keeps the port off your network.

Transport settings are read from the environment, so they can be overridden per run:

```bash
docker run -d -e MCP_PORT=9000 -p 127.0.0.1:9000:9000 -v ig-mcp-data:/data instagram-dm-mcp
```

### Signing in without a terminal

A container has nobody to type a 2FA code at it, so signing in is part of the server
rather than a separate interactive script. **The server always starts**, with or without
a usable session. If it can't sign in, it stays up and says so instead of exiting — a
server that exits gets restarted by Docker or Kubernetes, and the retried login every few
minutes is what gets accounts flagged.

While signed out, Instagram tools return `Not signed in to Instagram (needs_2fa): …` and
two tools stay available to fix it:

- `instagram_auth_status` — the current state and the next step to take.
- `instagram_login` — performs the sign-in, taking `verification_code` for 2FA.

So the flow through any MCP client is just a conversation:

> **You:** check the instagram auth status
> **Claude:** It needs a 2FA code — what does your authenticator app show?
> **You:** 481920
> **Claude:** *(calls `instagram_login` with the code)* Signed in as @you.

**No credential ever passes through the agent.** Everything that grants access to the
account — password, session cookie, TOTP seed — is read from the server's own
environment, listed below. The only thing a tool ever accepts is a 2FA code, which is
single-use and dead within about 30 seconds, and worthless without the password it
never sees.

| Env var | What it is | Why it's server-side |
|---------|-----------|----------------------|
| `INSTAGRAM_USERNAME` / `INSTAGRAM_PASSWORD` | The account credentials | Full account access |
| `INSTAGRAM_TOTP_SEED` | Authenticator-app seed | Mints codes forever; equivalent to owning the second factor |
| `INSTAGRAM_SESSIONID` | Cookie from a signed-in browser | Long-lived bearer token for the whole account |

The session is written to the volume, so this is a one-time step, not something you
repeat on every restart.

**Fully headless:** if the account's 2FA is an authenticator app, put its seed in
`INSTAGRAM_TOTP_SEED` and the server generates its own code at login — no human at all,
including after a session expires. Paste the seed however Instagram gives it to you; the
spaced groups of four and any case are normalised before use.

### When 2FA is an approve-on-device push

Some accounts don't get a code at all — Instagram sends a notification to a phone that is
already signed in and asks you to approve or deny it. There is no code to type, and the
login API has no way to wait for the tap, so `instagram_login` cannot complete. Three ways
through, best last:

1. **A backup code.** In the app: Accounts Center → Password and security → Two-factor
   authentication → your account → Additional methods → Backup codes. Pass one of the
   8-digit codes as `verification_code` to `instagram_login`. Each works once.
2. **A browser session, handed to the server.** Sign in at instagram.com, approve the
   push, copy the `sessionid` cookie (DevTools → Application → Cookies), and set it as
   `INSTAGRAM_SESSIONID` in the server's own environment — the same place the password
   lives. The server adopts it at startup and writes a durable session to the volume, so
   the variable can be removed afterwards.
3. **Add an authenticator app** as a second 2FA method and set `INSTAGRAM_TOTP_SEED`.
   This is the only option that survives a session expiry unattended, so it's the one
   worth doing for an always-on deployment.

**Failed logins are not retried.** A failure only a human can clear (2FA, wrong password,
a challenge) is recorded in `login_blocked.json` next to the session, and later starts
refuse to attempt another login rather than contacting Instagram — calling
`instagram_login`, or running `auth.py`, clears it. A valid session file takes precedence,
so a stale marker never blocks a working server.

`auth.py` still exists for signing in from a terminal, and is the better option locally:

```bash
docker run -it --rm -v ig-mcp-data:/data instagram-dm-mcp auth.py
```

### Volume permissions

The container runs as uid 10001. A Docker named volume inherits ownership from the image
and just works, but a mount that arrives root-owned — a bind mount of a host directory, or
a freshly provisioned Kubernetes PV — does not, and the first session write fails with
`PermissionError: [Errno 13] Permission denied: '/data/.instagram_dm_mcp'`.

For a bind mount, run as the owning user:

```bash
docker run --user "$(id -u):$(id -g)" -v "$PWD/data:/data" instagram-dm-mcp
```

On Kubernetes, set `fsGroup` so the kubelet chowns the volume at mount time:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
```

---

## Usage

Below is a list of all available tools and what they do:

| Tool Name                   | Description                                                                                   |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| `instagram_auth_status`     | Report whether the server is signed in, and what it needs if not. Always available.            |
| `instagram_login`           | Sign in, optionally completing 2FA with a code the user reads off their phone. Always available. |
| `send_message`              | Send a direct message, to a user by username or into a thread by `thread_id` (groups included). |
| `reply_to_message`          | Send a quote reply to a specific message in a thread, rendered with the original quoted above it. |
| `send_photo_message`        | Send a photo as an Instagram direct message to a user by username.                            |
| `send_video_message`        | Send a video as an Instagram direct message to a user by username.                            |
| `list_chats`                | Get Instagram Direct Message threads (chats) from your account, with optional filters/limits.  |
| `list_messages`             | Get messages from a specific Instagram Direct Message thread by thread ID. Now exposes `item_type` and shared post/reel info for each message. Use this to determine which download tool to use. |
| `download_media_from_message` | Download a direct-uploaded photo or video from a DM message (not for shared posts/reels/clips). |
| `download_shared_post_from_message` | Download media from a shared post, reel, or clip in a DM message (not for direct uploads). |
| `list_media_messages`       | List all messages containing direct-uploaded media (photo/video) in a DM thread.              |
| `mark_message_seen`         | Mark a specific message in an Instagram Direct Message thread as seen.                         |
| `react_to_message`          | React to a message with an emoji (defaults to the heart, i.e. Instagram's double-tap like).    |
| `remove_message_reaction`   | Remove your own emoji reaction from a message.                                                 |
| `delete_message`            | Delete a message from a direct message thread.                                                 |
| `mute_conversation`         | Mute or unmute a direct message conversation.                                                  |
| `hide_chat`                 | Remove a chat from your inbox (Instagram's "Delete"), optionally filing it under hidden requests. |
| `check_user_online_status`  | Check the online status of Instagram users.                                                    |
| `list_pending_chats`        | Get Instagram Direct Message threads from your pending inbox.                                  |
| `search_threads`            | Search Instagram Direct Message threads by username or keyword.                                |
| `get_thread_by_participants`| Get an Instagram Direct Message thread by participant user IDs.                                |
| `get_thread_details`        | Get details and messages for a specific Instagram Direct Message thread by thread ID.          |
| `get_user_id_from_username` | Get the Instagram user ID for a given username.                                                |
| `get_username_from_user_id` | Get the Instagram username for a given user ID.                                                |
| `get_user_info`             | Get information about a specific Instagram user by username.                        |
| `search_users`              | Search for Instagram users by username                                              |
| `get_user_stories`          | Get recent stories from a specific Instagram user by username.                                  |
| `like_media`               | Like or unlike a specific media post by media ID.                                                       |
| `get_user_followers`        | Get a list of followers for a specific Instagram user by username.                             |
| `get_user_following`        | Get a list of users that a specific Instagram user is following by username.                   |
| `get_user_posts`            | Get recent posts from a specific Instagram user by username.                                   |


---

## Troubleshooting

**Instagram Login Hanging:** The server now includes automatic session management to prevent login hangs. Session files (e.g., `username_session.json`) are automatically created and reused to maintain authentication state between runs.

For additional Claude Desktop integration troubleshooting, see the [MCP documentation](https://modelcontextprotocol.io/quickstart/server#claude-for-desktop-integration-issues). The documentation includes helpful tips for checking logs and resolving common issues.

---

## Feedback

Your feedback will be massively appreciated. Please [tell us](mailto:tanmay@usegala.com) which features on that list you like to see next or request entirely new ones.

---

## License

This project is licensed under the MIT License.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12+-green.svg)
