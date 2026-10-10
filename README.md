# pi-poppy

Version 0.1.0. Personal Agent Protocol (Poppy) for the [pi](https://github.com/earendil-works/pi) coding agent. A personal agent discovers a company, opens a signed-out session, signs the user in, calls the company's APIs, and talks to its company agent. This package is the personal-agent side that pi loads. The conformance tests include their own company peer. There is no `pi-poppy` command.

The implementation follows [Personal Agent Protocol draft 0.1](https://personalagentprotocol.org/) as published on 9 October 2026. The site has no JSON Schema, no official conformance suite, and no published reference implementation. The checklist in `src/requirements.ts` is this package's reading of every MUST, SHOULD, and MAY on the spec, extensions, and guides pages. Payments, push notifications, and attachments are open topics and are not part of this draft.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in BCP 14 (RFC 2119 and RFC 8174).

## Install

pi 1.0.1 loads this package from the `pi.extensions` field. Node 22 or newer is required.

```bash
pi install npm:pi-poppy
```

From a checkout:

```bash
npm install
pi -e ./index.ts
npm test
npm run typecheck
```

## First load

Loading the extension creates `~/.pi/poppy.json` (mode 0600) when that file is missing. The file holds the agent's signing key, one stable user id per company, one DPoP key per user per company, account tokens, and standing permissions. The first load also creates a `client_id` and serves that metadata document on `127.0.0.1` for as long as pi is running. Later loads keep the same URL and port. Tool results do not include those secrets.

A company downloads that `client_id` before it will open a session. `jwks_uri` and `redirect_uris` are HTTPS on the same host. A company on another machine cannot fetch `127.0.0.1`. The tests serve their own company and metadata. `PI_POPPY_STORE`, `PI_POPPY_ALLOW_LOOPBACK`, and `PI_POPPY_CA` exist for those tests. A public company is reached with the system trust store, and loopback is refused.

## Tools

Each tool that uses a session takes `domain`, so more than one company can be open. There are no slash commands.

| Tool | Parameters | What it does |
| --- | --- | --- |
| `poppy_discover` | `domain` | Read the company's protocol document. |
| `poppy_session_start` | `domain` | Start a signed-out session for that domain. |
| `poppy_session_status` | `domain` optional | Describe one session, or every open session when `domain` is omitted. Tokens are omitted. |
| `poppy_sign_in` | `domain`, `scope`, `method` optional (`auto`, `direct`, `device`, or `mediated`) | Direct, then device, then mediated sign-in. Passwords are collected in pi's own UI. |
| `poppy_sign_out` | `domain` | Revoke that domain's account token. |
| `poppy_api_call` | `domain`, `path`, `body` optional | Call an OpenAPI endpoint on the company origin with a DPoP session token. |
| `poppy_conversation_send` | `domain`, `sender` (`agent` or `human`), `text` optional, `data` optional, `locale` optional, `time_zone` optional, `user_available` optional | Send a message. `sender` is `human` only for the user's own words. |
| `poppy_conversation_read` | `domain`, `wait` optional | Read events. A gap is reported when the cursor has expired. |
| `poppy_conversation_handoff` | `domain` | Hand the conversation to a person. |
| `poppy_conversation_close` | `domain` | Close the conversation. |
| `poppy_direct_conversation` | `domain`, `text` | Open the one direct child of a parent conversation. |
| `poppy_operation_show` | `domain`, `operation_id` | Read an operations-extension proposal. |
| `poppy_operation_confirm` | `domain`, `operation_id` | Confirm the latest revision after the user accepts the company's name and summary, or after a standing permission covers it. |
| `poppy_operation_cancel` | `domain`, `operation_id` | Cancel a proposal. |
| `poppy_permission` | `domain`, `action`, `max_amount` optional, `currency` optional, `max_uses` optional | Store a standing permission the user accepted in pi's UI. |
| `poppy_mcp_connect` | `domain` | Register the company's MCP servers on pi. |
| `poppy_browser_join` | `domain`, `url` | Post a browser-session assertion from the agent's own cookie jar. `url` is an HTTPS page on the company domain. |

## Examples

Each example is a local HTTPS company with its own certificate. That certificate is not the agent's. Set `PI_POPPY_CA` to the company CA the process prints, and `PI_POPPY_ALLOW_LOOPBACK=1`, before the agent fetches it. Set `TODO_AGENT_CA` to the agent's CA (`localIdentity.ca` in the secret file) so the company can download `client_id`.

| Directory | What it publishes |
| --- | --- |
| `examples/simple_website` | `web` only. No sign-in and no session. |
| `examples/todo_website` | A website with in-memory users and todos, plus an OAuth issuer so an agent can start a signed-out session. Website login is separate from that session. |
| `examples/todos_api` | An OpenAPI document. `poppy_api_call` lists, adds, and completes todos for the agent's user id. |
| `examples/todos_mcp` | An MCP endpoint. `poppy_mcp_connect` registers `list_todos`, `add_todo`, and `complete_todo`. |

```bash
node --experimental-strip-types examples/simple_website/server.ts
TODO_AGENT_CA=agent-ca.pem node --experimental-strip-types examples/todo_website/server.ts
TODO_AGENT_CA=agent-ca.pem node --experimental-strip-types examples/todos_api/server.ts
TODO_AGENT_CA=agent-ca.pem node --experimental-strip-types examples/todos_mcp/server.ts
```

## MCP

pi 1.0.1 already ships an MCP client. This extension uses that client and does not open a second one.

Company MCP APIs are handed to `pi.registerMcpServer`. The config is an HTTP server whose `Authorization` header is a PAP bearer session token. The token's `resource` is the MCP URL, and it is minted without a DPoP proof, which is what the protocol requires for MCP. `exposure` is `direct`, so the model sees tools named `mcp__<server>__<tool>`. The server name contains no `oauth` field: pi runs its own OAuth client only when that field is set and no `Authorization` header is present. PAP clients must present the session token the company issued, so pi's OAuth flow is the wrong client for this API. Call `poppy_mcp_connect` again for that domain when the bearer expires; registration replaces the server config.

Everything else stays a pi tool:

- Conversations, OpenAPI calls, DPoP proofs, and browser-session assertions are PAP messages, not MCP tools.
- Sign-in and operation approval have to use `ctx.ui`. An MCP tool result cannot collect a password or show the company's summary for a yes/no answer.
- Account tokens and session tokens must not enter the model context. The bearer sent to pi is a short-lived MCP access token, and the extension's own tool results strip `st1_` and `pat_` values.

The extension does not subscribe to `mcp_servers_change` and does not register `/mcp`. Subscribing would replace pi's built-in MCP connector.

## Readings

Where the draft leaves a choice, this build does the following.

- The major version is the integer before the dot. Major version 0 is supported. Any 0.x minor is accepted. Unknown fields are ignored.
- `www.` is stripped once from the left when `organization.domain` is compared with the requested hostname.
- The company rejects a session or client assertion whose `exp - iat` is greater than 120 seconds. A browser assertion must be 60 seconds or shorter.
- `wait` and `cursor` are query parameters.
- Mediated sign-in returns HTTP 200 with `status` of `complete`, `code_required`, `failed`, or `expired`. HTTP 429 is the rate limit. HTTP 400 is a malformed body. An unknown account and a bad password both return `failed`.
- Bearer tokens are accepted only on the MCP API, and only when `resource` is that API's URL. DPoP is required on every other API. The MCP endpoint rejects a DPoP `Authorization` scheme.
- The first signed-in request binds a conversation to an account. A later signed-out token gets `sign_in_required`. The wrong client or user gets `conversation_not_found`.
- A session does not switch accounts. Signing out leaves the binding in place. A different account is `account_mismatch`. Sessions stay open across sign-out unless the company was started with `endSessionsOnSignOut`.
- A signed-out token stays signed out even if the session later signs in. After sign-out, a token that was signed in is treated as signed out.
- Direct sign-in uses PKCE S256. The `plain` method is rejected. Device verification GET does not approve the request. Polling faster than `interval` returns `slow_down` and adds 5 seconds.
- Publishers use the extension name `operations` or a name that starts with a domain they control. Receivers still parse other names and ignore extensions they do not implement.
- The DPoP nonce is one current value per company, not a rotating list. A proof rejected for a bad nonce can be retried. A client-assertion `jti` is consumed even when the DPoP check fails, so the retry mints a new assertion.
- `user_approval_required` is set when `terms.price_difference.amount` is at least 50.
- Confirming an operation that is no longer `proposed` returns the current record and does not perform it again. `terms_changed` is HTTP 409 and includes the new operation.
- Message idempotency is keyed by user id and message id. The same content returns the original result. Different content is HTTP 409 `message_id_conflict`.
- Loopback HTTPS is refused unless `allowLoopback` is set.
- The browser session in tests is the agent's cookie jar and a form POST. A graphical browser is not bundled.
- Account tokens are protected by the secret file's mode 0600. There is no second encryption layer.
- One DPoP key is kept per user per company. The spec allows a new key per session; this build does not rotate one.
- An operator can block a `client_id`. There is no automatic detector that revokes an agent for a false approval claim.

## Spec compliance

Draft 0.1, site updated 9 October 2026. All 143 requirements are met. Notes on five of them are in the requirement text below and in `src/requirements.ts`.

| ID | Level | Section | Requirement | Status | Test |
| --- | --- | --- | --- | --- | --- |
| S001 | MUST | 1 | The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in BCP 14 (RFC 2119 and RFC 8174). | met | unit.test.ts |
| S002 | MUST | 3 | A company publishes poppy.json at https://{domain}/.well-known/poppy.json over HTTPS. | met | e2e.test.ts, conformance.test.ts |
| S003 | MAY | 3 | The well-known URL may redirect to where the document is hosted. | met | conformance.test.ts |
| S004 | MUST | 3 | Personal agents follow redirects, and every redirect is to an HTTPS URL. | met | unit.test.ts |
| S005 | SHOULD | 3 | Personal agents cache poppy.json according to its HTTP caching headers. | met | conformance.test.ts |
| S006 | MUST NOT | 3 | A personal agent does not use a document whose major version it does not support. | met | conformance.test.ts |
| S007 | MUST | 3 | organization.domain matches the requested host, ignoring one leading www. | met | conformance.test.ts |
| S008 | MAY | 3 | An API entry may include resource to require tokens issued for it. | met | schema.test.ts |
| S009 | MAY | 3 | A conversation protocol entry may include resource to require tokens issued for it. | met | schema.test.ts |
| S010 | MAY | 3.2 | Several domains may name the same issuer and then share user ids, sessions, and account tokens. | met | conformance.test.ts |
| S011 | MUST | 3.2 | The issuer publishes OAuth authorization server metadata, and poppy_domains lists every domain whose poppy.json uses that issuer. | met | conformance.test.ts |
| S012 | MUST | 3.2 | Before using poppy.json, the agent checks that metadata issuer matches auth.issuer and poppy_domains includes organization.domain. | met | conformance.test.ts |
| S013 | MAY | 3.2 | OAuth metadata may include other fields, which agents ignore. | met | conformance.test.ts |
| S014 | SHOULD | 3.2 | Agents cache OAuth metadata according to its HTTP caching headers. | met | conformance.test.ts |
| S015 | MUST | 3.3 | Extension names are operations or start with a domain the publisher controls. | met | conformance.test.ts |
| S016 | MUST | 3.3 | Both sides ignore extensions they do not support and fields they do not recognize. | met | conformance.test.ts |
| S017 | MAY | 3.3 | A company may refuse a request that needs an extension the agent does not list, with extension_required. | met | conformance.test.ts |
| S018 | MAY | 4 | Companies may limit what an agent can do in a session, signed in or out. | met | conformance.test.ts |
| S019 | MUST | 4.1 | client_id is an HTTPS URL that returns the client metadata document. | met | schema.test.ts |
| S020 | MUST | 4.1 | client_id equals the URL the metadata document was fetched from. | met | schema.test.ts |
| S021 | MUST | 4.1 | jwks_uri and every redirect_uri are HTTPS URLs on the same domain as client_id. | met | schema.test.ts |
| S022 | MAY | 4.1 | Companies may require agents to register ahead of time. | met | conformance.test.ts |
| S023 | MAY | 4.1 | Companies may keep allowlists or blocklists and revoke a misusing client_id. | met | conformance.test.ts |
| S024 | MAY | 4.1 | Companies may rate-limit session creation. | met | conformance.test.ts |
| S025 | MAY | 4.1 | A company that does not require registration may limit how many new client_id values it accepts. | met | conformance.test.ts |
| S026 | MUST | 4.2 | The agent gives each user a stable user id per company, identified by auth.issuer. | met | conformance.test.ts |
| S027 | MUST NOT | 4.2 | A user id does not contain or derive from personal information, even with a keyed hash. | met | unit.test.ts |
| S028 | MUST | 4.2 | expires_in is greater than 0. | met | conformance.test.ts |
| S029 | SHOULD | 4.2 | Session tokens last hours, not days. | met | conformance.test.ts |
| S030 | MUST NOT | 4.2 | Agents do not depend on session token contents. | met | conformance.test.ts |
| S031 | MAY | 4.2 | A company may embed its own session credentials in a token. | met | conformance.test.ts |
| S032 | MUST | 4.2 | Embedded session credentials are encrypted. | met | conformance.test.ts |
| S033 | MAY | 4.3 | The agent may use a new DPoP key for each session. This build keeps one key per user per company.  One DPoP key is kept per user per company. A new key per session is allowed by the spec and is not required. | met | conformance.test.ts |
| S034 | MUST | 4.3 | The company checks the DPoP signature, key binding, htm, htu, iat window, jti replay, and ath. | met | conformance.test.ts |
| S035 | MAY | 4.3 | A company may require a DPoP nonce so proofs cannot be made in advance. | met | conformance.test.ts |
| S036 | MUST | 4.3 | Agents support DPoP nonces and retry once with a new proof. | met | conformance.test.ts |
| S037 | MUST | 4.3 | An MCP bearer token is obtained without a DPoP proof and with resource set to the MCP URL. | met | conformance.test.ts |
| S038 | MUST | 4.3 | Companies accept bearer session tokens only on MCP APIs and require DPoP everywhere else. | met | conformance.test.ts |
| S039 | MUST | 4.3 | Companies accept the session token in Authorization without requiring cookies. | met | conformance.test.ts |
| S040 | MUST | 4.3 | Agents send a session token on every API and conversation request and do not omit it to look like a person. | met | e2e.test.ts, conformance.test.ts |
| S041 | MUST | 4.3 | After a new session token is issued, the agent uses that token from then on. | met | conformance.test.ts |
| S042 | MUST NOT | 4.3 | Agents do not send tokens in a URL, and companies do not accept them from one. | met | unit.test.ts, conformance.test.ts |
| S043 | MUST | 4.3 | On HTTP 429 the agent waits at least Retry-After before sending the request again. | met | conformance.test.ts |
| S044 | MUST | 4.4 | Direct and device sign-in are used only when the user signs in themselves. | met | extension.test.ts, conformance.test.ts |
| S045 | MAY | 4.4 | Companies may revoke the client_id of an agent that misuses sign-in. | met | conformance.test.ts |
| S046 | MAY | 4.4 | Companies may define custom scopes and describe them in auth.custom_scopes. | met | conformance.test.ts |
| S047 | MAY | 4.4 | A company may omit poppy:read and poppy:write and offer only narrower scopes. | met | conformance.test.ts |
| S048 | MUST NOT | 4.4 | The company does not grant scopes beyond those requested and allowed for the sign-in type. | met | conformance.test.ts |
| S049 | MUST | 4.4 | Each sign-in request includes scope as a space-separated OAuth scope string. | met | conformance.test.ts |
| S050 | SHOULD | 4.4 | After step-up, the new account token replaces the old one and the agent revokes the old token. | met | conformance.test.ts |
| S051 | SHOULD | 4.4 | Before starting sign-in, the agent checks whether an account token already covers the task. | met | conformance.test.ts |
| S052 | MUST | 4.5 | redirect_uri exactly matches an entry in the agent's redirect_uris. | met | conformance.test.ts |
| S053 | MUST | 4.5 | The agent checks that iss exactly matches the auth.issuer of the company that started sign-in. | met | conformance.test.ts |
| S054 | MUST NOT | 4.6 | Opening the device verification link does not approve the request. | met | conformance.test.ts |
| S055 | MUST | 4.7 | Secret mediated fields are not shown back, logged, or sent anywhere else. | met | conformance.test.ts |
| S056 | MUST | 4.7 | Mediated sign-in is rate-limited, does not return credentials, and uses a one-time code when a sign-in looks unusual. | met | conformance.test.ts |
| S057 | MUST NOT | 4.7 | Agents send credentials only to auth.mediated.endpoint. | met | conformance.test.ts |
| S058 | MUST | 4.8 | Account tokens are accepted only at the token and revocation endpoints, and only from the issuing client. | met | conformance.test.ts |
| S059 | MUST | 4.8 | A refreshed session belongs to the same client_id and user id, and to the same account when one is already bound. | met | conformance.test.ts |
| S060 | MAY | 4.8 | Refresh may ask for fewer scopes than the account token has, and cannot increase scope. | met | conformance.test.ts |
| S061 | MAY | 4.8 | A company may return a new account token in refresh_token. | met | conformance.test.ts |
| S062 | MUST | 4.8 | When a new account token is returned, the agent uses it from then on. | met | conformance.test.ts |
| S063 | MUST | 4.8 | Account tokens are stored as secrets and are not put in model context, messages, logs, or URLs. | met | extension.test.ts, conformance.test.ts |
| S064 | MAY | 4.9 | A company may end sessions on sign-out. | met | conformance.test.ts |
| S065 | SHOULD | 4.9 | Companies check on each request whether the session is still signed in. | met | conformance.test.ts |
| S066 | SHOULD | 4.9 | A company that does not check sign-in per request uses much shorter session token lifetimes. This build checks per request.  The company checks the live session on each request, so the shorter-lifetime alternative is not used. | met | conformance.test.ts |
| S067 | MUST | 5 | When a browser session endpoint is published, the agent joins its browser to the session before browsing. | met | conformance.test.ts |
| S068 | MUST | 5 | return_to is an HTTPS URL on the company domain or a subdomain. | met | conformance.test.ts |
| S069 | MUST | 5 | The browser assertion is in the request body, never in the URL. | met | conformance.test.ts |
| S070 | MUST | 5 | The assertion is posted from a browser the agent controls, not the user's browser.  The agent posts the assertion with its own cookie jar. A graphical browser is not bundled. | met | conformance.test.ts |
| S071 | MUST | 5 | The company verifies the browser assertion signature, typ, audience, 60 second lifetime, jti, session owner, and return_to. | met | conformance.test.ts |
| S072 | MUST | 5 | The browser cookie follows the session's current sign-in state. | met | conformance.test.ts |
| S073 | MUST NOT | 5 | The browser cookie does not outlive the session. | met | conformance.test.ts |
| S074 | MUST | 5 | The browser cookie is Secure and HttpOnly, with SameSite Lax or None. | met | conformance.test.ts |
| S075 | MAY | 5 | The agent may post a new browser assertion when the website no longer recognizes the session. | met | conformance.test.ts |
| S076 | MUST | 6 | Each API type a company publishes here is openapi or mcp. | met | conformance.test.ts |
| S077 | SHOULD | 6 | Agents skip API types they do not recognize. | met | conformance.test.ts |
| S078 | MUST | 6 | Every listed API accepts session tokens: DPoP for OpenAPI and bearer for MCP. | met | conformance.test.ts |
| S079 | MUST | 6 | A listed MCP server accepts session tokens as its access tokens and enforces their scopes. | met | conformance.test.ts |
| S080 | MUST | 6 | An MCP server accepts only tokens issued for its url. | met | conformance.test.ts |
| S081 | MUST | 6 | Protected resource metadata authorization_servers includes auth.issuer. | met | conformance.test.ts |
| S082 | MUST | 7 | The company rejects conversation requests from any other client_id, user, or account. | met | conformance.test.ts |
| S083 | SHOULD | 7.1 | Identifiers start with a short prefix such as cnv_, msg_, or evt_. | met | conformance.test.ts |
| S084 | MUST NOT | 7.1 | The receiver does not depend on the sender's identifier format. | met | conformance.test.ts |
| S085 | MUST | 7.2 | A message has at least one of text, data, or context. | met | conformance.test.ts |
| S086 | SHOULD NOT | 7.2 | Agents do not put JSON or other markup in text. | met | conformance.test.ts |
| S087 | MUST | 7.2 | locale, time_zone, and user_available use the formats defined by the spec. | met | conformance.test.ts |
| S088 | MAY | 7.2 | context may include other fields. | met | conformance.test.ts |
| S089 | MAY | 7.2 | A company may ignore context fields it does not understand. | met | conformance.test.ts |
| S090 | SHOULD | 7.2 | Agents share only the context the task needs. | met | extension.test.ts, conformance.test.ts |
| S091 | MUST | 7.3 | Agents skip event types they do not recognize. | met | conformance.test.ts |
| S092 | MUST NOT | 7.4 | Cursors are opaque. Agents do not compare or sort them. | met | conformance.test.ts |
| S093 | MAY | 7.4 | A company may return a read before wait elapses, or cap wait. | met | conformance.test.ts |
| S094 | MUST | 7.4 | Every successful read includes cursor, has_more, status, and responder. | met | conformance.test.ts |
| S095 | SHOULD | 7.5 | On cursor_expired the agent tells the user that part of the conversation is missing. | met | conformance.test.ts |
| S096 | MAY | 7.6 | A company may stream events with server-sent events. | met | conformance.test.ts |
| S097 | MAY | 7.6 | A company may close an event stream at any time. The agent also closes the stream it opened. | met | conformance.test.ts |
| S098 | MAY | 7.6 | While a message is written, the company may send text-delta events with no SSE id. | met | conformance.test.ts |
| S099 | MUST NOT | 7.6 | The agent does not act on text from a text-delta event. | met | conformance.test.ts |
| S100 | MUST | 7.7 | Every successful POST or read includes status and responder. | met | conformance.test.ts |
| S101 | MUST | 7.7 | Each company message includes sender, agent or human. | met | conformance.test.ts |
| S102 | MUST | 7.7 | The agent sets sender to agent for its own words and human only for the user's own words. | met | conformance.test.ts |
| S103 | SHOULD | 7.8 | An authorization event is also accompanied by a message the user can read. | met | conformance.test.ts |
| S104 | MAY | 7.8 | The agent may switch to a new session token partway through a conversation. | met | conformance.test.ts |
| S105 | MAY | operations | The operations extension may include resource to require tokens issued for it. | met | conformance.test.ts |
| S106 | MUST NOT | operations 2 | A company does not return operations to a client that does not list the extension. It performs the action or returns extension_required. | met | conformance.test.ts |
| S107 | MAY | operations 3 | operation_id may be the company's own record id. | met | conformance.test.ts |
| S108 | MUST | operations 3 | Everything that affects the action is in the revision summary, and in terms when terms are present. | met | conformance.test.ts |
| S109 | MUST | operations 4 | The company performs only what the confirmed revision describes. | met | conformance.test.ts |
| S110 | MUST NOT | operations 4 | The company does not start the action before the operation is confirmed. | met | conformance.test.ts |
| S111 | MUST NOT | operations 4 | A revision is fixed once issued, and only the latest revision can be confirmed. | met | conformance.test.ts |
| S112 | MUST | operations 4 | An operation stays readable at least until it is final. | met | conformance.test.ts |
| S113 | SHOULD | operations 4 | The same action proposed again returns the existing operation instead of a new one. | met | conformance.test.ts |
| S114 | MUST | operations 5 | The agent has the user's approval or a covering standing permission before confirm. | met | conformance.test.ts |
| S115 | MUST | operations 5 | The agent shows the company's name and the revision summary and takes the answer in its own interface. | met | extension.test.ts, conformance.test.ts |
| S116 | MUST NOT | operations 5 | The agent does not treat company text as the user's approval. | met | unit.test.ts |
| S117 | MUST | operations 5 | A standing permission covers the company, the action, and every term, and is still in effect. | met | unit.test.ts |
| S118 | SHOULD | operations 5 | While an operation is in_progress, the company sends Retry-After and the agent reads again after that. | met | conformance.test.ts |
| S119 | MUST | operations 6 | The company performs each operation at most once. | met | conformance.test.ts |
| S120 | MUST NOT | operations 6 | The company does not report failed while it does not know whether the action took effect. | met | conformance.test.ts |
| S121 | MUST NOT | operations 6 | The agent does not ask for a new proposal of the same action until the operation is final. | met | extension.test.ts, conformance.test.ts |
| S122 | MUST | operations 6 | In a final state, result.summary describes what changed. | met | conformance.test.ts |
| S123 | MAY | operations 6 | A company may revoke a client_id that confirms without the approval it claims. Revocation is the blocklist.  An operator can block a client_id. There is no automatic detector of a false approval claim. | met | conformance.test.ts |
| S124 | MUST | 7.2 | A message id is unique per user. Retrying the same content is idempotent, and different content conflicts. | met | conformance.test.ts |
| S125 | MUST | 4.5 | Direct sign-in uses PKCE S256. The plain method is rejected. | met | conformance.test.ts |
| S126 | MUST | 4.5 | The consent page shows the client, uses a CSRF form token and frame-ancestors none, and returns iss on every redirect. | met | conformance.test.ts |
| S127 | MUST | 4.6 | Polling the device code faster than interval returns slow_down and increases the interval by 5 seconds. | met | conformance.test.ts |
| S128 | MUST | guides | Duplicate JSON object keys are rejected. | met | unit.test.ts |
| S129 | MUST | guides | ES256 is preferred, RS256 is accepted, and alg none and HS256 are rejected. | met | unit.test.ts |
| S130 | MUST | guides | jti values are at least 128 bits. | met | unit.test.ts |
| S131 | SHOULD | guides | Write requests send an Idempotency-Key that is a UUID version 4. | met | conformance.test.ts |
| S132 | MUST NOT | guides | Metadata fetches do not send Authorization, Cookie, or DPoP. | met | unit.test.ts |
| S133 | SHOULD | guides | Loopback and private addresses are refused unless the deployment explicitly allows them. | met | unit.test.ts |
| S134 | SHOULD | guides | Metadata cache lifetime is clamped to between 60 seconds and one day. | met | unit.test.ts |
| S135 | MUST | 4.8 | The secret store is created mode 0600 and is not returned to the model.  The file mode is 0600. There is no second encryption layer around the file. | met | unit.test.ts |
| S136 | MUST | 4.3 | DPoP htu is the URL without query or fragment. | met | unit.test.ts |
| S137 | MUST | 6 | The MCP API speaks MCP 2025-06-18 over streamable HTTP and rejects DPoP on that endpoint. | met | conformance.test.ts |
| S138 | MUST | 6 | MCP protected resource metadata names the company's authorization server. | met | conformance.test.ts |
| S139 | MUST | 7.9 | Direct conversations require an open parent that is not itself direct, and only one direct child is open. | met | conformance.test.ts |
| S140 | SHOULD | 4.9 | Sign-out takes effect on the next request. The session can continue signed out. | met | conformance.test.ts |
| S141 | MUST | 4.3 | Token failures on APIs include a WWW-Authenticate challenge. | met | conformance.test.ts |
| S142 | SHOULD | operations | OpenAPI marks operations with x-poppy-operation. | met | conformance.test.ts |
| S143 | SHOULD | guides | The agent prefers direct sign-in, then device sign-in, then mediated sign-in. | met | extension.test.ts |
