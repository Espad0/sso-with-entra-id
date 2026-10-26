# SSO lab

A local stand-in for Microsoft Entra ID ("Mini Entra") and two web apps that
sign users in through it with OpenID Connect. It belongs to the chapter
"Single Sign-On with Entra ID".

```bash
podman compose up -d
podman compose logs -f      # in a second terminal: every step of every sign-in
```

Open http://app-a.localhost:8001 in Chrome or Firefox and sign in as
`alice@lab.test` / `lab-password`. Then open http://app-b.localhost:8002:
you are signed in without a password. That is single sign-on.

| Folder or file | What it is |
|---|---|
| `idp/idp.py` | Mini Entra: sign-in page, codes, signed ID tokens, discovery, keys, logout |
| `idp/directory.json` | The "tenant": two test users and two app registrations |
| `app/app.py` | The web app; runs twice, as App A and App B |
| `secrets/` | The two apps' client secrets (fake, for the lab only) |
| `compose.yaml` | Starts all three containers |

Stop and remove everything with `podman compose down`.

Everything here is teaching code: plain HTTP, test passwords, keys in memory.
