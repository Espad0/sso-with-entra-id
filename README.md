# Single Sign-On with Entra ID

A free, self-contained textbook chapter on single sign-on for web developers.
It starts from HTTP cookies and redirects, builds up to OpenID Connect, explains
how Microsoft Entra ID works, and ends with a lab where you watch every step of
a sign-in on your own computer.

**Read it here: https://espad0.github.io/sso-with-entra-id/**

About 2½ hours of reading and a 45-minute lab. The interactive figures check
signatures with your browser's own cryptography. Each section ends with a few
questions, and the chapter ends with review questions, flashcards and a
glossary.

## What it covers

| Part | Sections |
|---|---|
| I. Foundations | The problem SSO solves · Cookies, sessions and redirects · Hashes, signatures and keys · Tokens and JWTs |
| II. The protocols | OAuth 2.0 and OpenID Connect · The sign-in, step by step · What each check stops |
| III. Microsoft Entra ID | Tenants and app registrations · Who may enter, and what they may do · Sessions, lifetimes and sign-out |
| IV. Building it | Three ways to add sign-in (a library, a sign-in proxy, the AWS load balancer) · Containers on AWS · The lab · A plan for a real project |

## The lab

`sso-lab/` runs three containers: "Mini Entra", a small OpenID Connect
identity provider that copies Entra's URL paths and error codes, and two web
apps that sign users in through it. Section 13 of the chapter walks through it.

```bash
git clone https://github.com/Espad0/sso-with-entra-id.git ~/sso-with-entra-id
cd ~/sso-with-entra-id/sso-lab
podman compose up -d
```

Then open http://app-a.localhost:8001 in Chrome or Firefox and sign in as
`alice@lab.test` with the password `lab-password`.

You need [Podman](https://podman.io) with Compose. The lab was run with Podman
only; `docker compose` should work the same way, but it was not tested.

Everything in `sso-lab/` is teaching code: plain HTTP, test users, fake client
secrets and keys kept in memory. Don't use it in production.

## How it was made and tested

This chapter was written with Claude, Anthropic's AI model, in October 2026.

- **Run:** the whole lab, with every command and output in section 13, on a Mac
  with Podman 6.0.2 and Docker Compose 5.5.1 ("the test Mac" in the chapter),
  with curl and in a Chromium-based browser.
- **Checked independently:** a lab token's signature with OpenSSL, and the lab
  app's discovery and key code against Entra's real public endpoints.
- **Not run:** a sign-in against a real Entra tenant, the Authlib example in
  section 14.3, and the oauth2-proxy and Caddy configuration in section 14.4.

Facts about Entra ID (lifetimes, limits, licences) come from Microsoft's
documentation as of 14 October 2026. They change, so check the links in
section 19 before you rely on a number.

## Corrections

If something is wrong or out of date, please open an issue or a pull request.
The chapter is a single file, `docs/index.html`.

## Licence

- Chapter text and figures: [CC BY 4.0](LICENSE-CONTENT.md)
- Code and configuration files: [MIT](LICENSE)
