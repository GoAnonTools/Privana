# Privana

**Privana** is an anonymous VPN access platform by **GoAnon**.

It is designed around a privacy-first account flow: no email, no password, no username, and no personal identity required. Users create an anonymous account number, receive a one-time recovery code, and can access a time-limited VPN trial without exposing traditional account details.

© 2026 GoAnon | [GoAnon.pro](https://goanon.pro)

---

## Purpose

Privana is built to provide a simple, privacy-focused VPN experience with anonymous account creation and secure device configuration.

The project focuses on:

- Anonymous signup with no form fields
- 16-digit account-number login
- One-time recovery code rotation
- 7-day trial access
- WireGuard-based VPN configuration
- Browser-generated client keys
- Local helper support for desktop WireGuard control
- Minimal external dependencies and privacy-sensitive asset loading

---

## Anonymous Account Flow

The intended user flow is:

1. **Signup**
   - User clicks **Create Anonymous Account**
   - No email, password, phone number, or username is requested

2. **Reveal**
   - User receives:
     - A 16-digit account number
     - A one-time recovery code
   - Copy buttons are provided
   - The user must confirm they saved the credentials before continuing

3. **Login**
   - User logs in using only the 16-digit account number
   - The input is numeric-friendly and formatted for readability

4. **Recovery**
   - User enters the recovery code
   - Privana immediately invalidates:
     - The old account number
     - The old recovery code
   - A new account number and new recovery code are issued

5. **Trial**
   - Trial access lasts 7 days from account creation
   - Expired trial users are redirected to the trial-ended page
   - Recovery does not reset the trial

---

## Security Model

Privana includes several hardening measures:

- Recovery codes are stored as hashes, not plaintext
- Recovery rotates both the account number and recovery code
- Expired trials are enforced server-side
- Browser JSON actions require CSRF protection
- API requests use HMAC authentication
- API nonce replay protection is stored durably
- SQLite uses WAL mode and busy timeouts
- Login brute-force attempts are temporarily blocked
- External CDN dependencies are removed from app templates
- Local Windows helper actions require a shared helper token

---

## Technology Stack

Privana currently uses:

- Python
- Flask
- SQLite
- WireGuard
- WebAuthn / passkeys
- HMAC-signed API calls
- Local static assets for privacy-sensitive frontend resources

---

## Project Structure

```txt
Privana/
├── web/                  # Flask web app
│   ├── routes/           # Auth, dashboard, WebAuthn, downloads
│   ├── templates/        # App templates
│   ├── static/           # Local static assets and vendored frontend files
│   └── db.py             # Database schema/init helpers
├── server/               # VPN server/API logic
├── clients/              # Client-side helpers
│   └── windows/helper/   # Windows WireGuard local helper
├── site/                 # Public marketing/legal pages
├── requirements.txt
├── README.md
└── LICENSE