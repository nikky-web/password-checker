# Cracktime: Password Strength Checker

A password strength checker that thinks like an attacker. Type a password and see:

- **Strength meter + entropy estimate**, scored by the patterns a cracking tool actually tries first (leaked-password lists, dictionary words with l33t swaps, years, sequences, keyboard runs, repeats), not by counting character types.
- **Time to crack** under four attack scenarios, from a rate-limited login page to a GPU rig on stolen MD5/SHA-1 hashes.
- **Attacker's-eye view** that breaks the password into the pieces that would get guessed.
- **Breach check** against Have I Been Pwned using k-anonymity (only the first 5 chars of a SHA-1 hash leave the browser).
- **Passphrase / random generator** built on `crypto.getRandomValues` and the EFF wordlist.
- **Light / dark / system themes**, fully responsive.

Everything runs client-side. The password is never sent anywhere.

## Stack

Plain HTML, CSS, and JavaScript with no build step. Deployed on Netlify from this repo. `netlify.toml` sets security headers (CSP, HSTS, X-Frame-Options, and more).

## Run locally

Open `index.html`, or serve the folder:

```bash
python3 -m http.server 8000
```

## Credits

Passphrase words from the [EFF Large Wordlist](https://www.eff.org/dice) (CC BY 3.0). Breach data from [Have I Been Pwned](https://haveibeenpwned.com/Passwords).

Built by Nikky Rivera, Florida Atlantic University, midterm project.
