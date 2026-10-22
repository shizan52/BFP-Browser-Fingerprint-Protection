<div align="center">

```
██████╗ ███████╗██████╗
██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔═══╝
██████╔╝██║     ██║
╚═════╝ ╚═╝     ╚═╝
```

```
        ▄▄▄▄████████▄▄▄▄
    ▄▄██▀▀▀          ▀▀▀██▄▄
  ▄██▀       ▄████▄       ▀██▄
 ██▀        ██▀▀▀▀██        ▀██
 ▀██▄       ██▄▄▄▄██       ▄██▀
   ▀▀██▄▄▄   ▀████▀   ▄▄▄██▀▀
        ▀▀▀▀████████▀▀▀▀
```

**Browser-fingerprint consistency, detectability scoring and human-like automation — one Python file**

![selftest: 86 passed](https://img.shields.io/badge/selftest-86%20passed-brightgreen) ![deliverable: 1 Python file](https://img.shields.io/badge/deliverable-1%20Python%20file-blue) ![browser: Chromium + Playwright](https://img.shields.io/badge/browser-Chromium%20%2B%20Playwright-informational)

```
ONE file ..... bfp.py  (11.5k lines)
drives   ..... a patched Chromium (Playwright)
identity ..... UA · Client Hints · WebGL · Canvas · Audio · Fonts
network  ..... WebRTC leak protection · timezone · locale · geo
behaves  ..... Bezier mouse paths · variable typing cadence
keeps    ..... one isolated storage partition per profile
scores   ..... a live detectability score + evidence log
proves   ..... 86 passed · 0 failed · 0 skipped (418 s)
```

</div>

> **BFP** is a single-file module for building a **coherent browser identity** and checking how it looks from the
> outside. It generates device profiles whose parts agree with each other (user-agent, Client Hints, GPU, fonts,
> screen, timezone, locale, geolocation), drives a real Chromium with human-like input timing, keeps every identity
> in its own storage partition, **scores itself live**, and writes evidence for what it did.
> It is meant for legitimate, consenting automation: testing and QA of your own sites, privacy research, and
> understanding how browser fingerprinting works.

```
▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄
```

## ▓▒░ QUICK START ░▒▓

```
╔═════════════════════════════════════════════════════════════════════════════════╗
║ pip install playwright && python -m playwright install chromium                 ║
║ python bfp.py doctor                  # is everything ready?                    ║
║ python bfp.py fingerprint --os macOS  # print a coherent device profile (JSON)  ║
║ python bfp.py scree <URL>             # how detectable is this setup right now? ║
║ python bfp.py goal "go to <URL> and click Sign in"                              ║
║ python bfp.py selftest                # the 86-part self-test                   ║
╚═════════════════════════════════════════════════════════════════════════════════╝
```

(The page-report command is spelled `scree` in the code, so that is what the CLI expects.)

## ▓▒░ LAYERS ░▒▓

```
┌──────────────────────────────────────────────────────────────────┐
│ BEHAVIOUR     mouse curves · typing cadence · timing             │
├──────────────────────────────────────────────────────────────────┤
│ FINGERPRINT   UA · Client Hints · WebGL · Canvas · Audio · Fonts │
├──────────────────────────────────────────────────────────────────┤
│ NETWORK       WebRTC · timezone · locale · geolocation · proxy   │
├──────────────────────────────────────────────────────────────────┤
│ IDENTITY      one isolated storage partition per profile         │
├──────────────────────────────────────────────────────────────────┤
│ EVIDENCE      live score + forensic logs of every run            │
└──────────────────────────────────────────────────────────────────┘
```

Profiles come from **one factory**, so the parts agree with each other — a mismatch between, say, the user-agent, the GPU and the timezone is one of the most common ways a fingerprint gives itself away.

## ▓▒░ DESIGN NOTES ░▒▓

```
╔════════════════════════════════════════════════════════════════════════════════════════╗
║ [#] Coherent by construction  ProfileFactory returns identities whose fields agree     ║
║ [#] One identity = one Session = one storage partition                                 ║
║ [#] Self-scoring              `scree` reports a 0-100 score and the exact tells        ║
║ [#] Attach to a real Chrome   wire the same layer onto a browser you launched yourself ║
║ [#] Plugins and hooks         extend without touching the core file                    ║
║ [#] Honest limitations        a built-in report of what it can NOT do (Part 85)        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝
```

## ▓▒░ TESTED ░▒▓

`python bfp.py selftest` starts a **local fixture internet inside the file** (a shop, a bot-check page, a CAPTCHA
page, a CSRF login form, a slow endpoint, an API, a nested iframe / shadow-DOM page, storage and geolocation pages) and
runs **one test per `knowledge.md` part** in a real Chromium — no internet required.

```
╔══ RESULT ═════════════════════════════════════════════════════╗
║ 86 passed · 0 failed · 0 errors · 0 skipped   in 418 s        ║
║ Windows 11 · Python 3.14.7 · Playwright 1.62.0 · Chromium 151 ║
║ (full run, no --quick, no --live)                             ║
╚═══════════════════════════════════════════════════════════════╝
```

It was also checked against public headless-tell pages (for example `bot.sannysoft.com`: 31 pass / 0 fail), and the
long-form manual records the **one signal it cannot remove** — timer resolution under a DevTools connection — because
an honest limitation is worth more than a perfect score.


## ▓▒░ DOCS ░▒▓

| | |
|---|---|
| **[DOCS.md](DOCS.md)** | Python API, CLI, configs and plugins, how each layer works, the 86 parts ↔ code map, troubleshooting |


## ▓▒░ RESPONSIBLE USE ░▒▓

This module is for **automation you are entitled to perform**: your own sites and test environments, QA, and research.
Honour `robots.txt`, terms of service, rate limits and the law. It is not a tool for fraud, account abuse, or getting around
security controls you have no right to bypass, and the author accepts no responsibility for misuse.

**Licence.** No open-source licence is attached to this repository, so by default all rights are reserved. If you would like to use or build on it, please ask the author first.

```
▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄
```
