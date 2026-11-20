# Grilled Phish privacy policy

*Last updated: 20 November 2026*

Grilled Phish is a browser extension that warns about fake look-alike websites. This policy explains exactly
what it does with information. The short version: **we don't collect anything.** There is no Grilled Phish
account, server, analytics or advertising, and nothing about you or the websites you visit is ever sent to us.

## What stays on your computer

Everything Grilled Phish checks is checked **inside your browser**:

- the addresses of links and of the page you are on, compared with built-in rules and with a list of
  100,000 well-known websites that ships with the extension;
- your settings and your list of trusted sites (saved with the browser's own storage; if you use your
  browser's sync, the browser syncs them like any other setting);
- answers you gave, such as "I really meant this address", and a cache of website creation dates.

None of this is sent to the Grilled Phish developers or to anyone else.

## What leaves your computer, and why

Only two things, both needed for features you can turn off in the settings:

1. **Website creation dates ("age check", on by default in Chrome-based browsers and Edge; asked for
   separately in Firefox).** To find out how old a website is, the extension asks the **official public
   registry** for that address ending (for example Verisign for `.com`), using the standard RDAP protocol.
   The request contains **only the website's name** (like `example.com`), never the full address, the page,
   or anything about you. The list of registries comes from IANA (`data.iana.org`). Like any request on the
   internet, the registry can see your IP address. Results are cached on your computer so each name is asked
   about rarely. Turn it off in Settings → "Brand-new websites".
2. **Updates of the well-known websites list.** About every three days the extension downloads the latest
   list from this project's GitHub repository (through `cdn.jsdelivr.net` or `raw.githubusercontent.com`).
   The download sends nothing about you; like any download, those servers can see your IP address. The list
   is digitally signed and used only if the signature is genuine. Turn it off in Settings → "Well-known websites".

Grilled Phish never sends the addresses you visit to Google, to a "safe browsing" service, or to any other
checking service.

## What we never do

- We never collect, sell, rent or share personal data.
- We never use data for advertising, profiling or credit decisions.
- We never contact you: no emails, messages, calls or chats. **Anyone claiming to be Grilled Phish
  and contacting you is a scammer.**
- We never ask for passwords, codes, payment details or remote access to your computer.

## Permissions

| Permission | Why |
|---|---|
| Read web pages on all sites (content script) | To find look-alike links on the pages you visit and put a red box around them, and to warn on fake pages. The check runs locally; page contents are never sent anywhere. |
| `webNavigation` | To show a warning **before** a fake website or a likely typing mistake (`githhub.com`) loads. Browsers describe this as "read your browsing history"; Grilled Phish does not store or send your history. |
| `storage` | To remember your settings, trusted sites and the website-age cache. |
| `activeTab` | To show, in the toolbar popup, the verdict for the page you are on. |

## Children

Grilled Phish collects no data from anyone, including children.

## Changes and contact

Changes to this policy are published in this file, with its full history in the repository:
https://github.com/giobinda/grilled-phish/blob/main/PRIVACY.md

Questions or security problems: see [SECURITY.md](SECURITY.md). This repository is the only official place
for Grilled Phish.
