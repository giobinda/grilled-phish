<img src="icons/icon-128.png" width="96" alt="Grilled Phish logo: a fish on a grill">

# Grilled Phish

*Blocks fake look-alike websites before you click.*

A browser extension that catches **look-alike scam links**, like `paypa1.com`, `pаypal.com` (Cyrillic а),
`arnazon.com`, `paypal.com.secure-verify.xyz` and `poste-italiane-verifica.com`, so you don't have to read domains yourself.

- Dangerous links get a **red box** and a "⛔ Fake site — blocked" label, and **they don't open when clicked**.
- Clicking one shows a big warning. It shows the real destination with the fake letters highlighted, next to the real website.
- To open it anyway: click "I know what I am doing…", tick the checkbox, wait 5 seconds, then click the button.
- If the **page you're on** is a fake, a red banner appears and password/card fields are locked behind the same warning.
- **Brand-new websites** (created less than a month ago, adjustable) are blocked too. Scam sites usually
  live only a few days. The creation date comes from the official registry for that ending (see Privacy below).
- **Copies of 100,000 well-known websites** are caught too, not just big brands: `wikipedla.org`, `g1thub.com`,
  `stackoverfIow.com`. The list of the most visited sites comes from [Tranco](https://tranco-list.eu) and is
  checked on your computer. The warning highlights the exact letter that is different.
- The toolbar button shows in big letters whether the current site is real, fake or unknown, and lets you add it to your trusted sites.
- All the look-alike checks run on your computer.

## Install

**Chrome / Edge / Brave**
1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked** and pick this `grilled-phish` folder

**Firefox**
1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…** and pick `manifest.json`
3. In `about:addons` → Grilled Phish → Permissions, allow access to all websites
   (Firefox asks for this separately). Temporary add-ons are removed when Firefox restarts.
   For a permanent install it has to be signed through addons.mozilla.org.

Then open the extension's settings and **add the sites you really use** (your bank, email provider…),
so that copies of those sites get blocked too.

## How it detects fakes (`lib/detector.js`)

| Trick | Example | Check |
|---|---|---|
| Letters from another alphabet | `pаypal.com` (Cyrillic) | Unicode look-alike table + mixed-alphabet check |
| Visual swaps | `paypa1`, `arnazon`, `g00gle` | "skeleton" comparison (`1→l`, `0→o`, `rn→m`, `vv→w`) |
| Typos | `amazom`, `netfilx` | one-letter edit distance (names of 6+ letters) |
| Real name, wrong owner | `paypal.com.verify.xyz`, `paypal-login.netlify.app` | brand in subdomain / brand + bait word (EN, IT, ES, DE, FR) |
| Same name, other ending | `paypal.xyz` | not in the brand's official domain list |
| Lying link text | text `www.paypal.com` → goes elsewhere | compares shown domain to the real target |
| Copy of a well-known site | `stackoverfIow.com`, `g1thub.com`, `wikipedia.org.read-more.xyz` | 100k-site database (`data/known-sites.txt`) |
| Brand-new website | `best-deals-4u.shop` created 3 days ago | RDAP registration date (`background.js`) |

Protected out of the box: about 40 brands that phishers copy most (PayPal, Google, Apple, Microsoft, Amazon, banks, Poste Italiane,
DHL…), plus whatever you add as trusted.

## The well-known websites database

`data/known-sites.txt` lists the ~100,000 most visited websites, most popular first. It's built from the
[Tranco list](https://tranco-list.eu), which combines five traffic sources over 30 days so it's hard to game.
"Known" means **popular, not safe**: the list is only used to recognise *copies* of these names.

How a site that isn't on the list is judged against it:

| Difference from a well-known name | Example | Result |
|---|---|---|
| Letters from another alphabet | `mywebsіte.com` (Ukrainian і) | blocked |
| Digit hidden inside the word | `g1thub.com`, `pr0fitel.com` | blocked |
| Letter swap (`i`/`l`, `rn`/`m`, `cl`/`d`) | `stackoverfIow.com` | blocked **if the site is less than 1 year old** |
| Well-known address used as a prefix | `stackoverflow.com.answers-hub.xyz` | blocked |
| Only hyphens differ | `one-click.de` vs `oneclick.com` | allowed (usually different businesses) |
| Same name, other ending | `mywebsite.net` vs `mywebsite.com` | allowed (unless it's one of the built-in brands) |

Measured on real data: the 100,000 websites ranked 100,001–200,000, which aren't in the database, were used as
"ordinary sites you might visit". Only 5 were flagged as copies outright. Letter-swap matches happen about
56 times, but 54 of those sites are years old, so the 1-year rule lets them through. The two under a year old include
`googleanalytlcs.com`, created 41 days earlier. Letter-swap copies on endings without public creation dates
(`.it`, `.de`…) aren't blocked by this check.

Popular sites also fix false alarms from the built-in brand rules: `google.ru` or `amazon.co.za` are the brands'
own sites, so they're allowed. Popular typo-squatters (`instragram.com`, `twiter.com`) are removed from the
list when it's built, so they stay blocked.

### Automatic, signed updates

Installed extensions check for a newer list every 3 days. They download it from the jsDelivr CDN, falling back to
GitHub. Because the list is **digitally signed**, where it's hosted doesn't matter: the extension uses a download only if all
of these hold:

- the signature matches a public key built into the extension (`lib/list-public-key.js`, ECDSA P-256);
- its serial number is newer than the list in use, so old lists can't be replayed;
- the essential sites (google.com, paypal.com, wikipedia.org…) are present;
- no more than 40% of sites were removed at once.

Otherwise the current list stays in use and Settings shows why. The saved copy is re-verified every time it's loaded.
Updates can be turned off in Settings.

**Weekly pipeline** (`.github/workflows/update-known-sites.yml`):

1. **build**: no secrets, read-only. Tests the code, downloads Tranco, removes fakes, refuses changes of more than 25%,
   and posts a summary of additions and removals on the run page.
2. **sign**: **waits for the maintainer's approval** (GitHub environment `list-signing`). Only this job can read the
   private key. It signs the file built in step 1, verifies it and commits it.

While the repository is private, step 2 is skipped (approval rules need a public repo or a paid plan).

**Keys and manual builds**

```
node tools/keygen.js                          # once: private key -> ~/.config/grilled-phish/ (mode 600), public key -> lib/list-public-key.js
node tools/build-known-sites.js --top 100000  # writes an unsigned data/known-sites.txt (+ report of dropped entries)
node tools/sign-list.js                       # signs it with the local key, checks it against the shipped public key
tools/setup-signing.sh                        # once, after going public: approval step + key as an environment secret
```

Keep a backup of the private key (e.g. in a password manager). If it's lost or leaked, run `keygen.js` again with
a new output path, publish an extension version with the new public key, and remove the old key from
`lib/list-public-key.js` once nobody runs older versions.

## Learning to spot scams (`learn/learn.html`)

A short, plain-language guide built into the extension (no network needed to read it):
what phishing is, how to read an address, look-alike letters, warning signs in messages,
five rules, what to do if you already clicked, plus links to official sources (CISA, UK NCSC,
AARP, Polizia Postale) and places to report scams. It opens once after installing, and from
the toolbar popup, the settings page and every warning dialog. The page is not web-accessible,
so websites can't load it or use it to detect the extension; the dialog asks the background
worker to open it, and only for a real click.

## Languages

The extension speaks 12 languages: English, Spanish, Chinese, Hindi, Arabic (right to left),
French, Portuguese, Ukrainian, Japanese, German, Italian and Indonesian.

- **Warnings, popup and settings** use the browser's standard translation system
  (`_locales/<lang>/messages.json`) and follow the browser's language. `lib/detector.js`
  keeps the English text built in so it also runs in Node; `test/i18n.test.js` checks that it
  matches `_locales/en`, that every language has every message with the same `$1`/`$2`
  placeholders, and that the store name and description fit the store limits.
- **The guide** (`learn/i18n/<lang>.js`) picks the browser's language too, can be switched
  from a menu, and adds local official sources where they exist: INCIBE (Spain),
  Cybermalveillance and PHAROS (France), BSI and Verbraucherzentrale (Germany), CERT.br
  (Brazil), CNCS (Portugal), Polizia Postale (Italy), the Council of Anti-Phishing Japan,
  CERT-UA, the National Bank and the Cyber Police (Ukraine), and India's cybercrime portal and
  1930 helpline. `test/learn-i18n.test.js` checks that nothing is missing.

To add a language: copy `_locales/en/messages.json` and `learn/i18n/en.js`, translate the
values, and add the code to `LANGS` in `learn/learn.js`.

**The translations were written by an AI and have not yet been reviewed by native speakers.**

## Grilled Phish will never contact you

Scammers like to pretend to be the security tool itself ("Grilled Phish support here, please
turn it off / mark this site as safe / install this update"). So, in every language, the settings
page, the popup and the guide say plainly:

- **We never collect your data.** There is no account and no Grilled Phish server; nothing about
  you or the websites you visit reaches us. (The age check asks the official registry about a
  site's *name*, and list updates are downloaded from this repository; see Privacy.)
- **We never write to you or call you**: no emails, texts, chats or phone calls, and we never ask
  for passwords, codes, money or remote access.
- **We never send links.** Links are shown only inside the extension itself.
- **Nobody from Grilled Phish will ever ask you to turn it off, remove it or trust a website.**
- **Our only website is https://github.com/giobinda/grilled-phish.** Anyone else claiming to be
  us is a scammer.

`test/links.test.js` enforces the "no links" promise: every web address in the shipped extension
must be on an approved list (this repository, the official registry directory, and the official
sources in the guide), and extension pages may not load remote scripts, frames or forms.

## Privacy (age check)

To find a site's age, `background.js` sends **only the domain name** (`best-deals.shop`, never the full address)
directly to the official registry for that ending. It uses RDAP, the registries' public database, and IANA's directory
to find the right registry. No third-party service is involved. Each answer is saved for 7 days, and at most 50 domains are looked up per page.
It can be turned off in the settings. `.it`, `.de`, `.es`, `.eu`, `.ru` and `.co` don't publish creation dates, so
sites with those endings get no age check (the look-alike checks still apply).

## Tests

```
node --test test/*.test.js
```

`test/demo.html` is a page full of fake links for trying the extension by hand. Serve it with
`python3 -m http.server` and open `http://localhost:8000/test/demo.html`.

## Security

A phishing page is hostile code running in the same page as the extension, so the extension is built to resist it.
`test/attacks.html` is a hostile test page that tries each attack below. All of them are blocked in Chromium:

| Attack by a hostile page | Defence |
|---|---|
| Removing the "blocked" mark from a fake link | links are re-checked at the moment of the click, never trusting page-editable markers |
| Swapping a link's address during the click | the Navigation API cancels the navigation (Chrome/Edge); on Firefox the address change is caught while the click is still being handled |
| Script redirects / form posts to a fake site | the Navigation API catches them in Chrome/Edge |
| Silencing the password lock (swallowing key/focus events) | the extension starts before any page script (`document_start`), so its handlers always run first |
| Deleting the red warning | it's re-added at once; after the second attempt a native browser alert appears, which pages can't remove |
| Covering the dialog with fake buttons | the dialog is a modal in the browser's top layer, and page pop-ups and fullscreen are closed while it's open |
| Clicking blocked links from page scripts | script-generated clicks are silently ignored |
| Detecting that the visitor has the extension | nothing is added to a page unless it contains something dangerous |

Other measures:
- No `innerHTML`, `eval` or remote code. All text, including attacker-controlled domain names, is inserted as plain text.
- Web pages can't message the extension. Settings messages are accepted only from the extension's own pages.
- Minimal permissions: `storage` and `activeTab`. Content scripts run on all sites, but the extension has no extra host permissions.
- List downloads must stay on HTTPS (redirects included), be signed with the project key, be newer than the list in
  use, and pass sanity checks before use.
- The GitHub workflow pins third-party actions to exact commits and only the update job can write to the repo.
- "Open anyway" and "I trust this site" warn about phone/chat scams, because scammers coach victims through them.

**Remaining risks (by design or not yet covered):**
- **Anything inside a web page can be imitated.** A scam page could draw its own fake "✓ verified by Grilled Phish" box.
  Grilled Phish never shows "safe" messages inside pages. The trustworthy signal is the **toolbar badge**
  (red `!` = fake, green `✓` = the real site), which the browser draws and pages can't touch.
- On **Firefox**, script redirects to a fake site aren't stopped before they happen (no Navigation API). The fake page
  is still recognised on arrival: red banner and locked password fields.
- Password/card fields built without real form inputs (custom widgets, canvas) aren't locked. The banner is still shown.
- On pages where something is blocked, the page can tell the extension is installed.
- Privacy: with the age check on, registries see the domain names being checked (see above).

## Credits

The well-known sites ranking is the [Tranco list](https://tranco-list.eu) (Le Pochat et al., *Tranco: A Research-Oriented
Top Sites Ranking Hardened Against Manipulation*, NDSS 2019).

## Limits

- It catches **look-alikes of known sites** and **brand-new sites**. A scam with a random name that doesn't imitate
  anyone *and* is more than a month old (or uses an ending without public creation dates) won't be flagged.
  Browser Safe Browsing, a password manager and passkeys cover that case.
- Links in phone text messages/apps aren't covered (mobile browsers barely support extensions).
