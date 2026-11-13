# Link Guardian

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
3. Click **Load unpacked** and pick this `link-guardian` folder

**Firefox**
1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…** and pick `manifest.json`
3. In `about:addons` → Link Guardian → Permissions, allow access to all websites
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

**Rebuild / update the list**

```
node tools/build-known-sites.js --top 100000     # writes data/known-sites.txt and a report of dropped entries
```

`.github/workflows/update-known-sites.yml` does this every week on GitHub. To have installed extensions pick up the
new list automatically, open Settings → Well-known websites → Advanced and enter the file's raw URL, e.g.
`https://raw.githubusercontent.com/<you>/<repo>/main/data/known-sites.txt`. The download is checked before use
(1,000–300,000 valid domain names). Use only a source you control: a tampered list could make a fake site count as
well-known. If the download fails, the built-in list is used.

## Privacy (age check)

To find a site's age, `background.js` sends **only the domain name** (`best-deals.shop`, never the full address)
directly to the official registry for that ending. It uses RDAP, the registries' public database, and IANA's directory
to find the right registry. No third-party service is involved. Each answer is saved for 7 days, and at most 50 domains are looked up per page.
It can be turned off in the settings. `.it`, `.de`, `.es`, `.eu`, `.ru` and `.co` don't publish creation dates, so
sites with those endings get no age check (the look-alike checks still apply).

## Tests

```
node --test test/detector.test.js
```

`test/demo.html` is a page full of fake links for trying the extension by hand. Serve it with
`python3 -m http.server` and open `http://localhost:8000/test/demo.html`.

## Credits

The well-known sites ranking is the [Tranco list](https://tranco-list.eu) (Le Pochat et al., *Tranco: A Research-Oriented
Top Sites Ranking Hardened Against Manipulation*, NDSS 2019).

## Limits

- It catches **look-alikes of known sites** and **brand-new sites**. A scam with a random name that doesn't imitate
  anyone *and* is more than a month old (or uses an ending without public creation dates) won't be flagged.
  Browser Safe Browsing, a password manager and passkeys cover that case.
- Links in phone text messages/apps aren't covered (mobile browsers barely support extensions).
