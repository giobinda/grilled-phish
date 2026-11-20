# Store submission kit

Everything needed to publish Grilled Phish in the Chrome Web Store (also used by Brave, Vivaldi and Opera),
Firefox Add-ons (AMO) and Microsoft Edge Add-ons. Nothing in this folder ships inside the extension.

| File | Use |
|---|---|
| `../tools/package.sh` | Builds `dist/grilled-phish-<version>.zip`, the file to upload to every store |
| `listing/<lang>.md` | Store title, short and full description, in 12 languages |
| `screenshots/*.png` | 1280×800 screenshots |
| `promo/small-tile-440x280.png`, `promo/marquee-1400x560.png` | Promotional images (Chrome Web Store) |
| `../PRIVACY.md` | Privacy policy. Link: https://github.com/giobinda/grilled-phish/blob/main/PRIVACY.md |

## Before submitting

1. Run `tools/package.sh` and upload the zip it prints.
2. Use a **separate contact email** (a Proton alias), not a personal address. Stores may show it publicly.
3. EU (Chrome Web Store, AMO): declare yourself a **non-trader** (no commercial activity), so no postal
   address is shown.
4. Claim the name in all three stores at the same time, then put the store links in the main README so
   people can tell the real extension from copies.

## Answers for the forms

**Category:** Chrome: *Privacy & Security*. Firefox: *Privacy & Security*. Edge: *Security*.

**Single purpose (Chrome):**
> Grilled Phish protects people from phishing by detecting fake look-alike web addresses (such as
> paypa1.com or githhub.com) and warning before such a link or page is opened.

**Permission justifications (Chrome "Privacy practices" tab):**

- **Host access / content scripts on all sites:** Phishing links can appear on any website (webmail, social
  networks, search results, chats). The content script reads link addresses on the page to mark look-alike
  ones with a red box and block them until the user confirms, and locks password fields on fake pages.
  All checks run locally; page contents are never sent anywhere.
- **webNavigation:** Used to stop a navigation to a fake address, or to a likely typing mistake of a popular
  site (githhub.com), before the page loads, including addresses typed in the address bar or opened from
  another app. Only the destination address is checked, locally. Nothing is stored or transmitted.
- **storage:** Saves the user's settings, trusted-sites list and a local cache of website creation dates.
- **activeTab:** Lets the toolbar popup show the verdict for the current page when the user clicks it.
- **Remote code:** No. All code ships in the package. The extension only downloads a signed *data* file
  (a list of well-known domain names) and public registration dates (RDAP JSON); neither is executed.

**Data usage (Chrome):** Tick **none** of the data types; the developer collects no user data.
Certify: not sold to third parties; not used for unrelated purposes; not used for creditworthiness.
(The age check sends a website's *name* to the public domain registry to read its creation date. This is
explained in the privacy policy; it is not collected by the developer.)

**Firefox:** the manifest declares `data_collection_permissions`: required `none`, optional
`browsingActivity` (the age check, asked for when the user turns it on in Settings). The source code is
not minified or bundled, so no separate source upload is needed.

**Edge:** same texts as Chrome. Privacy policy URL as above.

**Notes for reviewers (all stores):**
> To test: download the repository (https://github.com/giobinda/grilled-phish), run `python3 -m http.server`
> in it and open http://localhost:8000/test/demo.html. Fake links get a red box and are blocked; typing
> githhub.com in the address bar shows "Did you mean github.com?"; paypa1.localhost:8000/test/fake-login.html
> shows the full-page warning. No account or login is needed.
