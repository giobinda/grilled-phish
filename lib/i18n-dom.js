/*
 * Fills the extension's own pages with text in the browser's language.
 *   data-i18n="key"             -> textContent
 *   data-i18n-html="key"        -> innerHTML (bundled strings only: <strong>, <code>)
 *   data-i18n-placeholder="key" -> placeholder attribute
 */
(function (root) {
  const T = (key, ...subs) => chrome.i18n.getMessage(key, subs.map(String)) || key;
  function localize(doc = document) {
    doc.documentElement.lang = chrome.i18n.getUILanguage();
    doc.documentElement.dir = (chrome.i18n.getMessage('textDir') === 'rtl' ? 'rtl' : 'ltr');
    doc.querySelectorAll('[data-i18n]').forEach((e) => { e.textContent = T(e.dataset.i18n); });
    doc.querySelectorAll('[data-i18n-html]').forEach((e) => { e.innerHTML = T(e.dataset.i18nHtml); });
    doc.querySelectorAll('[data-i18n-placeholder]').forEach((e) => { e.placeholder = T(e.dataset.i18nPlaceholder); });
  }
  root.GP_T = T;
  root.GP_localize = localize;
  localize();
})(globalThis);
