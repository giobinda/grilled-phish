/*
 * Puts a bundled translation into an element without innerHTML.
 * Only <strong>, <b>, <code> and <mark> become formatting; anything else stays plain text,
 * so even a broken or hostile string can never create links, images or scripts.
 */
(function (root) {
  'use strict';
  const TAG = /<(\/?)(strong|b|code|mark)>/g;
  function richText(el, str) {
    el.textContent = '';
    const stack = [el];
    let last = 0;
    for (const m of String(str).matchAll(TAG)) {
      if (m.index > last) stack.at(-1).append(str.slice(last, m.index));
      if (!m[1]) {
        const child = document.createElement(m[2]);
        stack.at(-1).appendChild(child);
        stack.push(child);
      } else if (stack.length > 1 && stack.at(-1).localName === m[2]) {
        stack.pop();
      }
      last = m.index + m[0].length;
    }
    if (last < String(str).length) stack.at(-1).append(String(str).slice(last));
    return el;
  }
  root.GP_richText = richText;
})(globalThis);
