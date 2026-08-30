// Executes the dashboard's inline <script> against a minimal DOM stub.
// `node --check` only parses; this catches load-time runtime errors such as
// using a `const` before its declaration, which blank out the whole UI.
const fs = require('fs');

const scriptPath = process.argv[2];
if (!scriptPath) {
  console.error('usage: node dashboard_smoke.js <extracted-script.js>');
  process.exit(2);
}
const code = fs.readFileSync(scriptPath, 'utf8');

function makeElement(id) {
  const element = {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    checked: false,
    disabled: false,
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {},
    removeEventListener() {},
    appendChild() {},
    setAttribute() {},
    removeAttribute() {},
    getAttribute: () => null,
    querySelector: () => makeElement('nested'),
    querySelectorAll: () => [],
    closest: () => null,
    focus() {},
    click() {},
    submit() {},
    reset() {},
    scrollIntoView() {},
    insertAdjacentHTML() {},
  };
  return element;
}

const elements = new Map();
global.document = {
  readyState: 'complete',
  body: makeElement('body'),
  documentElement: makeElement('html'),
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  },
  querySelector: () => makeElement('query'),
  querySelectorAll: () => [],
  createElement: (tag) => makeElement(tag),
  addEventListener() {},
  cookie: '',
};
global.window = {
  location: { hash: '', href: 'http://localhost/', search: '', reload() {} },
  history: { replaceState() {}, pushState() {} },
  addEventListener() {},
  setTimeout: () => 0,
  setInterval: () => 0,
  clearInterval() {},
  matchMedia: () => ({ matches: false, addEventListener() {} }),
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
};
global.location = global.window.location;
global.history = global.window.history;
global.localStorage = global.window.localStorage;
global.navigator = { userAgent: 'node', clipboard: { writeText: async () => {} } };
global.fetch = async () => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => ({}), text: async () => '' });
global.setInterval = () => 0;
global.setTimeout = (fn) => 0;      // never fire timers during the smoke run
global.requestAnimationFrame = () => 0;
global.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
global.alert = () => {};
global.confirm = () => true;
global.Chart = class { constructor() {} update() {} destroy() {} };

const errors = [];
process.on('unhandledRejection', () => {});   // background fetches are expected to no-op

try {
  new Function(code)();
} catch (err) {
  errors.push(`${err.name}: ${err.message}`);
}

if (errors.length) {
  console.error('DASHBOARD SCRIPT FAILED TO LOAD:');
  errors.forEach((message) => console.error('  ' + message));
  process.exit(1);
}
console.log('dashboard script loaded without runtime errors');
