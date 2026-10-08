// Tests for the pure part of index.html: everything before the rendering section runs without a DOM.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'index.html'), 'utf8');
const script = html.split('<script>')[1].split('</script>')[0];
const pure = script.slice(0, script.indexOf('// ---------- Rendering'));

function load() {
  return new Function(pure + `;
    return { state, RR, APEX_TYPES, HOST_TYPES, DNSSEC_TYPES, normalizeInput, quoteTxt, unquoteTxt, canonicalData,
      relative, scopeOf, buildZoneFile, reverseName, parseSoa, addRecord, typeName, csvEscape };`)();
}
function zone(api, apex, delegations = []) {
  api.state.zone = apex;
  api.state.delegations = new Set(delegations);
  api.state.resolvers = ['google'];
}
const rec = (name, type, data, ttl = 300) => ({ name, type, data, ttl, sources: new Set(['Google']) });

test('normalizeInput: a URL with "@" in its query keeps the host', () => {
  const { normalizeInput } = load();
  assert.equal(normalizeInput('https://www.Example.com/path?x=a@b'), 'www.example.com.');
});
test('normalizeInput: mailbox, port, trailing dot and case are stripped', () => {
  const { normalizeInput } = load();
  assert.equal(normalizeInput('user@EXAMPLE.com'), 'example.com.', 'mailbox');
  assert.equal(normalizeInput('example.com:8080'), 'example.com.', 'port');
  assert.equal(normalizeInput('mail.example.co.za.'), 'mail.example.co.za.', 'trailing dot');
  assert.equal(normalizeInput('*.example.com'), '*.example.com.', 'wildcard');
});
test('normalizeInput: text that is not a name is rejected', () => {
  const { normalizeInput } = load();
  assert.equal(normalizeInput('not a domain'), '');
  assert.equal(normalizeInput(''), '');
});

test('TXT round trip at the 255-character chunk boundary', () => {
  const { quoteTxt, unquoteTxt } = load();
  const at = 'a'.repeat(255);
  const over = 'a'.repeat(256);
  assert.equal(quoteTxt(at), '"' + at + '"', 'exactly 255 is one string');
  assert.equal(quoteTxt(over), '"' + at + '" "a"', '256 splits into two strings');
  assert.equal(unquoteTxt(quoteTxt(over)), over);
});
test('TXT round trip with a quote and a backslash straddling the chunk boundary', () => {
  const { quoteTxt, unquoteTxt } = load();
  for (const raw of ['a'.repeat(254) + '"' + 'b'.repeat(50), 'a'.repeat(254) + '\\' + 'b'.repeat(50), 'x\\y"z']) {
    assert.equal(unquoteTxt(quoteTxt(raw)), raw);
  }
});
test('TXT chunks are limited by UTF-8 bytes, not characters', () => {
  const { quoteTxt, unquoteTxt } = load();
  const raw = 'é'.repeat(200);
  const strings = quoteTxt(raw).split('" "');
  assert.equal(strings.length, 2);
  assert.equal(Buffer.byteLength(strings[0].slice(1)), 254, 'first string holds 127 two-byte characters');
  assert.equal(unquoteTxt(quoteTxt(raw)), raw);
});
test('csvEscape neutralises formula prefixes and quotes commas', () => {
  const { csvEscape } = load();
  assert.equal(csvEscape('=HYPERLINK("http://x")'), `"'=HYPERLINK(""http://x"")"`);
  assert.equal(csvEscape('-1'), "'-1");
  assert.equal(csvEscape('v=spf1 a, b'), '"v=spf1 a, b"');
  assert.equal(csvEscape('plain'), 'plain');
});
test('addRecord strips line breaks from resolver data', () => {
  const api = load();
  api.addRecord('google', { name: 'example.com.', type: 257, TTL: 1, data: '0 issue "x"\n$INCLUDE /etc/passwd' });
  assert.equal([...api.state.records.values()][0].data, '0 issue "x" $INCLUDE /etc/passwd');
});
test('unquoteTxt joins several quoted strings and leaves unquoted text alone', () => {
  const { unquoteTxt } = load();
  assert.equal(unquoteTxt('"v=spf1" " -all"'), 'v=spf1 -all');
  assert.equal(unquoteTxt('v=spf1 -all'), 'v=spf1 -all');
});

test('canonicalData: both resolvers produce one key for the same answer', () => {
  const { canonicalData } = load();
  assert.equal(canonicalData('SRV', '100 1 443 Sipdir.online.lync.com'), canonicalData('SRV', '100 1 443 sipdir.online.lync.com.'), 'SRV target dot');
  assert.equal(canonicalData('DS', '2371 13 2 ABCDEF'), canonicalData('DS', '2371 13 2 abcdef'), 'DS digest case');
  assert.equal(canonicalData('TXT', '"v=spf1 -all"'), canonicalData('TXT', 'v=spf1 -all'), 'TXT quoting');
  assert.equal(canonicalData('SOA', 'ns1.example.com. Hostmaster.example.com 1 2 3 4 5'), 'ns1.example.com. hostmaster.example.com. 1 2 3 4 5', 'SOA name fields');
  assert.equal(canonicalData('NAPTR', '100 10 "S" "SIP+D2U" "" _sip._udp.example.com'), '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.', 'NAPTR keeps non-name fields');
  assert.equal(canonicalData('DNSKEY', '257 3 13 AbC='), '257 3 13 AbC=', 'base64 untouched');
  assert.equal(canonicalData('NS', 'NS1.Example.com'), 'ns1.example.com.', 'whole-rdata name lowercased and absolute');
});

test('relative: apex is "@", names under the zone drop the suffix, others stay absolute', () => {
  const { relative } = load();
  assert.equal(relative('example.com.', 'example.com.'), '@');
  assert.equal(relative('www.example.com.', 'example.com.'), 'www');
  assert.equal(relative('*.example.com.', 'example.com.'), '*');
  assert.equal(relative('notexample.com.', 'example.com.'), 'notexample.com.');
});

test('scopeOf: every scope value', () => {
  const api = load();
  zone(api, 'example.com.', ['dev.example.com.']);
  api.addRecord('google', { name: 'dev.example.com.', type: 2, TTL: 300, data: 'ns1.dev.example.com.' });
  const cases = [
    [rec('example.com.', 'A', '1.2.3.4'), 'zone'],
    [rec('www.example.com.', 'A', '1.2.3.4'), 'zone'],
    [rec('dev.example.com.', 'NS', 'ns1.dev.example.com.'), 'zone'],
    [rec('dev.example.com.', 'DS', '1 13 2 ab'), 'zone'],
    [rec('ns1.dev.example.com.', 'A', '10.0.0.1'), 'zone'],
    [rec('www.dev.example.com.', 'A', '10.0.0.2'), 'child'],
    [rec('dev.example.com.', 'A', '10.0.0.3'), 'child'],
    [rec('example.com.', 'DS', '1 13 2 ab'), 'parent'],
    [rec('example.com.', 'RRSIG', 'A 13 2 300 ...'), 'sig'],
    [rec('shops.myshopify.com.', 'A', '1.2.3.4'), 'ext'],
    [rec('4.3.2.1.in-addr.arpa.', 'PTR', 'example.com.'), 'rev'],
  ];
  for (const [r, expected] of cases) assert.equal(api.scopeOf(r), expected, `${r.name} ${r.type}`);
});

test('buildZoneFile: one SOA, $TTL from a zero minimum, TXT quoted, child and parent records excluded', () => {
  const api = load();
  zone(api, 'example.com.', ['dev.example.com.']);
  api.addRecord('google', { name: 'example.com.', type: 6, TTL: 300, data: 'ns1.example.com. hostmaster.example.com. 7 7200 3600 1209600 0' });
  api.addRecord('cloudflare', { name: 'example.com', type: 6, TTL: 299, data: 'ns1.example.com. hostmaster.example.com. 7 7200 3600 1209600 0' });
  api.addRecord('google', { name: 'example.com.', type: 2, TTL: 300, data: 'ns1.example.com.' });
  api.addRecord('google', { name: 'example.com.', type: 16, TTL: 300, data: 'v=spf1 -all' });
  api.addRecord('google', { name: 'dev.example.com.', type: 2, TTL: 300, data: 'ns1.dev.example.com.' });
  api.addRecord('google', { name: 'www.dev.example.com.', type: 1, TTL: 300, data: '10.0.0.2' });
  api.addRecord('google', { name: 'example.com.', type: 43, TTL: 300, data: '1 13 2 ab' });
  const out = api.buildZoneFile();
  const lines = out.split('\n');
  assert.equal(lines.filter(l => /\tSOA\t/.test(l)).length, 1, 'one SOA');
  assert.ok(lines.includes('$TTL 0'), '$TTL 0 from SOA minimum');
  assert.ok(lines.includes('@\t300\tIN\tTXT\t"v=spf1 -all"'), 'quoted TXT');
  assert.ok(lines.includes('dev\t300\tIN\tNS\tns1.dev.example.com.'), 'delegation NS relative');
  assert.ok(!out.includes('10.0.0.2'), 'child record excluded');
  assert.ok(!/\tDS\t/.test(out), 'apex DS excluded');
  assert.ok(!out.includes('undefined'), 'no undefined');
});

test('reverseName: IPv4, compressed IPv6 and ::1', () => {
  const { reverseName } = load();
  assert.equal(reverseName('1.2.3.4'), '4.3.2.1.in-addr.arpa.');
  assert.equal(reverseName('2606:4700::6810:84e5'), '5.e.4.8.0.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.ip6.arpa.');
  assert.equal(reverseName('::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.');
});

test('parseSoa: seven fields or nothing', () => {
  const { parseSoa } = load();
  assert.deepEqual(parseSoa('a. b. 1 2 3 4 5'), { primary: 'a.', contact: 'b.', serial: '1', refresh: '2', retry: '3', expire: '4', minimum: '5' });
  assert.equal(parseSoa('a. b. 1 2 3 4'), null);
});

test('registry: every type has a wire code and the sweep lists derive from it', () => {
  const { RR, APEX_TYPES, HOST_TYPES, DNSSEC_TYPES, typeName } = load();
  for (const [name, spec] of Object.entries(RR)) assert.equal(typeName(spec.num), name, name);
  assert.ok(APEX_TYPES.includes('SOA') && !APEX_TYPES.includes('RRSIG'));
  assert.deepEqual(HOST_TYPES.sort(), ['A', 'AAAA', 'CAA', 'CNAME', 'HTTPS', 'MX', 'NS', 'SRV', 'TXT']);
  assert.deepEqual(DNSSEC_TYPES, ['RRSIG', 'NSEC', 'NSEC3']);
});
