import { parseWhoisText, parseRdapDomain, hasKeyRegistrationFields } from '../../src/services/whois';
import { hasWhoisData } from '../../src/core/collector';

describe('parseWhoisText', () => {
  it('extracts registrar, dates, and name servers from a typical record', () => {
    const raw = [
      'Registrar: Example Registrar, Inc.',
      'Creation Date: 2010-01-01T00:00:00Z',
      'Registry Expiry Date: 2030-01-01T00:00:00Z',
      'Name Server: NS1.EXAMPLE.COM',
      'Name Server: NS2.EXAMPLE.COM',
      'Domain Status: clientTransferProhibited',
    ].join('\n');

    const result = parseWhoisText(raw);
    expect(result.registrar).toBe('Example Registrar, Inc.');
    expect(result.registrationDate).toBe('2010-01-01T00:00:00Z');
    expect(result.expirationDate).toBe('2030-01-01T00:00:00Z');
    expect(result.nameServers).toEqual(['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']);
  });

  it('does NOT capture disclaimer prose as a value (the false-positive bug)', () => {
    // Real registrars emit a NOTICE line whose body contains "expiration date";
    // matching the whole line would wrongly set expirationDate to prose.
    const raw = [
      'No match for "NOPE-NOPE-12345.COM".',
      'NOTICE: The expiration date displayed in this record is the date the',
      "registrar's sponsorship of the domain name registration in the registry",
      'Registrar:',
    ].join('\n');

    const result = parseWhoisText(raw);
    expect(result.expirationDate).toBeUndefined();
    expect(result.registrar).toBeUndefined();
    expect(Object.keys(result)).toHaveLength(0);
    expect(hasWhoisData(result)).toBe(false);
  });

  it('does not mistake "Registrar WHOIS Server" for the registrar', () => {
    const raw = ['Registrar: Real Registrar LLC', 'Registrar WHOIS Server: whois.example.net'].join('\n');
    expect(parseWhoisText(raw).registrar).toBe('Real Registrar LLC');
  });
});

describe('parseRdapDomain', () => {
  const rdap = {
    entities: [
      {
        roles: ['registrar'],
        vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]],
      },
      {
        roles: ['registrant'],
        vcardArray: ['vcard', [['adr', {}, 'text', ['', '', '', '', '', '', 'US']]]],
      },
    ],
    events: [
      { eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' },
      { eventAction: 'expiration', eventDate: '2028-09-14T04:00:00Z' },
    ],
    nameservers: [{ ldhName: 'ns1.example.com' }, { ldhName: 'ns2.example.com' }],
    status: ['client transfer prohibited', 'server delete prohibited'],
  };

  it('maps entities, events, nameservers, and status', () => {
    const result = parseRdapDomain(rdap);
    expect(result.registrar).toBe('MarkMonitor Inc.');
    expect(result.registrantCountry).toBe('US');
    expect(result.registrationDate).toBe('1997-09-15T04:00:00Z');
    expect(result.expirationDate).toBe('2028-09-14T04:00:00Z');
    expect(result.nameServers).toEqual(['ns1.example.com', 'ns2.example.com']);
    expect(result.status).toEqual(['client transfer prohibited', 'server delete prohibited']);
  });

  it('degrades gracefully on empty/garbage input', () => {
    expect(parseRdapDomain(null)).toEqual({});
    expect(parseRdapDomain({})).toEqual({});
    expect(parseRdapDomain({ entities: 'not-an-array' })).toEqual({});
  });

  it('returns a sparse record when RDAP omits registrar/dates', () => {
    const sparse = parseRdapDomain({ nameservers: [{ ldhName: 'a.iana-servers.net' }] });
    expect(sparse.nameServers).toEqual(['a.iana-servers.net']);
    expect(hasKeyRegistrationFields(sparse)).toBe(false); // triggers the WHOIS fallback
  });
});
