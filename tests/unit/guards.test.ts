import { isDomainShaped, isPrivateAddress, assertPublicDomain } from '../../src/core/target-guard';
import { collectAdvisories, hasWhoisData, hasDnsData } from '../../src/core/collector';

describe('isDomainShaped', () => {
  it.each(['example.com', 'a.b.co', 'sub.example.co.uk', 'example.com.', '1.2.3.4'])('accepts %s', v => {
    expect(isDomainShaped(v)).toBe(true);
  });
  it.each(['sssl', 'localhost', '', 'no dots', 'has space.com'])('rejects %s', v => {
    expect(isDomainShaped(v)).toBe(false);
  });
});

describe('isPrivateAddress', () => {
  it.each([
    '127.0.0.1', '10.1.2.3', '192.168.1.1', '172.16.0.1', '172.31.255.255',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1',
  ])('flags %s as private', ip => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700::1', 'not-an-ip'])(
    'treats %s as public',
    ip => {
      expect(isPrivateAddress(ip)).toBe(false);
    },
  );
});

describe('assertPublicDomain', () => {
  it('rejects IP literals, localhost, and internal suffixes (no DNS needed)', async () => {
    await expect(assertPublicDomain('127.0.0.1')).rejects.toThrow(/IP address/i);
    await expect(assertPublicDomain('169.254.169.254')).rejects.toThrow(/IP address/i);
    await expect(assertPublicDomain('localhost')).rejects.toThrow(/internal/i);
    await expect(assertPublicDomain('db.internal')).rejects.toThrow(/internal/i);
    await expect(assertPublicDomain('sssl')).rejects.toThrow(/valid domain/i);
  });
});

describe('collectAdvisories', () => {
  it('flags a missing SSL certificate', () => {
    expect(collectAdvisories({ domain: 'x.com' })).toContain('No SSL certificate detected.');
  });

  it('flags an SSL certificate expiring soon', () => {
    const advisories = collectAdvisories({ domain: 'x.com', ssl: { daysUntilExpiry: 10 } });
    expect(advisories).toContain('SSL certificate expires in 10 days.');
  });

  it('is quiet for a healthy domain', () => {
    const advisories = collectAdvisories({
      domain: 'x.com',
      ssl: { daysUntilExpiry: 200 },
      whois: { registrationDate: '2005-01-01T00:00:00Z' },
    });
    expect(advisories).toEqual([]);
  });
});

describe('data predicates', () => {
  it('hasWhoisData ignores keys whose value is undefined', () => {
    expect(hasWhoisData({ expirationDate: undefined })).toBe(false);
    expect(hasWhoisData({ nameServers: [] })).toBe(false);
    expect(hasWhoisData({ registrar: 'X' })).toBe(true);
  });

  it('hasDnsData ignores empty arrays', () => {
    expect(hasDnsData({ a: [] })).toBe(false);
    expect(hasDnsData({ a: ['1.2.3.4'] })).toBe(true);
  });
});
