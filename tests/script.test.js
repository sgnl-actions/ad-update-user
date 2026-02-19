import { jest, describe, test, expect, beforeEach } from '@jest/globals';

const mockBind = jest.fn();
const mockUnbind = jest.fn();
const mockModify = jest.fn();
const mockSearch = jest.fn();

jest.unstable_mockModule('ldapts', () => ({
  Client: jest.fn().mockImplementation(() => ({
    bind: mockBind,
    unbind: mockUnbind,
    modify: mockModify,
    search: mockSearch
  })),
  Change: jest.fn().mockImplementation((opts) => ({
    operation: opts.operation,
    modification: opts.modification
  })),
  Attribute: jest.fn().mockImplementation((opts) => ({
    type: opts.type,
    values: opts.values
  })),
  EqualityFilter: jest.fn().mockImplementation((opts) => ({
    type: 'EqualityFilter',
    attribute: opts.attribute,
    value: opts.value
  })),
  AndFilter: jest.fn().mockImplementation((opts) => ({
    type: 'AndFilter',
    filters: opts.filters
  }))
}));

const mockGetBaseURL = jest.fn().mockReturnValue('ldaps://dc.example.com:636');

jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  getBaseURL: mockGetBaseURL
}));

const { default: script } = await import('../src/script.mjs');
const { Client } = await import('ldapts');

describe('AD Update User Script', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'ldaps://dc.example.com:636'
    },
    secrets: {
      LDAP_BIND_DN: 'CN=admin,DC=example,DC=com',
      LDAP_BIND_PASSWORD: 'password123'
    },
    outputs: {}
  };

  const defaultParams = {
    baseDN: 'DC=example,DC=com',
    samAccountName: 'jdoe'
  };

  const resolvedUserDN = 'CN=John Doe,OU=Users,DC=example,DC=com';

  beforeEach(() => {
    jest.clearAllMocks();
    mockBind.mockResolvedValue(undefined);
    mockUnbind.mockResolvedValue(undefined);
    mockModify.mockResolvedValue(undefined);
    mockGetBaseURL.mockReturnValue('ldaps://dc.example.com:636');
    // Default: user lookup returns one user
    mockSearch.mockResolvedValue({
      searchEntries: [{ dn: resolvedUserDN }]
    });
  });

  describe('invoke handler', () => {
    test('should successfully find user and update a single attribute', async () => {
      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'John Updated' }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.userDN).toBe(resolvedUserDN);
      expect(result.modified).toBe(true);
      expect(result.attributes).toEqual(['displayName']);

      // Verify search was called for sAMAccountName lookup
      expect(mockSearch).toHaveBeenCalledWith(defaultParams.baseDN, {
        scope: 'sub',
        filter: `(&(objectClass=user)(sAMAccountName=${defaultParams.samAccountName}))`,
        attributes: ['distinguishedName']
      });

      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          {
            operation: 'replace',
            modification: { type: 'displayName', values: ['John Updated'] }
          }
        ]
      );
    });

    test('should successfully update multiple attributes', async () => {
      const params = {
        ...defaultParams,
        additionalAttributes: {
          displayName: 'John Updated',
          mail: 'john.updated@example.com',
          department: 'Engineering'
        }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(['displayName', 'mail', 'department']);
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'displayName', values: ['John Updated'] } },
          { operation: 'replace', modification: { type: 'mail', values: ['john.updated@example.com'] } },
          { operation: 'replace', modification: { type: 'department', values: ['Engineering'] } }
        ]
      );
    });

    test('should throw when user not found by sAMAccountName', async () => {
      mockSearch.mockResolvedValue({ searchEntries: [] });

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        `User not found with sAMAccountName: ${defaultParams.samAccountName}`
      );
    });

    test('should throw when multiple users found with same sAMAccountName', async () => {
      mockSearch.mockResolvedValue({
        searchEntries: [
          { dn: 'CN=User1,OU=Users,DC=example,DC=com' },
          { dn: 'CN=User2,OU=Users,DC=example,DC=com' }
        ]
      });

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        `Multiple users found with sAMAccountName: ${defaultParams.samAccountName}. Expected exactly one.`
      );
    });

    test('should throw on empty additionalAttributes object', async () => {
      const params = {
        ...defaultParams,
        additionalAttributes: {}
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw on missing attributes', async () => {
      const params = {
        ...defaultParams
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should propagate LDAP error code 32 (no such object)', async () => {
      mockModify.mockRejectedValue(
        Object.assign(new Error('No such object'), { code: 32 })
      );

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('No such object');
    });

    test('should propagate bind failure and still call unbind', async () => {
      mockBind.mockRejectedValue(new Error('Bind failed: invalid credentials'));

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Bind failed: invalid credentials');
      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw on missing LDAP_BIND_DN', async () => {
      const context = {
        ...mockContext,
        secrets: { ...mockContext.secrets, LDAP_BIND_DN: '' }
      };

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, context)).rejects.toThrow('LDAP_BIND_DN secret is required');
    });

    test('should throw on missing LDAP_BIND_PASSWORD', async () => {
      const context = {
        ...mockContext,
        secrets: { ...mockContext.secrets, LDAP_BIND_PASSWORD: '' }
      };

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, context)).rejects.toThrow('LDAP_BIND_PASSWORD secret is required');
    });

    test('should set rejectUnauthorized false when TLS_SKIP_VERIFY is true', async () => {
      const context = {
        ...mockContext,
        environment: { ...mockContext.environment, TLS_SKIP_VERIFY: 'true' }
      };

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, context);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://dc.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: false }
      });
    });

    test('should set rejectUnauthorized to true for ldaps:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://dc.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: true }
      });
    });

    test('should not include tlsOptions for ldap:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      mockGetBaseURL.mockReturnValue('ldap://dc.example.com:389');

      const params = {
        ...defaultParams,
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldap://dc.example.com:389',
        timeout: 10000,
        connectTimeout: 10000
      });
    });

    test('should throw when baseDN is missing', async () => {
      const params = { samAccountName: 'jdoe', firstName: 'John' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('baseDN is required');
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw when neither samAccountName nor objectGUID is provided', async () => {
      const params = { baseDN: 'DC=example,DC=com', firstName: 'John' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Either samAccountName or objectGUID is required');
      expect(mockBind).not.toHaveBeenCalled();
    });
  });

  describe('named input parameters', () => {
    test('should map named params to LDAP attribute names without additionalAttributes object', async () => {
      const params = {
        ...defaultParams,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(expect.arrayContaining(['givenName', 'sn', 'mail']));
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        expect.arrayContaining([
          { operation: 'replace', modification: { type: 'givenName', values: ['John'] } },
          { operation: 'replace', modification: { type: 'sn', values: ['Doe'] } },
          { operation: 'replace', modification: { type: 'mail', values: ['john@example.com'] } }
        ])
      );
    });

    test('should merge named params with additionalAttributes object', async () => {
      const params = {
        ...defaultParams,
        firstName: 'John',
        additionalAttributes: {
          telephoneNumber: '+1-555-0100'
        }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(expect.arrayContaining(['telephoneNumber', 'givenName']));
    });

    test('should let named params override conflicting additionalAttributes keys', async () => {
      const params = {
        ...defaultParams,
        email: 'named@example.com',
        additionalAttributes: {
          mail: 'attributes@example.com'
        }
      };

      await script.invoke(params, mockContext);

      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'mail', values: ['named@example.com'] } }
        ]
      );
    });

    test('should map newSamAccountName to sAMAccountName LDAP attribute', async () => {
      const params = {
        ...defaultParams,
        newSamAccountName: 'johndoe'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('sAMAccountName');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'sAMAccountName', values: ['johndoe'] } }
        ]
      );
    });

    test('should map userPrincipalName to LDAP userPrincipalName', async () => {
      const params = {
        ...defaultParams,
        userPrincipalName: 'jdoe@example.com'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('userPrincipalName');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'userPrincipalName', values: ['jdoe@example.com'] } }
        ]
      );
    });
  });

  describe('password parameter', () => {
    test('should set unicodePwd as encoded Buffer when password is provided', async () => {
      const params = {
        ...defaultParams,
        password: 'P@ssw0rd123'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('unicodePwd');

      const modifyCall = mockModify.mock.calls[0];
      const unicodePwdChange = modifyCall[1].find(
        c => c.modification.type === 'unicodePwd'
      );
      expect(unicodePwdChange).toBeDefined();
      expect(unicodePwdChange.operation).toBe('replace');

      const pwdValue = unicodePwdChange.modification.values[0];
      expect(Buffer.isBuffer(pwdValue)).toBe(true);

      const expectedBuffer = Buffer.from('"P@ssw0rd123"', 'utf16le');
      expect(pwdValue).toEqual(expectedBuffer);
    });
  });

  describe('changePasswordAtNextLogin parameter', () => {
    test('should set pwdLastSet to 0 when changePasswordAtNextLogin is true', async () => {
      const params = {
        ...defaultParams,
        changePasswordAtNextLogin: true
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('pwdLastSet');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'pwdLastSet', values: ['0'] } }
        ]
      );
    });
  });

  describe('unbind error handling', () => {
    test('should handle unbind errors gracefully', async () => {
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      const params = {
        ...defaultParams,
        firstName: 'John'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.modified).toBe(true);
    });

    test('should not mask original error when unbind also fails', async () => {
      mockModify.mockRejectedValueOnce(new Error('Modify operation failed'));
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      const params = {
        ...defaultParams,
        firstName: 'John'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Modify operation failed');
    });
  });

  describe('dry run', () => {
    test('should return dry_run_completed when dry_run is true', async () => {
      const params = {
        ...defaultParams,
        firstName: 'John',
        dry_run: true
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('dry_run_completed');
      expect(result.baseDN).toBe(defaultParams.baseDN);
      expect(result.samAccountName).toBe(defaultParams.samAccountName);
      expect(result.userDN).toBe(null);
      expect(result.modified).toBe(false);
      expect(result.attributes).toContain('givenName');
      expect(mockBind).not.toHaveBeenCalled();
      expect(mockModify).not.toHaveBeenCalled();
    });
  });

  describe('error handler', () => {
    test('should re-throw error and log context', async () => {
      const error = new Error('LDAP connection failed');
      const params = {
        ...defaultParams,
        error
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('LDAP connection failed');
    });

    test('should wrap multiple users found errors', async () => {
      const error = new Error('Multiple users found with sAMAccountName');
      const params = {
        ...defaultParams,
        error
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('Multiple users found');
    });
  });

  describe('halt handler', () => {
    test('should return halted status with baseDN and samAccountName', async () => {
      const params = {
        ...defaultParams,
        reason: 'timeout'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.baseDN).toBe(defaultParams.baseDN);
      expect(result.samAccountName).toBe(defaultParams.samAccountName);
      expect(result.reason).toBe('timeout');
      expect(result.halted_at).toBeDefined();
    });

    test('should handle halt without baseDN and samAccountName', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.baseDN).toBe('unknown');
      expect(result.samAccountName).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
    });
  });

  describe('special characters in attributes', () => {
    test('should handle apostrophe in lastName (O\'Shea)', async () => {
      const params = {
        ...defaultParams,
        lastName: "O'Shea"
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'sn', values: ["O'Shea"] } }
        ]
      );
    });

    test('should handle dashes in department', async () => {
      const params = {
        ...defaultParams,
        department: 'team - engineering'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'department', values: ['team - engineering'] } }
        ]
      );
    });

    test('should handle forward slash in title', async () => {
      const params = {
        ...defaultParams,
        title: 'Sales/Marketing Lead'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          { operation: 'replace', modification: { type: 'title', values: ['Sales/Marketing Lead'] } }
        ]
      );
    });

    test('should escape backslash in samAccountName for LDAP filter', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        samAccountName: 'domain\\user',
        firstName: 'John'
      };

      mockSearch.mockImplementation((baseDN, options) => {
        expect(options.filter).toContain('domain\\5cuser');
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN }]
        });
      });

      await script.invoke(params, mockContext);
    });
  });

  describe('LDAP filter escaping', () => {
    test('should escape special characters in sAMAccountName for LDAP filter', async () => {
      const paramsWithSpecialChars = {
        baseDN: 'DC=example,DC=com',
        samAccountName: 'user*test(name)',
        firstName: 'John'
      };

      mockSearch.mockImplementation((baseDN, options) => {
        // Verify the filter contains escaped characters
        expect(options.filter).toContain('user\\2atest\\28name\\29');
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN }]
        });
      });

      await script.invoke(paramsWithSpecialChars, mockContext);
    });
  });

  describe('objectGUID-based lookup', () => {
    const testGUID = '550e8400-e29b-41d4-a716-446655440000';

    test('should encode objectGUID correctly as mixed-endian Buffer in EqualityFilter', async () => {
      // 550e8400-e29b-41d4-a716-446655440000
      // First group little-endian: 00,84,0e,55
      // Second group little-endian: 9b,e2
      // Third group little-endian: d4,41
      // Last two groups big-endian: a7,16,44,66,55,44,00,00
      const expectedBytes = [
        0x00, 0x84, 0x0e, 0x55,
        0x9b, 0xe2,
        0xd4, 0x41,
        0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00
      ];

      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: testGUID,
        firstName: 'John'
      };

      mockSearch.mockImplementation((_baseDN, options) => {
        // filter is an AndFilter object; find the objectGUID EqualityFilter
        const guidFilter = options.filter.filters.find(f => f.attribute === 'objectGUID');
        expect(guidFilter).toBeDefined();
        expect(Buffer.isBuffer(guidFilter.value)).toBe(true);
        expect([...guidFilter.value]).toEqual(expectedBytes);
        return Promise.resolve({ searchEntries: [{ dn: resolvedUserDN }] });
      });

      await script.invoke(params, mockContext);
    });

    test('should successfully look up user by objectGUID alone (no samAccountName)', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: testGUID,
        firstName: 'John'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.userDN).toBe(resolvedUserDN);
      expect(result.modified).toBe(true);
      // Filter is an AndFilter object (not a string) when using objectGUID
      const [[, searchOptions]] = mockSearch.mock.calls;
      expect(searchOptions.filter.type).toBe('AndFilter');
      expect(searchOptions.filter.filters.some(f => f.attribute === 'objectGUID')).toBe(true);
    });

    test('should use objectGUID for lookup when both samAccountName and objectGUID are provided', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        samAccountName: 'jdoe',
        objectGUID: testGUID,
        newSamAccountName: 'johndoe'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      // Filter must be an AndFilter (objectGUID path) not a sAMAccountName string filter
      const [[, searchOptions]] = mockSearch.mock.calls;
      expect(searchOptions.filter.type).toBe('AndFilter');
      expect(searchOptions.filter.filters.some(f => f.attribute === 'objectGUID')).toBe(true);
      expect(searchOptions.filter.filters.every(f => f.attribute !== 'sAMAccountName')).toBe(true);
      // sAMAccountName attribute is still updated on the user
      expect(result.attributes).toContain('sAMAccountName');
    });

    test('should reject invalid objectGUID format before making any LDAP connection', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: 'not-a-valid-guid',
        firstName: 'John'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'objectGUID must be in UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should reject objectGUID with wrong number of segments', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: '550e8400-e29b-41d4-a716',
        firstName: 'John'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'objectGUID must be in UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw when user not found by objectGUID', async () => {
      mockSearch.mockResolvedValue({ searchEntries: [] });

      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: testGUID,
        firstName: 'John'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        `User not found with objectGUID: ${testGUID}`
      );
    });

    test('should return dry_run_completed with objectGUID when dry_run is true', async () => {
      const params = {
        baseDN: 'DC=example,DC=com',
        objectGUID: testGUID,
        firstName: 'John',
        dry_run: true
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('dry_run_completed');
      expect(result.baseDN).toBe('DC=example,DC=com');
      expect(result.objectGUID).toBe(testGUID);
      expect(result.samAccountName).toBeNull();
      expect(result.userDN).toBeNull();
      expect(result.modified).toBe(false);
      expect(result.attributes).toContain('givenName');
      expect(mockBind).not.toHaveBeenCalled();
    });
  });
});
