import { jest } from '@jest/globals';

// Mock ldapts module BEFORE importing runLDAPScenarios
jest.unstable_mockModule('ldapts', () => ({
  Client: jest.fn().mockImplementation(() => ({
    bind: jest.fn().mockResolvedValue(),
    unbind: jest.fn().mockResolvedValue(),
    modify: jest.fn().mockResolvedValue(),
    search: jest.fn().mockResolvedValue({ searchEntries: [] }),
    add: jest.fn().mockResolvedValue(),
    delete: jest.fn().mockResolvedValue(),
    modifyDN: jest.fn().mockResolvedValue(),
    compare: jest.fn().mockResolvedValue(),
    connect: jest.fn().mockResolvedValue(),
    disconnect: jest.fn().mockResolvedValue(),
    startTLS: jest.fn().mockResolvedValue()
  })),
  Change: jest.fn().mockImplementation((opts) => ({
    operation: opts.operation,
    modification: opts.modification
  })),
  Attribute: jest.fn().mockImplementation((opts) => ({
    type: opts.type,
    values: opts.values
  })),
  // Filter classes - essential for complex LDAP queries like objectGUID searches
  EqualityFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    value: opts.value,
    toString: () => `(${opts.attribute}=${opts.value})`
  })),
  AndFilter: jest.fn().mockImplementation((opts) => ({
    filters: opts.filters || [],
    toString: () => `(&${(opts.filters || []).map(f => f.toString ? f.toString() : f).join('')})`
  })),
  OrFilter: jest.fn().mockImplementation((opts) => ({
    filters: opts.filters || [],
    toString: () => `(|${(opts.filters || []).map(f => f.toString ? f.toString() : f).join('')})`
  })),
  NotFilter: jest.fn().mockImplementation((opts) => ({
    filter: opts.filter,
    toString: () => `(!${opts.filter?.toString ? opts.filter.toString() : opts.filter})`
  })),
  PresenceFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    toString: () => `(${opts.attribute}=*)`
  })),
  SubstringFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    initial: opts.initial,
    any: opts.any,
    final: opts.final,
    toString: () => `(${opts.attribute}=*substring*)`
  })),
  GreaterThanEqualsFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    value: opts.value,
    toString: () => `(${opts.attribute}>=${opts.value})`
  })),
  LessThanEqualsFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    value: opts.value,
    toString: () => `(${opts.attribute}<=${opts.value})`
  })),
  ApproximateFilter: jest.fn().mockImplementation((opts) => ({
    attribute: opts.attribute,
    value: opts.value,
    toString: () => `(${opts.attribute}~=${opts.value})`
  })),
  ExtensibleFilter: jest.fn().mockImplementation((opts) => opts),
  DN: jest.fn().mockImplementation((dn) => ({
    toString: () => dn || ''
  })),
  Filter: jest.fn().mockImplementation((opts) => opts),
  // Common LDAP error classes
  ResultCodeError: jest.fn(),
  NoSuchObjectError: jest.fn(),
  InvalidCredentialsError: jest.fn(),
  InsufficientAccessError: jest.fn(),
  NoSuchAttributeError: jest.fn(),
  ConstraintViolationError: jest.fn(),
  AlreadyExistsError: jest.fn(),
  UnwillingToPerformError: jest.fn(),
  SizeLimitExceededError: jest.fn(),
  TimeLimitExceededError: jest.fn(),
  InvalidSyntaxError: jest.fn(),
  OperationsError: jest.fn(),
  ProtocolError: jest.fn(),
  BusyError: jest.fn(),
  UnavailableError: jest.fn(),
  SearchEntry: jest.fn(),
  SearchResponse: jest.fn(),
  ModifyRequest: jest.fn(),
  ModifyResponse: jest.fn(),
  AddRequest: jest.fn(),
  AddResponse: jest.fn(),
  DeleteRequest: jest.fn(),
  DeleteResponse: jest.fn(),
  BindRequest: jest.fn(),
  BindResponse: jest.fn()
}));

// Now import and run the testing framework
const { runLDAPScenarios } = await import('@sgnl-actions/testing/ldap-scenarios');

runLDAPScenarios({
  script: './src/script.mjs',
  scenarios: './tests/scenarios.yaml'
});