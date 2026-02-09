// SGNL Job Script - Auto-generated bundle
'use strict';

var ldapts = require('ldapts');

/**
 * SGNL Actions - Authentication Utilities
 *
 * Shared authentication utilities for SGNL actions.
 * Supports: Bearer Token, Basic Auth, OAuth2 Client Credentials, OAuth2 Authorization Code
 */


/**
 * Get the base URL/address for API calls
 * @param {Object} params - Request parameters
 * @param {string} [params.address] - Address from params
 * @param {Object} context - Execution context
 * @returns {string} Base URL
 */
function getBaseURL(params, context) {
  const env = context.environment || {};
  const address = params?.address || env.ADDRESS;

  if (!address) {
    throw new Error('No URL specified. Provide address parameter or ADDRESS environment variable');
  }

  // Remove trailing slash if present
  return address.endsWith('/') ? address.slice(0, -1) : address;
}

/**
 * Active Directory Update User Action
 *
 * Updates attributes on an existing user in on-premise Active Directory using LDAP/LDAPS.
 * Supports updating any user attributes including password and enabled/disabled state.
 */


/**
 * Mapping from friendly parameter names to LDAP attribute names.
 * These are the commonly used AD user attributes.
 */
const PARAM_TO_LDAP = {
  samAccountName: 'sAMAccountName',
  userPrincipalName: 'userPrincipalName',
  firstName: 'givenName',
  lastName: 'sn',
  displayName: 'displayName',
  email: 'mail',
  company: 'company',
  department: 'department',
  title: 'title'
};

/**
 * Encode a password for Active Directory using UTF-16LE format.
 * AD requires passwords to be wrapped in quotes and encoded as UTF-16LE.
 *
 * @param {string} password - The plaintext password
 * @returns {Buffer} The encoded password buffer
 */
function encodePassword(password) {
  const quotedPassword = `"${password}"`;
  return Buffer.from(quotedPassword, 'utf16le');
}

/**
 * Build LDAP attributes object from params, mapping friendly names to LDAP names.
 * Named params override conflicting additionalAttributes keys.
 *
 * @param {Object} params - The input parameters
 * @returns {Object} The LDAP attributes object
 */
function buildAttributes(params) {
  // Start with additionalAttributes, then overlay named params
  const merged = { ...(params.additionalAttributes || {}) };
  for (const [param, ldapName] of Object.entries(PARAM_TO_LDAP)) {
    if (params[param] !== undefined) {
      merged[ldapName] = params[param];
    }
  }
  return merged;
}

/**
 * Update user attributes in Active Directory using replace operations.
 *
 * @param {string} userDN - Distinguished Name of the user
 * @param {Object} attributes - Attributes to update
 * @param {Client} client - Bound ldapts Client instance
 */
async function updateUserAttributes(userDN, attributes, client) {
  const changes = Object.entries(attributes).map(([key, value]) =>
    new ldapts.Change({
      operation: 'replace',
      modification: new ldapts.Attribute({
        type: key,
        values: Array.isArray(value) ? value : [value]
      })
    })
  );

  await client.modify(userDN, changes);
}

/**
 * Safely disconnect from LDAP server.
 * Errors during unbind are logged but not thrown to avoid masking original errors.
 *
 * @param {Client} client - The ldapts client
 */
async function safeUnbind(client) {
  try {
    await client.unbind();
  } catch (unbindError) {
    console.warn(`Warning: Error during LDAP unbind: ${unbindError.message}`);
  }
}

var script = {
  /**
   * Main execution handler - updates a user in Active Directory.
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.userDN - Distinguished Name of the user to update
   * @param {string} [params.samAccountName] - SAM account name
   * @param {string} [params.userPrincipalName] - User principal name
   * @param {string} [params.firstName] - First name (givenName)
   * @param {string} [params.lastName] - Last name (sn)
   * @param {string} [params.displayName] - Display name
   * @param {string} [params.email] - Email address (mail)
   * @param {string} [params.company] - Company name
   * @param {string} [params.department] - Department name
   * @param {string} [params.title] - Job title
   * @param {string} [params.password] - New password (will be encoded)
   * @param {boolean} [params.changePasswordAtNextLogin] - Force password change at next login
   * @param {Object} [params.additionalAttributes] - Additional LDAP attributes to update
   * @param {boolean} [params.dry_run] - If true, validate without making changes
   * @param {Object} context - Execution context with environment and secrets
   * @returns {Object} Job results including status, userDN, and modified flag
   */
  invoke: async (params, context) => {
    console.log('Starting Active Directory update user operation');

    const { userDN, dry_run = false } = params;

    // Validate required parameters
    if (!userDN) {
      throw new Error('userDN is required');
    }

    // Build attributes from params
    const attributes = buildAttributes(params);

    // Add special attributes
    if (params.password) {
      attributes.unicodePwd = encodePassword(params.password);
      console.log('Password will be updated');
    }
    if (params.changePasswordAtNextLogin) {
      attributes.pwdLastSet = '0';
      console.log('User will be required to change password at next login');
    }

    // Validate at least one attribute is being updated
    if (!attributes || typeof attributes !== 'object' || Object.keys(attributes).length === 0) {
      throw new Error('At least one attribute must be provided');
    }

    console.log(`Planning to update user: ${userDN}`);
    console.log(`Attributes to update: ${Object.keys(attributes).join(', ')}`);

    // Handle dry run - validate and return without making changes
    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        userDN,
        modified: false,
        attributes: Object.keys(attributes)
      };
    }

    // Get LDAP connection details
    const address = getBaseURL(params, context);
    const bindDN = context.secrets.LDAP_BIND_DN;
    const bindPassword = context.secrets.LDAP_BIND_PASSWORD;

    // Validate required secrets
    if (!bindDN) {
      throw new Error('LDAP_BIND_DN secret is required');
    }
    if (!bindPassword) {
      throw new Error('LDAP_BIND_PASSWORD secret is required');
    }

    // Configure LDAP client with timeouts
    const clientOptions = {
      url: address,
      timeout: 10000,
      connectTimeout: 10000
    };

    // Configure TLS options for secure connections
    if (address.startsWith('ldaps://') || context.environment?.TLS_SKIP_VERIFY === 'true') {
      clientOptions.tlsOptions = {
        rejectUnauthorized: context.environment?.TLS_SKIP_VERIFY !== 'true'
      };
    }

    const client = new ldapts.Client(clientOptions);

    try {
      console.log(`Connecting to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);
      console.log('Successfully authenticated to LDAP server');

      console.log(`Updating user: ${userDN}`);
      await updateUserAttributes(userDN, attributes, client);

      console.log(`Successfully updated user: ${userDN}`);
      return {
        status: 'success',
        userDN,
        modified: true,
        attributes: Object.keys(attributes),
        address
      };
    } catch (error) {
      console.error(`Failed to update user: ${error.message}`);
      throw error;
    } finally {
      await safeUnbind(client);
    }
  },

  /**
   * Error recovery handler - classifies errors and determines retry behavior.
   *
   * @param {Object} params - Original params plus error information
   * @param {Error} params.error - The error that occurred
   * @param {string} params.userDN - The user DN being updated
   * @param {Object} _context - Execution context (unused)
   * @throws {Error} Re-throws with appropriate classification
   */
  error: async (params, _context) => {
    const { error, userDN } = params;
    console.error(`Error handler invoked for user "${userDN}": ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check LDAP_BIND_DN and LDAP_BIND_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable - framework will retry)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // User not found (fatal - don't retry)
    if (errorMessage.includes('no such object') ||
        errorMessage.includes('not found')) {
      console.error('User not found - check userDN');
      throw new Error(`User not found: ${error.message}`);
    }

    // Constraint violations (fatal - don't retry)
    if (errorMessage.includes('constraint violation') ||
        errorMessage.includes('invalid syntax')) {
      console.error('Data validation error - check input parameters');
      throw new Error(`Invalid attribute data: ${error.message}`);
    }

    // Insufficient permissions (fatal - don't retry)
    if (errorMessage.includes('insufficient access') ||
        errorMessage.includes('permission denied')) {
      console.error('Insufficient permissions - check service account privileges');
      throw new Error(`Insufficient LDAP permissions: ${error.message}`);
    }

    // Unknown error - re-throw for framework retry
    console.error('Unknown error occurred, allowing framework to retry');
    throw error;
  },

  /**
   * Graceful shutdown handler - called when the job is halted.
   *
   * @param {Object} params - Original params plus halt reason
   * @param {string} params.reason - The reason for the halt
   * @param {string} [params.userDN] - The user DN being updated
   * @param {Object} _context - Execution context (unused)
   * @returns {Object} Cleanup results with halted status
   */
  halt: async (params, _context) => {
    const { reason, userDN } = params;
    console.log(`Active Directory update user operation halted: ${reason}`);

    return {
      status: 'halted',
      userDN: userDN || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};

module.exports = script;
