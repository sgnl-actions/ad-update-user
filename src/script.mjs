/**
 * Active Directory Update User Action
 *
 * Updates attributes on an existing user in on-premise Active Directory using LDAP/LDAPS.
 * Supports updating any user attributes including password and enabled/disabled state.
 */

import { Client, Change, Attribute } from 'ldapts';
import { getBaseURL } from '@sgnl-actions/utils';

/**
 * Escape special characters in LDAP filter values to prevent injection.
 *
 * @param {string} str - The string to escape
 * @returns {string} The escaped string safe for use in LDAP filters
 */
function escapeLDAPFilter(str) {
  return str.replace(/[\\*()\0]/g, (char) => '\\' + char.charCodeAt(0).toString(16).padStart(2, '0'));
}

/**
 * Find a user's Distinguished Name by searching for their sAMAccountName.
 *
 * @param {Client} client - Bound ldapts Client instance
 * @param {string} baseDN - Base DN to search from
 * @param {string} samAccountName - User's sAMAccountName
 * @returns {Promise<string>} The user's Distinguished Name
 * @throws {Error} If user not found or multiple users found
 */
async function findUserDN(client, baseDN, samAccountName) {
  console.log(`Searching for user with sAMAccountName: ${samAccountName}`);

  const escapedSamAccountName = escapeLDAPFilter(samAccountName);
  const { searchEntries } = await client.search(baseDN, {
    scope: 'sub',
    filter: `(&(objectClass=user)(sAMAccountName=${escapedSamAccountName}))`,
    attributes: ['distinguishedName']
  });

  if (!searchEntries || searchEntries.length === 0) {
    throw new Error(`User not found with sAMAccountName: ${samAccountName}`);
  }

  if (searchEntries.length > 1) {
    throw new Error(`Multiple users found with sAMAccountName: ${samAccountName}. Expected exactly one.`);
  }

  const userDN = searchEntries[0].dn;
  console.log(`Found user DN: ${userDN}`);
  return userDN;
}

/**
 * Mapping from friendly parameter names to LDAP attribute names.
 * These are the commonly used AD user attributes.
 */
const PARAM_TO_LDAP = {
  newSamAccountName: 'sAMAccountName',
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
    new Change({
      operation: 'replace',
      modification: new Attribute({
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
  if (!client) {
    return;
  }
  try {
    await client.unbind();
  } catch (unbindError) {
    console.warn(`Warning: Error during LDAP unbind: ${unbindError.message}`);
  }
}

export default {
  /**
   * Main execution handler - updates a user in Active Directory.
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.baseDN - Base DN to search for the user
   * @param {string} params.samAccountName - User's sAMAccountName to lookup
   * @param {string} [params.newSamAccountName] - New SAM account name (if renaming)
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

    const { baseDN, samAccountName, dry_run = false } = params;

    // Validate required parameters
    if (!baseDN) {
      throw new Error('baseDN is required');
    }
    if (!samAccountName) {
      throw new Error('samAccountName is required');
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

    console.log(`Planning to update user with sAMAccountName: ${samAccountName}`);
    console.log(`Attributes to update: ${Object.keys(attributes).join(', ')}`);

    // Handle dry run - validate and return without making changes
    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        baseDN,
        samAccountName,
        userDN: null,
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

    const client = new Client(clientOptions);

    try {
      console.log(`Connecting to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);
      console.log('Successfully authenticated to LDAP server');

      // Lookup user DN by sAMAccountName
      const userDN = await findUserDN(client, baseDN, samAccountName);

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
   * @param {string} params.baseDN - The base DN being searched
   * @param {string} params.samAccountName - The sAMAccountName being looked up
   * @param {Object} _context - Execution context (unused)
   * @throws {Error} Re-throws with appropriate classification
   */
  error: async (params, _context) => {
    const { error, baseDN, samAccountName } = params;
    console.error(`Error handler invoked for user "${samAccountName}" in "${baseDN}": ${error.message}`);

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
      console.error('User not found - check samAccountName');
      throw new Error(`User not found: ${error.message}`);
    }

    // Multiple users found (fatal - don't retry)
    if (errorMessage.includes('multiple users found')) {
      console.error('Multiple users found - sAMAccountName should be unique');
      throw new Error(`Multiple users found: ${error.message}`);
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
   * @param {string} [params.baseDN] - The base DN being searched
   * @param {string} [params.samAccountName] - The sAMAccountName being looked up
   * @param {Object} _context - Execution context (unused)
   * @returns {Object} Cleanup results with halted status
   */
  halt: async (params, _context) => {
    const { reason, baseDN, samAccountName } = params;
    console.log(`Active Directory update user operation halted: ${reason}`);

    return {
      status: 'halted',
      baseDN: baseDN || 'unknown',
      samAccountName: samAccountName || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};
