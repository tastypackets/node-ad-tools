const ldap = require('ldapjs');

/** This class will authenticate a user to AD and return basic user information */
class ActiveDirectory {
    /**
     * Create a new Active Directory object for manging AD connections
     * @param {string} url URL / IP of the Active Directory server
     * @param {string} base The default base to use when one is not provided on a method
     * @param {object} [searchOptions] The search options passed down to ldapjs, see http://ldapjs.org/client.html#search for details.
     * @param {string} [searchOptions.scope='sub'] What scope should the Active Directory be searched in
     * @param {string} [searchOptions.filter=(objectclass=*)] A string version of an LDAP filter
     * @param {number} [searchOptions.sizeLimit=0] Mximum number of entries to return, 0 = unlimited
     * @param {number} idleTimeout How long to wait idle before timing out
     * @param {object} tlsOptions The NodeJS TLS options object, see https://nodejs.org/api/tls.html#tls_tls_connect_options_callback for details.
     */
    constructor({ url, suffix = '', base = '', searchOptions = {scope: 'sub'}, idleTimeout = 3000, tlsOptions = {} }){
        // Switching to proper name base, leaving suffix as backwards compat until v2
        this.base = base;
        if(suffix.length !== 0 && base.length === 0) {
            console.log('Deprecation warning: API suffix was renamed to base, suffix param will be removed in v2.')
            this.base = suffix;
        }

        this.searchOptions = searchOptions;

        this.ldapjsSettings = {
            url,
            idleTimeout,
            tlsOptions
        };
    }

    /**
     * Turns AD bind errors into friendlier error messages
     * @param {string} error Error returned from ldapjs / AD when attempting to bing
     * @returns {string} Error explanation string
     */
    static resolveBindError(error) {
        if(error.name !== 'InvalidCredentialsError' || !error.lde_message)
            return 'Unknown Auth Error'

        if (error.lde_message.indexOf('775') !== -1)
            return 'Account is locked out';
        
        return 'Invalid username or password';
    }

    /**
     * Resolves AD group membership
     * @param {object} entry This is an entry returned from loginAdUser
     * @returns {string[]} An array of string group names
     */
    static resolveGroups(entry) {
        if(typeof entry.object !== 'object')
            throw new Error('Invalid entry, entry.object must be an object');

        const memberOf = entry.object.memberOf;
        if(memberOf === undefined) {
            return [];
        } else if(typeof memberOf === 'string') {
            // If only 1 OU ldapjs returns it as a string
            return memberOf.split(',')
                .filter(item => item.indexOf('CN=') !== -1)
                .map(item => item.split('CN=')[1])

        } else if(Array.isArray(memberOf)) {
            return memberOf.map(group => group.split(',')[0].split('CN=')[1]);
        }

        return [];
    }

    /**
     * Locates objectGUID and then formats it
     * @param {object} entry This is an entry returned from loginAdUser
     * @returns {string} Formated GUID string
     */
    static resolveGUID(entry){
        if(!Array.isArray(entry.attributes))
            throw new Error('Attributes must be an array');

        const binaryGUID = entry.attributes.find(attribute => attribute.type === 'objectGUID').buffers[0];
        const guidFormat = [
            [3,2,1,0],
            [5,4],
            [7,6],
            [8,9],
            [10,11,12,13,14,15]
        ];
    
        const guidArray = guidFormat.map( part => {
            const stringPart = part.map(byte => {
                // If less than 16 add a 0 to the end
                const byteString = binaryGUID[byte] < 16 ?
                    `0${binaryGUID[byte].toString(16)}` :
                    binaryGUID[byte].toString(16)

                return byteString
            });
            return `${stringPart.join('')}`;
        });
        return guidArray.join('-');
    }

    /**
     * Creates a standard user object from ldapjs entry response
     * @param {object} entry This is an entry returned from loginAdUser
     * @returns {object} User object { groups: Array, phone: string, name: string, mail: string, guid: string }
     */
    static createUserObj(entry){
        if(typeof entry !== 'object')
            throw new Error('Entry must be an object')

        return {
            groups: ActiveDirectory.resolveGroups(entry),
            phone: entry.object.telephoneNumber || '',
            name: entry.object.name || '',
            mail: entry.object.mail || '',
            guid: ActiveDirectory.resolveGUID(entry),
            dn: entry.objectName
        };
    }

    /**
     * Detects what type of account name this is or defaults to userLogonName
     * @param {string} username The user name being used to bind
     * @returns {string} Returns userPrincipalName || distinguishedName || sAMAccountName
     */
    static detectLogonType(username) {
        if(username.indexOf('@') !== -1) {
            return 'userPrincipalName';
        } else if(username.toUpperCase().indexOf('DC=') !== -1) {
            return 'distinguishedName';
        } else {
            return 'sAMAccountName';
        }
    }


    /**
     * Converts the ActiveDirectory / LDAP fields whenCreated & whenChanged to JS dates
     * @param {string} date 
     * @returns {Date} ISO formatted date
     */
    static convertToDate(date) {
        const year = date.slice(0,4);
        const month = date.slice(4,6);
        const day = date.slice(6, 8);
        const hour = date.slice(8, 10);
        const min = date.slice(10, 12);
        const sec = date.slice(12, 14);

        return new Date(`${year}-${month}-${day}T${hour}:${min}:${sec}.000Z`);
    }

    /**
     * Cleans sAMAccountName
     * @param {string} sAMA 
     * @returns {string} sAMAccountName
     */
    static cleanSama(sAMA) {
        const parts = sAMA.split('\\') // Extracts any appended domain
        return parts[parts.length - 1] // This returns 0 if there was no domain provided or returns 1 if domain was provided
    }

    /**
     * Performs a bind on the client passed in
     * @param {ldap.Client} client LDAPjs client obj
     * @param {string} username Username to bind with
     * @param {string} password Password to bind with
     * @returns {Promise} Resolvs with LDAPjs response
     * @throws {Error} If username or password are not a string
     */
    _bind(client, username, password) {
        if(typeof username !== 'string' || typeof password !== 'string') {
            const err = new Error('Usrname and password must be a string');
            err.name = 'InvalidCredentialsError';
            err.lde_message = 'Usrname and password must be a string';
            throw err;
        }

        return new Promise((resolve, reject) => {
            client.bind(username, password, (err, res) => {
                if (err) {
                    reject(err);
                    return;
                }

                resolve(res);
            })
        })
    }

    /**
     * Performs a search on a client
     * @param {ldap.Client} client LDAPjs client obj
     * @param {string} base The base to perform the search on
     * @param {object} search The search options to use
     */
    _search(client, customBase, search) {
        return new Promise((resolve, reject) => {
            const base = typeof customBase === 'string' && customBase ? customBase : this.base;

            let accumulator = [];
            //TODO Add check if client is bind
            client.search(base, search, (error, res) => {
                if(error) {
                    reject(err);
                    return;
                }

                res.on('searchEntry', entry => {
                    accumulator.push(entry);
                });

                res.on('end', res => {
                    resolve(accumulator);
                    return;
                })

                res.on('error', error => {
                    reject(error);
                    return;
                });
            })
        })
    }

    /**
     * Attempts to authenticate 1 user to AD using their UPN.
     * If the ldap client has an error a user friendly message is in message and the full error is in error.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string} customBase Override the default class base, if not passed the class base is used.
     * @param {string} customSearch A custom search string, e.g. (userPrincipalName=test@domain.local)
     * @returns {Promise<object>} Promise resolves as an obj { success: true, entry: {} || undefined } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
    async loginUser(username, password, customBase, customSearch) {
        try {
            const client = ldap.createClient(this.ldapjsSettings);
            const usernameType = ActiveDirectory.detectLogonType(username);
            const searchUser = usernameType === 'sAMAccountName' ? ActiveDirectory.cleanSama(username) : username;
            const search = {
                ...this.searchOptions,
                filter: `(${usernameType}=${searchUser})`,
                ...customSearch // Overrides any other search options
            };
    
            // Return errors
            client.on('error', error => {
                client.unbind();
                return { success: false, message: 'Error resolving account', error };
            });
    
            // Bind to AD - error thrown if invalid login
            await this._bind(client, username, password);
    
            // Search AD for user
            const records = await this._search(client, customBase, search);
            
            // We only expect 1 user acct
            return { success: true, entry: records[0] };
        } catch(err) {
            return { success: false, message: ActiveDirectory.resolveBindError(err), error: err };
        }
    }

    /**
     * Attempts to get all groups from AD that the user has permissions to read and match filter.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string=} customBase Override the default class base, if not passed the class base is used.
     * @param {boolean} detailed Indicates if you want the detailed groups objects with name, dn, guid, description, created, and changed values
     * @returns {Promise<object>} Promise resolves as an obj { success: true, groups: [string] } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
    async getAllGroups(username, password, customBase, detailed) {
        try {
            // For backwards compatability until v2
            if(detailed === undefined && typeof customBase === 'boolean')
                detailed = customBase;

            const attributes = detailed ? ['name','dn','objectGUID','description','whenCreated','whenChanged'] : 'name';
            const client = ldap.createClient(this.ldapjsSettings);
            const customSearch = {
                ...this.searchOptions,
                filter: `(objectCategory=group)`,
                attributes
            };

            // Return errors
            client.on('error', error => {
                client.unbind();
                return { success: false, message: 'Error resolving groups', error };
            });

            // Bind to AD - error thrown if invalid login
            await this._bind(client, username, password);

            // Search AD for groups
            const records = await this._search(client, customBase, customSearch);

            function getDetails(records) {
                return records.map(entry => {
                    return {
                        name: entry.object.name,
                        dn: entry.object.dn,
                        guid: ActiveDirectory.resolveGUID(entry),
                        description: entry.object.description,
                        created: ActiveDirectory.convertToDate(entry.object.whenCreated),
                        changed: ActiveDirectory.convertToDate(entry.object.whenChanged)
                    }
                });
            }

            return {
                success: true,
                groups: detailed ? getDetails(records) : records.map(entry => entry.object.name)
            }

        } catch (err) {
            return { success: false, message: ActiveDirectory.resolveBindError(err), error: err };
        }
    }

    /**
     * Attempts to get all users from AD that the user has permissions to read and match filter.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string=} customBase Override the default class base, if not passed the class base is used.
     * @param {boolean} formatted Indicates if you;d like your response formatted as user objects
     * @returns {Promise<object>} Promise resolves as an obj { success: true, users: [object] } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
    async getAllUsers(username, password, customBase, formatted) {
        try {
            // For backwards compatability until v2
            if(formatted === undefined && typeof customBase === 'boolean')
                formatted = customBase;

            const client = ldap.createClient(this.ldapjsSettings);
            const customSearch = {
                ...this.searchOptions,
                filter: `(&(objectClass=user)(objectCategory=person))`
            };

            // Return errors
            client.on('error', error => {
                client.unbind();
                return { success: false, message: 'Error resolving users', error };
            });

            // Bind to AD - error thrown if invalid login
            await this._bind(client, username, password);

            // Search AD for groups
            let records = await this._search(client, customBase, customSearch);

            // Create formatted AD users if user requested them
            if(formatted)
                records = records.map(entry => ActiveDirectory.createUserObj(entry));

            return {
                success: true,
                users: records
            };
        } catch (err) {
            return { success: false, message: ActiveDirectory.resolveBindError(err), error: err };
        }
    }
}

exports.ActiveDirectory = ActiveDirectory;