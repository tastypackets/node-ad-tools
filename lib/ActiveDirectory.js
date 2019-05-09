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
        if(suffix.length > 1 && base.length === 0) {
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
            guid: ActiveDirectory.resolveGUID(entry)
        };
    }

    /**
     * Attempts to authenticate 1 user to AD using their UPN.
     * If the ldap client has an error a user friendly message is in message and the full error is in error.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string=} customBase Override the default class base, if not passed the class base is used.
     * @returns {Promise<object>} Promise resolves as an obj { success: true, entry: {} } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
    loginUser(username, password, customBase) {
        return new Promise((resolve, reject) => {
            const client = ldap.createClient(this.ldapjsSettings);
            const base = typeof customBase === 'string' ? customBase : this.base;
            // This part was modified to support custom search filters.
            let customSearch = {};
            if (!this.searchOptions.filter) customSearch = {
                ...this.searchOptions,
                filter: `(userPrincipalName=${username})`
            } 
            else {
                customSearch = {
                    ...this.searchOptions
                }
            };
    
            // Return errors
            client.on('error', error => {
                client.unbind();
                reject({success: false, message: 'Error resolving account', error});
            });
    
            // Return user object
            client.on('searchEntry', entry => {
                client.unbind();
                resolve({success: true, entry});
            });

            // No results
            client.on('end', err => {
                client.unbind();
                
                resolve({
                    success: false,
                    message: 'Error resolving account'
                })
            });
    
            // Login the user
            client.bind(username,password, (err,res) => {
                if(err){
                    resolve({
                        success: false,
                        message: ActiveDirectory.resolveBindError(err),
                        error: err
                    });
                    return;
                }
    
                // This is a second emitter insider the ldapjs search, it is set to emit to the,
                // first emitter on client. It's ugly and should be made nicer one day.
                client.search(base, customSearch, (error, res) => {
                    if(error) {
                        client.emit('error', error);
                    }
    
                    res.on('searchEntry', entry => {
                        client.emit('searchEntry',entry);
                    });

                    res.on('end', res => {
                        client.emit('end', res)
                    })
    
                    res.on('error', error => {
                        client.emit('error', error);
                    });
                });
            });
    
        });
    }

    /**
     * Attempts to get all groups from AD that the user has permissions to read and match filter.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string=} customBase Override the default class base, if not passed the class base is used.
     * @returns {Promise<object>} Promise resolves as an obj { success: true, groups: [string] } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
    getAllGroups(username, password, customBase) {
        // TODO: Clean-up in v2 - duplicate code here and weird creation of entry below to resolve groups
        return new Promise((resolve, reject) => {
            const client = ldap.createClient(this.ldapjsSettings);
            const base = typeof customBase === 'string' ? customBase : this.base;
            const customSearch = { 
                ...this.searchOptions,
                filter: `(objectCategory=group)`
            };

            let groups = []
    
            // Return errors
            client.on('error', error => {
                client.unbind();
                reject({success:false, message:'Error resolving groups', error});
            });
    
            // Return user object
            client.on('searchEntry', entry => {
                groups.push(entry.objectName);
            });

            // No more results
            client.on('end', err => {
                client.unbind();
                // Simulate an entry resp, so we don't have to break older API
                const entry = {
                    object: {
                        memberOf: groups
                    }
                }

                resolve({
                    success: true,
                    groups: ActiveDirectory.resolveGroups(entry)
                })
            });
    
            // Login the user
            client.bind(username,password, (err,res) => {
                if(err){
                    resolve({
                        success: false,
                        message: ActiveDirectory.resolveBindError(err),
                        error: err
                    });
                    return;
                }
    
                // This is a second emitter insider the ldapjs search, it is set to emit to the,
                // first emitter on client. It's ugly and should be made nicer one day.
                client.search(base, customSearch, (error, res) => {
                    if(error) {
                        client.emit('error', error);
                    }
    
                    res.on('searchEntry', entry => {
                        client.emit('searchEntry',entry);
                    });
    
                    res.on('end', res => {
                        client.emit('end', res)
                    })

                    res.on('error', error => {
                        client.emit('error', error);
                    });
                });
            });
        });
    }

    /**
     * Attempts to get all users from AD that the user has permissions to read and match filter.
     * @param {string} username This must be the UPN
     * @param {string} password The users password
     * @param {string=} customBase Override the default class base, if not passed the class base is used.
     * @returns {Promise<object>} Promise resolves as an obj { success: true, users: [object] } || { success: false, message: 'error', error: 'ldapjs error' } 
     */
     getAllUsers(username, password, customBase) {
        // TODO: Clean-up in v2 - duplicate code here and weird creation of entry below to resolve users
        return new Promise((resolve, reject) => {
            const client = ldap.createClient(this.ldapjsSettings);
            const base = typeof customBase === 'string' ? customBase : this.base;
            const customSearch = { 
                ...this.searchOptions,
                filter: `(&(objectClass=user)(objectCategory=person))`
            };
            
            let users = []
            
            // Return errors
            client.on('error', error => {
                client.unbind();
                reject({success:false, message:'Error resolving users', error});
            });
            
            // Return user object
            client.on('searchEntry', entry => {
                users.push(entry);
            });
            
            // No more results
            client.on('end', err => {
                client.unbind();
                // Simulate an entry resp, so we don't have to break older API
                
                resolve({
                    success: true,
                    users
                })
            });
            
            // Login the user
            client.bind(username,password, (err,res) => {
                if(err){
                    resolve({
                        success: false,
                        message: ActiveDirectory.resolveBindError(err),
                        error: err
                    });
                    return;
                }
                
                // This is a second emitter insider the ldapjs search, it is set to emit to the,
                // first emitter on client. It's ugly and should be made nicer one day.
                client.search(base, customSearch, (error, res) => {
                    if(error) {
                        client.emit('error', error);
                    }
                    
                    res.on('searchEntry', entry => {
                        client.emit('searchEntry',entry);
                    });
                    
                    res.on('end', res => {
                        client.emit('end', res)
                    })
                    
                    res.on('error', error => {
                        client.emit('error', error);
                    });
                });
            });
        });
    }
}

exports.ActiveDirectory = ActiveDirectory;