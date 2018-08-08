const ldap = require('ldapjs');

/**
 * This class will authenticate a user to AD and return basic user information
 * @param {Object} // {server, suffix, searchOptions, idleTimeout, tlsOptions, verifyCert}
 * 
 */
class ActiveDirectory {
    constructor({ url, suffix, searchOptions = {scope: 'sub'}, idleTimeout = 3000, tlsOptions = {} }){
        this.suffix = suffix;
        this.searchOptions = searchOptions;

        this.ldapjsSettings = {
            url,
            idleTimeout,
            tlsOptions
        };
    }

    /**
     * Turns AD bind errors into friendlier error messages
     * @param {String} error
     * @returns {String} Error explenation string
     */
    static resolveBindError(error) {
        if(error.name !== 'InvalidCredentialsError' || !error.lde_message)
            return 'Unkown Auth Error'

        if (error.lde_message.indexOf('775') !== -1)
            return 'Account is locked out';
        
        return 'Invalid username or password';
    }

    /**
     * Resolves AD group membership
     * @param {Object} entry This is an entry returned from loginAdUser
     * @returns {Array} An array of string group names
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
     * @param {Object} entry This is an entry returned from loginAdUser
     * @returns {String} Formated GUID string
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
     * @param {Object} entry 
     * @returns {Object} User object { groups: Array, phone: String, name: String, mail: String, guid: String }
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
     * @param {String} username This must be the UPN!
     * @param {String} password 
     * @returns {Promise} Promise resolves as an obj { success: boolean, message: 'error' || { entry }, Optional client error }
     */
    loginUser(username, password) {
        return new Promise((resolve, reject) => {
            const client = ldap.createClient(this.ldapjsSettings);
            const customSearch = { 
                ...this.searchOptions, // Avoid mutation
                filter: `(userPrincipalName=${username})`
            };
    
            // Return errors
            client.on('error', error => {
                client.unbind();
                reject({success:false, message:'Error resolving account', error});
            });
    
            // Return user object
            client.on('searchEntry', entry => {
                client.unbind();
                resolve({success:true, entry});
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
                client.search(this.suffix, customSearch, (error, res) => {
                    if(error) {
                        client.emit('error', error);
                    }
    
                    res.on('searchEntry', entry => {
                        client.emit('searchEntry',entry);
                    });
    
                    res.on('error', error => {
                        client.emit('error', error);
                    });
                });
            });
    
        });
    }

    /**
     * Attempts to get all groups from AD that the user has permissions to read and match filter.
     * @param {String} username This must be the UPN!
     * @param {String} password 
     * @returns {Promise} Promise resolves as an obj { success: boolean, message: 'error' || { entry }, Optional client error }
     */
    getAllGroups(username, password) {
        // TODO: Clean-up in v2 - duplciated code here and weird creation of entry below to resolve groups
        return new Promise((resolve, reject) => {
            const client = ldap.createClient(this.ldapjsSettings);
            const customSearch = { 
                ...this.searchOptions, // Avoid mutation
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
                client.search(this.suffix, customSearch, (error, res) => {
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