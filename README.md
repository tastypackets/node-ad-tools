# ad-tools
NodeJS Active Directory authentication and tools. - **Requires ES6 support**

This is a simple wrapper around ldapjs, which is a full ldap server & client. For custom or advanced setups please see https://github.com/joyent/node-ldapjs. This is highly opinionated and lacking in may features right now, but should work for simple AD authentication.

PR's that improve the project a welcomed, right now development is primarily on an as-needed basis.

# API
## Install
`yarn add ad-tools`

### Setup AD
The active directory class requires a basic configuration object that will inform ldapjs of the binding and searching parameters. This is configured once by creating a new ActiveDirectory object, if you need to change these settings dynamically you can construct the object right before performing the auth.

```javascript
{
    url: 'ldap://192.168.1.1',
    suff: 'dc=domain,dc=local',
    searchOptions: {scope: 'sub'},
    idleTimeout: 3000
}
```
### Full Example
```javascript
const { ActiveDirectory } = require('./index');

const myADConfig = {
    url: 'ldap://192.168.1.1', // You can use DNS as well for redundency in a domain, like domain.local
    suffix: 'dc=domain,dc=local'
}

const myAD = new ActiveDirectory(myADConfig);

myAD.loginAdUser('test@domain.local','password')
    .then(res => {
        // If it failed to auth user find out why
        if(!res.success) {
            console.log(res.message);
            return;
        }

        const user = ActiveDirectory.createUserObj(res.entry);
        console.log(user);
    })
    .catch(err => console.error(err))
```



#### Constructor Config Options

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| url | String | Required | The url to the AD server, should start with `ldap://` or `ldaps://` |
| suffix | String | Required | AD suffix, example.local would be `dc=example, dc=local`|
| searchOptions | Object | Optional | ldapjs searchOptions, defaults to `scope: 'sub'` |
| idleTimeout | Number | Optional | How long to wait for response from AD before timing out |

## Methods
### loginAdUser(username, password)
This function takes a username and password and will return a Promise. **The promise will only reject client connection issues**, invalid authentication will still resolve the promise. This was done to make it easier to provide a different error or to try a 2ndry auth source easily. The success key is on all types of responses and should be used to verify if user was logged in. If success is false there will be 2 additional keys, message and error.

```javascript
myAD.loginAdUser('test@domain.local','password')
    .then(res => {
        // If it failed to auth user find out why
        if(!res.success) {
            console.log(res.message);
            return;
        }

        const user = ActiveDirectory.createUserObj(res.entry);
        console.log(user);
    })
    .catch(err => console.error(err))
```

**Params**

| Required | Type | Description
| -------- | ---- | -----------
| Required | String | Username - **this must be the UPN** e.g. test@domain.local |
| Required | String | Password |

**Both resolve & reject will be in the following format**

| Key | Returned | Type | Description |
| --- | -------- | ---- | ----------- |
| success | Always | boolean | Indicates if the login succeeded |
| entry | Situational | Object | Entry is the ldapjs entry response |
| message | Situational | String | User friendly message from resolveBindError, only on `success: false` |
| error | Situational | String | The original error generated, only on `success: false` |


### createUserObj(entry)
Takes in the entry returned by ldapjs and creates a standardized user object. If you do not want to store all the users data it is recommended you extract the values you need from this object, because in the future there will likely be many more fields added to this. The first set of fields added were based on immediate needs.

*If this does not have all the desired fields please feel free to add more in a PR or you can simply access them on the entry.objects or entry.attributes if you need the buffers.*

```javascript
const user = ActiveDirectory.resolveBindError(res.entry)
```

**Params**

| Required | Type | Description |
| -------- | ---- | ----------- |
| Required | Object | This is the ldapjs entry obj, this is returned by loginAdUser when success is true. |

**Returns Object**

| Returned | Type | Description |
| -------- | ---- | ----------- |
| groups | Array | An array of group name strings. *This is the group names only, not the full AD location* |
| phone | String | Users phone number |
| name | String | Users full name |
| mail | String | Users email address |
| guid | String | Unique AD key, this should be used to track and or link the user account to your app. |


### resolveBindError(entry)
This function takes in the ldapjs errors and checks if it's due to invalid credentials or if the account is locked out. **This does not check if an account is disabled, so it will still return as invalid credentials**

```javascript
const message = ActiveDirectory.resolveBindError(res.entry)
// Examples: Account is locked out, Invalid username or password, or Error resolving account.
```

**Params**

| Required | Type | Description |
| -------- | ---- | ----------- |
| Required | Object | This is the ldapjs entry obj, this is returned by loginAdUser when success is true. |

**Returns**

| Type | Description |
| ---- | ----------- |
| String | A user friendly message indicating why the login failed |


### resolveGUID(entry)
Takes in the entry returned by ldapjs and creates a GUID string. This should be used as your unique ID in your app or somehow used to link to a unique ID in your app. This will not change for the life of the object in AD, so even if the users name or email is changed this will stay the same.

```javascript
const guid = ActiveDirectory.resolveGUID(res.entry)
// Example: 17d4e710-624d-4978-900b-8549cb753699
```

**Params**

| Required | Type | Description |
| -------- | ---- | ----------- |
| Required | Object | This is the ldapjs entry obj, this is returned by loginAdUser when success is true. |

**Returns**

| Type | Description |
| ---- | ----------- |
| String | An array of group name strings. *This is the group names only, not the full AD location* |


### resolveGroups(entry)
Takes in the entry returned by ldapjs and creates an array of the users groups.

```javascript
const guid = ActiveDirectory.resolveGroups(res.entry)
// Example: ['Group1', 'Group2']
```
**Params**

| Required | Type | Description |
| -------- | ---- | ----------- |
| Required | Object | This is the ldapjs entry obj, this is returned by loginAdUser when success is true. |

**Returns**

| Type | Description |
| ---- | ----------- |
| String | Unique AD key |


# Potential Issues
Sometimes ldapjs has issues with newer version of Node, please see ldapjs for any of these issues.
