const assert = require('assert');
const AD = require('../index').ActiveDirectory;

//const testConfig = { url: '', suffix: '' }
//const  = new index.ActiveDirectory(testConfig);

const testEntry = {
    object: {
        memberOf: [
            'CN=Group1,OU=Test,DC=domain,DC=com',
            'CN=Group2,OU=Test,OU=Test2,DC=domain,DC=com',
        ],
        mail: 'test@domain.com',
        telephoneNumber: '+1 12312312324',
        name: 'Test User'
    },
    attributes: [
        {
            type: 'objectGUID',
            buffers: [
                Buffer.from('10E7D4174D627849900B8549CB753699', 'hex')
            ]
        }
    ]
}

describe('Static Functions', () => {
    describe('#resolveBindError()', () => {
        it('Should return unkown if random text is sent', () => {
            assert.equal(
                AD.resolveBindError('ergrughusi'),
                'Unkown Auth Error'
            );
        });

        it('Should return invalid credentials if message does not contain 775 in message', () => {
            assert.equal(
                AD.resolveBindError({name: 'InvalidCredentialsError', lde_message: '352fsgfs'}),
                'Invalid username or password'
            );
        });

        it('Should return lock out if 775 is in message', () => {
            assert.equal(
                AD.resolveBindError({name: 'InvalidCredentialsError', lde_message: 'junguiengeiu775'}),
                'Account is locked out'
            );
        });
    });

    describe('#resolveGroups()', () => {
        it('User only has groups in 1 OU', () => {
            const tmpEntry = {...testEntry, object: { memberOf: [...testEntry.object.memberOf] }};
            tmpEntry.object.memberOf = 'CN=Group1,CN=Group2,DC=domain,DC=com';
            assert.deepStrictEqual(
                AD.resolveGroups(tmpEntry),
                ['Group1', 'Group2']
            );
        });

        it('Has groups in multiple OUs', () => {
            assert.deepStrictEqual(
                AD.resolveGroups(testEntry),
                ['Group1', 'Group2']
            );
        });

        it('If invalid argument it should return empty array', () => {
            const tmpEntry = {...testEntry, object: { memberOf: [...testEntry.object.memberOf] }};
            tmpEntry.object.memberOf = undefined;
            assert.deepStrictEqual(
                AD.resolveGroups(tmpEntry),
                []
            );
        });

        it('If invalid entry it should throw an error', () => {
            let tmpEntry = {...testEntry};
            tmpEntry = undefined;
            assert.throws(() => AD.resolveGroups(tmpEntry), Error);
        });
    });

    describe('#resolveGUID()', () => {
        it('Convert hex buffer into formatted guid string', () => {
            assert.equal(
                AD.resolveGUID(testEntry),
                '17d4e710-624d-4978-900b-8549cb753699'
            );
        });

        it('If entry is not valid it should throw error', () => {
            const tmpEntry = undefined;
            assert.throws(() => AD.resolveGUID(tmpEntry), Error);
        });
    });

    describe('#createUserObj()', () => {
        it('Should return valid user object', () => {
            const userObj = {
                groups: ['Group1', 'Group2'],
                mail: 'test@domain.com',
                phone: '+1 12312312324',
                name: 'Test User',
                guid: '17d4e710-624d-4978-900b-8549cb753699'
            }
            
            assert.deepStrictEqual(
                AD.createUserObj(testEntry), userObj);
        });
        
        it('If invalid entry it should throw an error', () => {
            const tmpEntry = undefined;
            assert.throws(() => AD.createUserObj(tmpEntry), Error);
        });
    });
  });