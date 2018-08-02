const assert = require('assert');
const AD = require('../index').ActiveDirectory;

//const testConfig = { url: '', suffix: '' }
//const  = new index.ActiveDirectory(testConfig);

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

    // TODO: Write unit tests
    // describe('#resolveGUID()', () => {
        
    // });

    describe('#resolveGUID()', () => {
        const testEntry = {
            attributes: [
                {
                    type: 'objectGUID',
                    buffers: [
                        Buffer.from('10E7D4174D627849900B8549CB753699', 'hex')
                    ]
                }
            ]
        }

        it('Convert hex buffer into formatted guid string', () => {
            assert.equal(
                AD.resolveGUID(testEntry),
                '17d4e710-624d-4978-900b-8549cb753699'
            );
        });

        it('If entry is not it should throw error', () => {
            const tmpEntry = undefined;
            assert.throws(() => AD.resolveGUID(tmpEntry), Error);
        });

        it('If no attributes it should throw error', () => {
            const tmpEntry = {...testEntry};
            delete tmpEntry.attributes;
            assert.throws(() => AD.resolveGUID(tmpEntry), Error);
        });

    });

    // TODO: Write unit tests
    // describe('#createUserObj()', () => {
        
    // });
  });