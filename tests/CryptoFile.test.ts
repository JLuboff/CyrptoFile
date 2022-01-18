import { promises as fs } from 'fs';
import CryptoFile, { EncryptedResult } from '../src/index';

const TESTFILESDIR = './testFiles';
const TESTFILENAME = 'test.txt';
const TESTFILEPATH = `${TESTFILESDIR}/${TESTFILENAME}`;
const TESTFILECONTENTS = 'This is a test file';
const TESTPASSWORD = 'My32CharacterLongSecretPassword!';

beforeAll(async () => {
  await fs.mkdir(TESTFILESDIR);
  await fs.writeFile(TESTFILEPATH, TESTFILECONTENTS);
});
afterAll(async () => {
  await Promise.all([
    fs.rm(TESTFILEPATH),
    fs.rm(`${TESTFILEPATH}.enc`),
  ]);
  await fs.rmdir(TESTFILESDIR);
});

describe('CryptoFile', () => {
  const cryptoFile = new CryptoFile({
    secretKey: 'My32CharacterLongSecretKey123456',
  });
  const encryptedResult = cryptoFile.encryptPassword(TESTPASSWORD);
  let dynamicPassResult: EncryptedResult;

  test('Should encrypt provided password and return iv, authTag, and hashed password', () => {
    expect(encryptedResult.iv).toBeTruthy();
    expect(encryptedResult.authTag).toBeTruthy();
    expect(encryptedResult.password).toBeTruthy();
    expect(encryptedResult.password).not.toEqual(TESTPASSWORD);
  });

  test('Should decrypt password and match pre-hashed password', () => {
    const decryptedPassword = cryptoFile.decryptPassword(JSON.stringify(encryptedResult));

    expect(decryptedPassword).toEqual(TESTPASSWORD);
  });

  test('Should encrypt a file', async () => {
    const result = await cryptoFile.encryptFile(TESTFILEPATH);

    expect(typeof result).toBe('string');
    expect(result).toBe(`${TESTFILEPATH}.enc`);

    const readFile = await fs.readFile(result);
    expect(readFile.toString()).not.toBe(TESTFILECONTENTS);
  });

  test('Should decrypt a file', async () => {
    const result = await cryptoFile.decryptFile();

    expect(result).toBe(TESTFILEPATH);

    const readFile = await fs.readFile(result);
    expect(readFile.toString()).toBe(TESTFILECONTENTS);
  });

  test('Should decrypt a file when path provided', async () => {
    const result = await cryptoFile.decryptFile({ filePath: `${TESTFILEPATH}.enc` });

    expect(result).toBe(TESTFILEPATH);

    const readFile = await fs.readFile(result);
    expect(readFile.toString()).toBe(TESTFILECONTENTS);
  });

  test('Should encrypt a dynamically created password', () => {
    dynamicPassResult = cryptoFile.encryptPassword();

    expect(dynamicPassResult.iv).toBeTruthy();
    expect(dynamicPassResult.authTag).toBeTruthy();
    expect(dynamicPassResult.password).toBeTruthy();
  });

  test('Should decrypt a dynamically created password', () => {
    const password = cryptoFile.decryptPassword(dynamicPassResult);

    expect(password).toHaveLength(32);
  });

  test('Should throw an error if SecretKey is not a length of 32', () => {
    expect(() => {
      const cryptoPass = new CryptoFile({ secretKey: 'Lessthan32Chars' });
      cryptoPass.encryptPassword();
    }).toThrow('SecretKey length must be 32 characters');
  });

  test('Should throw an error if encrypt password is not of length 32', () => {
    expect(() => {
      cryptoFile.encryptPassword('NotLongEnough');
    }).toThrow('Password length must be 32 characters');
  });

  test('Should throw an error if decrypt not provided iv', () => {
    expect(() => {
      cryptoFile.decryptPassword({ password: encryptedResult.password, authTag: encryptedResult.authTag, iv: '' });
    }).toThrow('Decrypt Password Failed: Missing IV value');
  });

  test('Should throw an error if decrypt not provided authTag', () => {
    expect(() => {
      cryptoFile.decryptPassword({
        password: encryptedResult.password,
        authTag: '',
        iv: encryptedResult.iv,
      });
    }).toThrow('Decrypt Password Failed: Missing AuthTag value');
  });

  test('Should throw an error if decrypt not provided password', () => {
    expect(() => {
      cryptoFile.decryptPassword({
        password: '',
        authTag: encryptedResult.authTag,
        iv: encryptedResult.iv,
      });
    }).toThrow('Decrypt Password Failed: Missing Password value');
  });

  const noFilePath = new CryptoFile({ secretKey: TESTPASSWORD });

  test('Should throw an error when no filepath for encryptFile is provided', async () => {
    async function testNoFilePath() {
      await noFilePath.encryptFile();
    }
    await expect(testNoFilePath()).rejects.toThrow('Encrypt File Failed: Missing filepath value');
  });

  test('Should throw an error when no filepath for decriptFile is provided', async () => {
    async function testNoFilePath() {
      await noFilePath.decryptFile();
    }
    await expect(testNoFilePath()).rejects.toThrow(
      'Decrypt File Failed: Missing filepath value',
    );
  });
});
