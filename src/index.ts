import { promises as fs } from 'fs';

import crypto, {
  CipherGCM,
  createCipheriv,
  createDecipheriv,
  DecipherGCM,
} from 'crypto';

export interface CryptoFileConstrucProps {
  /**
   * Required value. SecretKey must be of length 32
   */
  secretKey: string;
  /**
   * Optional value. Path to file that will be encrypted
   */
  filePath?: string;
  /**
   * Optional value. Password must be of length 32.
   *
   * If password is not provided, a dynamically generated one will be created
   */
  password?: string;
  /**
   * Optional value. This is the value to append to the encrypted file name
   *
   * Default `enc`
   */
  encryptedFileExt?: string;
}
export interface EncryptedResult {
  /**
   * Required value. String value of IV to be converted to Buffer
   */
  iv: string;
  /**
   * Required value. String value of authTag to be converted to Buffer
   */
  authTag: string;
  /**
   * Required value. String value of Password to be converted to Buffer
   */
  password: string;
}
export interface DecryptFileOptions {
  /**
   * Optional value. Path to file that will be decrypted
   *
   * Default `this.filePath`
   */
  filePath?: string;
  /**
   * Optional value. Path to where decrypted file should be saved
   */
  newFilePath?: string;
}

export interface CryptoFileDef {
  /**
   * Optional provided value. Password must be of length 32
   *
   * If value is not of length 32, an error will be thrown
   *
   * If password is not provided, a dynamically generated one will be created
   */
  password: string;
  /**
   * Buffer used for IV value
   */
  iv: Buffer;
  /**
   * String value for secretKey to be used. Must be of length 32
   *
   * If value is not of length 32, an error will be thrown
   *
   * If this value is lost, you may not be able to decrypt passwords/files
   */
  secretKey: string;
  /**
   * String value for path to file
   *
   * If value is not provided at instantiation or when using encryptFile method
   * , an error will be thrown
   *
   */
  filePath: string;
  /**
   * Optional value. This is the value to append to the encrypted file name
   *
   * Default `enc`
   */
  encryptedFileExt: string;
  /**
   * Handles encrypting the file using `aes-256-gcm` encryption
   *
   * @async
   * @param {string} filePath - Optional path to file to be encrypted.
   * Default `this.filePath`
   * @returns {Promise<string>}
   */
  encryptFile(filePath?: string): Promise<string>;
  /**
   * Handles decrypting the file using `aes-256-gcm` encryption
   *
   * @async
   * @param {DecryptFileOptions} options - Optional object
   * @param {string} options.filePath - Optional path to file to be decrypted.
   * Default `this.filePath`
   * @param {string} options.newFilePath - Optional path to where decrypted file should be saved
   * including file name and extension.
   * Default `this.filePath`
   * @returns {Promise<string>}
   */
  decryptFile(options: DecryptFileOptions): Promise<string>;
  /**
   * Handles encrypting a provided password or a dynamically generated one
   *
   * @param {string} password - Optional value. Password must be of length 32.
   * Default `this.password`
   *
   * @returns EncyptedResult
   */
  encryptPassword(password?: string): EncryptedResult;
  /**
   * Handles decrypting the provided options to the decrypted password
   *
   * @param {string | EncryptedResult } options - Either a string of EncryptedResult (to be parsed)
   * or an object of EncryptedResult
   * @returns {string}
   */
  decryptPassword(options: string | EncryptedResult): string;
}

class CryptoFile implements CryptoFileDef {
  password: string;

  iv: Buffer = crypto.randomBytes(16);

  secretKey: string;

  filePath: string;

  encryptedFileExt: string;

  constructor({
    filePath, secretKey, password, encryptedFileExt,
  }: CryptoFileConstrucProps) {
    this.password = password ?? '';
    this.secretKey = secretKey;
    this.filePath = filePath ?? '';
    this.encryptedFileExt = encryptedFileExt ?? 'enc';
  }

  private createCipher(): CipherGCM {
    const SECRETKEY = this.secretKey;
    const IV = this.iv;

    if (SECRETKEY.length !== 32) {
      throw new Error('SecretKey length must be 32 characters');
    }

    return createCipheriv('aes-256-gcm', SECRETKEY, IV);
  }

  private createDecipher(
    IV: Buffer,
    authTag: Buffer,
    usePassword: boolean,
  ): DecipherGCM {
    const SECRETKEY = usePassword ? this.password : this.secretKey;

    const decipher = createDecipheriv('aes-256-gcm', SECRETKEY, IV);
    decipher.setAuthTag(authTag);

    return decipher;
  }

  private createPassword(): void {
    const charList = 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let password = '';
    for (let i = 0; i < 32; i += 1) {
      password += charList[Math.floor(Math.random() * charList.length)];
    }
    this.password = password;
  }

  encryptPassword(password?: string): EncryptedResult {
    const cipher = this.createCipher();
    if (password) {
      if (password.length !== 32) {
        throw new Error('Password length must be 32 characters');
      }
      this.password = password;
    } else {
      this.createPassword();
    }

    const encrypted = Buffer.concat([
      cipher.update(this.password),
      cipher.final(),
    ]);
    const result = {
      iv: this.iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
      password: encrypted.toString('hex'),
    };

    return result;
  }

  decryptPassword(options: string | EncryptedResult) : string {
    const { iv, password, authTag } = typeof options === 'string' ? JSON.parse(options) : options;
    if (!iv) {
      throw new Error('Decrypt Password Failed: Missing IV value');
    }
    if (!password) {
      throw new Error('Decrypt Password Failed: Missing Password value');
    }
    if (!authTag) {
      throw new Error('Decrypt Password Failed: Missing AuthTag value');
    }

    const decipher = this.createDecipher(
      Buffer.from(iv, 'hex'),
      Buffer.from(authTag, 'hex'),
      false,
    );
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(password, 'hex')),
      decipher.final(),
    ]);
    this.password = decrypted.toString();

    return decrypted.toString();
  }

  async encryptFile(filePath?: string): Promise<string> {
    if (filePath) {
      this.filePath = filePath;
    }
    if (!this.filePath) {
      throw new Error('Encrypt File Failed: Missing filepath value');
    }
    const fileToEncrypt = await fs.readFile(this.filePath);
    const IV = this.iv;
    const cipher = this.createCipher();
    const encryptedFile = Buffer.concat([
      cipher.update(fileToEncrypt),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    const encryptedWithAuthTag = Buffer.concat([IV, authTag, encryptedFile]);
    const newFilePath = `${this.filePath}.${this.encryptedFileExt}`;
    await fs.writeFile(newFilePath, encryptedWithAuthTag);

    return newFilePath;
  }

  async decryptFile({ filePath, newFilePath }: DecryptFileOptions): Promise<string> {
    if (filePath) {
      this.filePath = filePath;
    }
    if (!this.filePath) {
      throw new Error('Decrypt File Failed: Missing filepath value');
    }
    const encryptedFile = await fs.readFile(this.filePath);
    const newFilePathLocation = newFilePath || this.filePath.replace(`.${this.encryptedFileExt}`, '');
    const IV = encryptedFile.slice(0, 16);
    const authTag = encryptedFile.slice(16, 32);
    const encryptedWithoutIV = encryptedFile.slice(32);
    const decipher = this.createDecipher(IV, authTag, true);

    const decryptedFile = Buffer.concat([
      decipher.update(encryptedWithoutIV),
      decipher.final(),
    ]);
    await fs.writeFile(
      newFilePathLocation,
      decryptedFile,
    );

    return newFilePathLocation;
  }
}

export default CryptoFile;
