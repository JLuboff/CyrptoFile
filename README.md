# CyrptoFile

A file/password encryptor/decryptor module written with native NodeJS modules

## Installation
    npm install cryptofile

## Usage
Typescript
```typescript
import CryptoFile from 'cryptofile';

const cryptoFile = new CryptoFile({ secretKey: 'My32CharacterLongSecretKey123456'}) //Secretkey of length 32 must be provided

// Create encrypted password
const encryptedPassword = cryptoFile.encryptPassword() // Optionally provide password of length 32

// Decrypt hashed password
const decryptedPassword = cryptoFile.decryptPassword(encryptedPassword)

// Create encrypted file
const newFilePathWithExtension = await cryptoFile.encryptFile('../path/to/file') // If filepath was not provided in original instantiation, it must be provided

// Decrypt hashed file
const newFilePathLocation = await cryptoFile.decryptFile({filePath: '../path/to/file'}) //If filepath was not provided in original instantiation, it must be provided
```

## Contributions
Contributions are welcome, please submit a PR which will be reviewed.

## Reporting Issues
Please report issues/errors to Github's issue tracker: [CryptoFile issue tracker](https://github.com/JLuboff/CyrptoFile/issues).
Include issue, expected behavior, and how to replicate the issue.

## License
[MIT License](https://github.com/JLuboff/CyrptoFile/blob/main/LICENSE)