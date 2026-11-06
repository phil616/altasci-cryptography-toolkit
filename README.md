# AltasCI Cryptography Toolkit

AltasCI KeyMaps is inherited from GreenShadeCapital Security DevOps Team. 

## Usage

### Root Key

The AltasCI root key is the key used to derive subkeys, and its function is solely for key derivation. For details on the root key generation and recovery ceremony, see Document 01. For details on the derivation algorithm, see the tool.

### Encryption

The AltasCI encryption key is the key used to encrypt files, directories, and critical files. It is primarily a symmetric encryption key. The current symmetric encryption methods are as follows: 1. Container encryption using VeraCrypt (because it can create and maintain a file system). 2. Encryption using Cryptomator, mainly for cloud synchronization and multi-endpoint synchronization; its design architecture is able to adapt to cloud synchronization. 3. General-purpose encryption: encryption using specific single-file encryption tools. 4. GPG encryption; employees rely on the GPG system for encryption.

### Infrastructure-generated encryption

The so-called infrastructure-generated encryption exists because AltasCI has many infrastructure components, such as PKI, CA, OpenBao Server, password managers, agent credential managers, and so on. Some of them are web backends, and some are execution engines. To protect the passwords they require, some subkeys are used to encrypt the keys they use or to directly derive the keys they use.

## ToolKit

FileSystem symmetric encryption tool: [VeraCrypt](https://github.com/veracrypt/veracrypt)

SingleFile symmetric encryption tool: [Age](https://github.com/FiloSottile/age)

Mnemonic passphrase generation tool: [sseed](https://github.com/phil616/sseed)

Multi-device data synchronization: [Syncovery](https://www.syncovery.com/)

Password derivation tool: [altasci-hkdf](./toolkit/altasci-hkdf.sh)

security-editor for windows: [sec-editor](https://github.com/phil616/sec-editor)

