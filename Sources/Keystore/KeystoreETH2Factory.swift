import Foundation
import CryptoSwift
import Scrypt
import bls_framework

public struct KeystoreETH2Factory {

    /// Extracts the private key from the given keystore
    ///
    /// - parameter keystore: The keystore.
    /// - parameter password: The password to use for the decryption.
    ///
    /// - returns: The extracted private key.
    ///
    /// - throws: Some `KeystoreETH2Factory.Error` if any step fails.
    public static func privateKey(from keystore: KeystoreETH2, password: String) throws -> Array<UInt8> {
        var forbiddenCharacterSet = CharacterSet()
        forbiddenCharacterSet.insert(charactersIn: Unicode.Scalar(0x00)...Unicode.Scalar(0x1f))
        forbiddenCharacterSet.insert(charactersIn: Unicode.Scalar(0x80)...Unicode.Scalar(0x9f))
        forbiddenCharacterSet.insert(Unicode.Scalar(0x7f))

        let password = password.decomposedStringWithCompatibilityMapping
            .components(separatedBy: .controlCharacters)
            .filter({ !$0.isEmpty })
            .joined(separator: "")

        // Check version
        guard keystore.version == 4 else {
            throw Error.keystoreVersionNotSupported
        }

        // Derive key
        let decryptionKey = try deriveKey(password: password, kdf: keystore.crypto.kdf)
        guard decryptionKey.count >= 32 else {
            throw Error.kdfFailed
        }

        // Verify password
        let isValidPassword = try passwordVerification(
            decryptionKey: decryptionKey,
            cipher: keystore.crypto.cipher,
            checksum: keystore.crypto.checksum
        )
        if !isValidPassword {
            throw Error.passwordWrong
        }

        let ivData = try keystore.crypto.cipher.params.iv.dataWithHexString()
        let ciphertextData = try keystore.crypto.cipher.message.dataWithHexString()
        let cipher = keystore.crypto.cipher.function

        let usableKey = decryptionKey[0..<16]

        guard cipher == .aes128Ctr else {
            throw Error.cipherNotAvailable
        }

        let aes = try AES(
            key: [UInt8](usableKey),
            blockMode: CTR(iv: ivData.bytes),
            padding: .noPadding
        )

        return try aes.decrypt([UInt8](ciphertextData))
    }

    /// Creates a keystore for the given privateKey with the given password.
    ///
    /// - parameter privateKey: The private key to encrypt.
    /// - parameter password: The password to use for the encryption.
    /// - parameter kdf: The key derivation function to use.
    /// - parameter cipher: The cipher to use for encryption.
    /// - parameter checksum: The password checksum to use to detect bad passwords during decryption.
    /// - parameter rounds: The number of rounds for the key derivation function to use. Defaults to a secure number.
    ///
    /// - returns: The KeystoreETH2 object with the encrypted private key.
    ///
    /// - throws: Some `KeystoreETH2Factory.Error` if any step fails.
    public static func keystore(
        from privateKey: [UInt8],
        password: String,
        kdf: KeystoreETH2.KDFModule.KDFType,
        cipher: KeystoreETH2.CipherModule.CipherType,
        checksum: KeystoreETH2.ChecksumModule.ChecksumType,
        rounds: Int = 262144
    ) throws -> KeystoreETH2 {
        guard privateKey.count == 32 else {
            throw Error.privateKeyMalformed
        }

        guard let iv = [UInt8].secureRandom(count: 16), let salt = [UInt8].secureRandom(count: 32) else {
            throw Error.bytesGenerationFailed
        }

        let password = password.decomposedStringWithCompatibilityMapping
            .components(separatedBy: .controlCharacters)
            .filter({ !$0.isEmpty })
            .joined(separator: "")

        // Derive key
        let kdfModule: KeystoreETH2.KDFModule
        switch kdf {
        case .scrypt:
            kdfModule = .init(function: kdf, params: .init(salt: salt.toHexString(), dklen: 32, n: rounds, r: 8, p: 1), message: "")
        case .pbkdf2:
            kdfModule = .init(function: kdf, params: .init(salt: salt.toHexString(), dklen: 32, prf: "hmac-sha256", c: rounds), message: "")
        }
        let encryptionKey = try deriveKey(password: password, kdf: kdfModule)
        guard encryptionKey.count >= 32 else {
            throw Error.kdfFailed
        }

        // Encrypt
        let usableKey = encryptionKey[0..<16]

        guard cipher == .aes128Ctr else {
            throw Error.cipherNotAvailable
        }

        let aes = try AES(
            key: [UInt8](usableKey),
            blockMode: CTR(iv: iv),
            padding: .noPadding
        )
        let cipherMessage = try aes.encrypt(privateKey)
        let cipherModule = KeystoreETH2.CipherModule(function: cipher, params: .init(iv: iv.toHexString()), message: cipherMessage.toHexString())

        // Checksum
        guard checksum == .sha256 else {
            throw Error.checksumNotAvailable
        }

        let checksumGenerated = try generatePasswordChecksum(decryptionKey: encryptionKey, cipher: cipherModule)
        let checksumModule = KeystoreETH2.ChecksumModule(function: checksum, params: .init(), message: checksumGenerated.toHexString())

        // BLS pubkey

        try BLSInterface.blsInit()

        var serializedPrivateKey = privateKey
        var secretKey = blsSecretKey.init()
        if blsSecretKeyDeserialize(&secretKey, &serializedPrivateKey, numericCast(serializedPrivateKey.count)) <= 0 {
            throw Error.privateKeyMalformed
        }
        var publicKey = blsPublicKey.init()
        blsGetPublicKey(&publicKey, &secretKey)
        // Ethereum public key is 48 bytes
        var publicKeyBytes = Data(count: 48).bytes
        blsPublicKeySerialize(&publicKeyBytes, 48, &publicKey)

        let ethereumPublicKey = Data(publicKeyBytes)

        return KeystoreETH2(
            crypto: .init(kdf: kdfModule, checksum: checksumModule, cipher: cipherModule),
            description: "",
            pubkey: ethereumPublicKey.toHexString(),
            path: "",
            uuid: UUID().uuidString,
            version: 4
        )
    }

    private static func deriveKey(
        password: String,
        kdf: KeystoreETH2.KDFModule
    ) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw Error.passwordMalformed
        }
        let saltData = try kdf.params.salt.dataWithHexString()

        if kdf.function == .scrypt {
            guard let n = kdf.params.n, let r = kdf.params.r, let p = kdf.params.p else {
                throw Error.kdfInputsMalformed
            }

            return try Data(scrypt(
                password: password.bytes,
                salt: saltData.bytes,
                length: kdf.params.dklen,
                N: UInt64(n),
                r: UInt32(r),
                p: UInt32(p)
            ))
        }

        // PBKDF2
        guard kdf.function == .pbkdf2, kdf.params.prf == "hmac-sha256" else {
            throw Error.kdfInputsMalformed
        }
        guard let c = kdf.params.c, c > 0 else {
            throw Error.kdfInputsMalformed
        }

        return try Data(PKCS5.PBKDF2(
            password: [UInt8](passwordData),
            salt: [UInt8](saltData),
            iterations: c,
            keyLength: kdf.params.dklen,
            variant: .sha2(.sha256)
        ).calculate())
    }

    private static func generatePasswordChecksum(
        decryptionKey: Data,
        cipher: KeystoreETH2.CipherModule
    ) throws -> Data {
        let dkSlice = decryptionKey[16..<32]
        var preImage = dkSlice
        try preImage.append(contentsOf: cipher.message.dataWithHexString())

        let calculatedChecksum = preImage.sha256()

        return calculatedChecksum
    }

    private static func passwordVerification(
        decryptionKey: Data,
        cipher: KeystoreETH2.CipherModule,
        checksum: KeystoreETH2.ChecksumModule
    ) throws -> Bool {
        let calculatedChecksum = try generatePasswordChecksum(decryptionKey: decryptionKey, cipher: cipher)
        return try calculatedChecksum == checksum.message.dataWithHexString()
    }

    public enum Error: Swift.Error {

        /// Unsupported keystore version
        case keystoreVersionNotSupported

        /// The password can't be represented as utf8 data
        case passwordMalformed

        /// The keystore contains values which are not acceptable or misses some values which are needed
        case keystoreMalformed

        /// The kdf values in the keystore are missing values/are not available
        case kdfInputsMalformed

        /// The kdf failed at any point
        case kdfFailed

        /// The password is wrong/mac verification failed
        case passwordWrong

        /// The given cipher is not available
        case cipherNotAvailable

        /// The given checksum is not available
        case checksumNotAvailable

        /// Generating random bytes failed
        case bytesGenerationFailed

        /// The given private key is not a valid secp256k1 private key
        case privateKeyMalformed
    }
}
