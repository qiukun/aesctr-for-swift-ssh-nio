//
//  AESCTR.swift
//
//
//  Created by Quinn Chiu on 2023/10/26.
//

import Crypto
import Foundation
import NIOCore
import NIOSSH

import IDZSwiftCommonCrypto

private struct InvalidKeySize: Error {}
private struct TagMissmatched: Error {}

private enum TransportProtectionError: Error {
    // NIOSSH errors marked internal(so we cannot use directly)
    case invalidKeySize
    case tagMissmatched
    case insufficientPadding
    case excessPadding
    
    // custom errors
    case invalidArgument(String)
}

final class AES128CTRTransportProtection: NIOSSHTransportProtection {
    private var keys: NIOSSHSessionKeys
    private var inboundCounter: [UInt8]
    private var outboundCounter: [UInt8]
    // https://datatracker.ietf.org/doc/html/rfc4344
    static var cipherName: String {
        "aes128-ctr"
    }

    // https://datatracker.ietf.org/doc/html/rfc6668#section-2
    static var macName: String? {
        "hmac-sha2-256"
    }

    static var keySizes: ExpectedKeySizes {
        .init(ivSize: 16, encryptionKeySize: 16, macKeySize: 32)
    }

    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        32
    }

    var lengthEncrypted: Bool {
        true
    }

    required init(initialKeys: NIOSSHSessionKeys) throws {
        guard initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
              initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw TransportProtectionError.invalidKeySize
        }

        self.keys = initialKeys
        self.inboundCounter = initialKeys.initialInboundIV
        self.outboundCounter = initialKeys.initialOutboundIV
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
              newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw TransportProtectionError.invalidKeySize
        }

        self.keys = newKeys
        self.inboundCounter = newKeys.initialInboundIV
        self.outboundCounter = newKeys.initialOutboundIV
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        let packageLengthIndex = source.readerIndex

        guard let ciphertextView = source.viewBytes(at: packageLengthIndex, length: Self.cipherBlockSize) else {
            throw TransportProtectionError.invalidArgument("insufficient source buffer for one cipher block")
        }

        let cryptor = Cryptor(operation: .decrypt, algorithm: .aes, mode: .CTR, padding: .NoPadding, key: keys.inboundEncryptionKey.bytes, iv: self.inboundCounter)
        guard let plaintext = cryptor.update(ciphertextView.bytes)?.final() else {
            throw cryptor.status
        }

        incrementCounter(&self.inboundCounter)

        source.setBytes(plaintext, at: packageLengthIndex)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        guard var firstBlock = source.readSlice(length: Self.cipherBlockSize),
              let length = firstBlock.readInteger(endianness: .big, as: UInt32.self)
        else {
            throw TransportProtectionError.invalidArgument("corrupted source buffer")
        }

        var plainTextBuffer = ByteBuffer(buffer: firstBlock)

        if let ciphertext = source.readBytes(length: source.readableBytes-self.macBytes) {
            let cryptor = Cryptor(operation: .decrypt, algorithm: .aes, mode: .CTR, padding: .NoPadding, key: keys.inboundEncryptionKey.bytes, iv: self.inboundCounter)

            guard let plaintext = cryptor.update(ciphertext.bytes)?.final() else {
                throw cryptor.status
            }

            plainTextBuffer.writeBytes(plaintext)
            let blockcount = plaintext.count / Self.cipherBlockSize
            for _ in 0 ..< blockcount {
                incrementCounter(&self.inboundCounter)
            }
        }

        let tag = source.readBytes(length: self.macBytes)

        let hmac = HMAC(algorithm: .sha256, key: self.keys.inboundMACKey.withUnsafeBytes { Data($0) })
        var x = ByteBuffer()
        x.writeInteger(sequenceNumber)
        x.writeInteger(length)
        x.writeBytes(plainTextBuffer.readableBytesView)
        let expectedTag = hmac.update(byteArray: x.readableBytesView.bytes)!.final()

        guard expectedTag == tag else {
            throw TransportProtectionError.tagMissmatched
        }

        var ret = Data(buffer: plainTextBuffer)
        try ret.removePaddingBytes()

        return ByteBuffer(data: ret)
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let packetLengthIndex = destination.readerIndex
        let encryptedBufferSize = destination.readableBytes

        let plaintextView = destination.viewBytes(at: packetLengthIndex, length: encryptedBufferSize)!
        let plaintext = plaintextView.bytes

        let cryptor = Cryptor(operation: .encrypt, algorithm: .aes, mode: .CTR, padding: .NoPadding, key: keys.outboundEncryptionKey.withUnsafeBytes { Data($0) }.map { $0 }, iv: self.outboundCounter)

        guard let ciphertext = cryptor.update(plaintext)?.final() else {
            throw cryptor.status
        }

        let blockcount = encryptedBufferSize / Self.cipherBlockSize
        for _ in 0 ..< blockcount {
            incrementCounter(&self.outboundCounter)
        }

        // https://datatracker.ietf.org/doc/html/rfc4253#section-6.4
        let hmac = HMAC(algorithm: .sha256, key: self.keys.outboundMACKey.withUnsafeBytes { Data($0) })
        var x = ByteBuffer()
        x.writeInteger(sequenceNumber)
        x.writeBytes(plaintext)
        let tag = hmac.update(byteArray: x.readableBytesView.bytes)!.final()

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the tag.
        destination.setBytes(ciphertext, at: packetLengthIndex)
        let tagLength = destination.writeBytes(tag)
        precondition(tagLength == self.macBytes, "Unexpected short tag")
    }
}

private func incrementCounter(_ counter: inout [UInt8]) {
    let cnt = counter.count

    for j in 1 ... cnt {
        counter[cnt-j] = counter[cnt-j] &+ 1
        if counter[cnt-j] != 0 {
            break
        }
    }
}

extension ContiguousBytes {
    var bytes: [UInt8] {
        withUnsafeBytes(Array.init)
    }
}

private extension Data {
    /// Removes the padding bytes from a Data object.
    mutating func removePaddingBytes() throws {
        guard let paddingLength = self.first, paddingLength >= 4 else {
            throw TransportProtectionError.insufficientPadding
        }

        // We're going to slice out the content bytes. To do that, can simply find the end index of the content, and confirm it's
        // not walked off the front of the buffer. If it has, there's too much padding and an error has occurred.
        let contentStartIndex = self.index(after: self.startIndex)
        guard let contentEndIndex = self.index(self.endIndex, offsetBy: -Int(paddingLength), limitedBy: contentStartIndex) else {
            throw TransportProtectionError.excessPadding
        }

        self = self[contentStartIndex ..< contentEndIndex]
    }
}
