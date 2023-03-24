using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric algorithm kind.
    /// </summary>
    [Flags]
    public enum AsymmetricAlgorithmKind
    {
        /// <summary>
        /// Indicates the algorithm is a asymmetric signature algorithm.
        /// </summary>
        Signature = 1,

        /// <summary>
        /// Indicates the algorithm is a asymmetric encryption algorithm.
        /// </summary>
        Encryption = 2,

        /// <summary>
        /// Indicates the algorithm is a asymmetric signature and encryption algorithm.
        /// </summary>
        SignatureAndEncryption = Signature | Encryption,

        /// <summary>
        /// Indicates the algorithm is a asymmetric key exchange algorithm.
        /// </summary>
        KeyExchange = 4,
    }
}