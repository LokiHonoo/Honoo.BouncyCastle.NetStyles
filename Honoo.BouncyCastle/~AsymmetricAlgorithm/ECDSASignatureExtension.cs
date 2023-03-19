namespace Honoo.BouncyCastle
{
    /// <summary>
    /// ECDSA signature extension.
    /// </summary>
    public enum ECDSASignatureExtension
    {
        /// <summary>
        /// ECDSA signer with standard.
        /// </summary>
        ECDSA = 1,

        /// <summary>
        /// ECNR signer with standard.
        /// </summary>
        ECNR,

        /// <summary>
        /// ECDSA signer with plain.
        /// </summary>
        Plain,

        /// <summary>
        /// ECDSA signer with plain.
        /// </summary>
        CVC,
    }
}