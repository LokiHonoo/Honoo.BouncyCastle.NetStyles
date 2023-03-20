namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Asymmetric encryption padding mode.
    /// </summary>
    public enum AsymmetricEncryptionPaddingMode
    {
        /// <summary>
        /// NoPadding padding mode.
        /// </summary>
        NoPadding = 1,

        /// <summary>
        /// PKCS1 padding mode. Legal key size is more than or equal to 96 bits (8 bits increments).
        /// </summary>
        PKCS1,

        /// <summary>
        /// OAEP padding mode. Legal key size is more than or equal to 344 bits (8 bits increments).
        /// </summary>
        OAEP,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        ISO9796_1,
    }
}