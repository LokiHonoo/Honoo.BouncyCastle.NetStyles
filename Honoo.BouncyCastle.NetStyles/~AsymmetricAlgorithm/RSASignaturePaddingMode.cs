namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// RSA signature padding mode.
    /// </summary>
    public enum RSASignaturePaddingMode
    {
        /// <summary>
        /// PKCS1 padding mode.
        /// </summary>
        PKCS1 = 1,

        /// <summary>
        /// MGF1 padding mode.
        /// </summary>
        MGF1,

        /// <summary>
        /// X931 padding mode.
        /// <para/>Legal signature hash Algorithm: <see cref="HashAlgorithmName.SHA1"/>,
        /// <see cref="HashAlgorithmName.SHA224"/>, <see cref="HashAlgorithmName.SHA256"/>,
        /// <see cref="HashAlgorithmName.SHA384"/>, <see cref="HashAlgorithmName.SHA512"/>,
        /// <see cref="HashAlgorithmName.RIPEMD128"/>, <see cref="HashAlgorithmName.RIPEMD160"/>,
        /// <see cref="HashAlgorithmName.SHA512_224"/>, <see cref="HashAlgorithmName.SHA512_256"/>,
        /// <see cref="HashAlgorithmName.Whirlpool"/>.
        /// </summary>
        X931 = 10,

        /// <summary>
        /// ISO9796-2 padding mode.
        /// </summary>
        ISO9796_2,
    }
}