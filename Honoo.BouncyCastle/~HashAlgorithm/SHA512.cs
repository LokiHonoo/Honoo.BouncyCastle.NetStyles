using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA512 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA512 class.
        /// </summary>
        public SHA512() : base("SHA512", 512)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA512 Create()
        {
            return new SHA512();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA512", 512, () => { return new Sha512Digest(); }, () => { return new SHA512(); });
        }
        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha512Digest();
        }
    }
}