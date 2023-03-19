using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA256 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA256 class.
        /// </summary>
        public SHA256() : base("SHA256", 256)
        {
        }

        #endregion Construction
        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA256 Create()
        {
            return new SHA256();
        }
        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA256", 256, () => { return new Sha256Digest(); }, () => { return new SHA256(); });
        }
        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha256Digest();
        }
    }
}