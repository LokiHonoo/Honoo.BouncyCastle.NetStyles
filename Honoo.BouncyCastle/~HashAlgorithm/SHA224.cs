using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA224 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA224 class.
        /// </summary>
        public SHA224() : base("SHA224", 224)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA224 Create()
        {
            return new SHA224();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA224", 224, () => { return new Sha224Digest(); }, () => { return new SHA224(); });
        }
        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha224Digest();
        }
    }
}