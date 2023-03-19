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

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA224", 224, () => { return new Sha224Digest(); }, () => { return new SHA224(); });
        }

        protected override IDigest GenerateDigest()
        {
            return new Sha224Digest();
        }
    }
}