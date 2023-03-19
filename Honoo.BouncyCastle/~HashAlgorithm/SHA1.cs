using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA1 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA1 class.
        /// </summary>
        public SHA1() : base("SHA1", 160)
        {
        }

        #endregion Construction

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA1", 160, () => { return new Sha1Digest(); }, () => { return new SHA1(); });
        }

        protected override IDigest GenerateDigest()
        {
            return new Sha1Digest();
        }
    }
}