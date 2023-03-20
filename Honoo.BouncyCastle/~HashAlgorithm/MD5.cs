using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class MD5 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 128;
        private const string NAME = "MD5";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the MD5 class.
        /// </summary>
        public MD5() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static MD5 Create()
        {
            return new MD5();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new MD5Digest(); }, () => { return new MD5(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new MD5Digest();
        }
    }
}