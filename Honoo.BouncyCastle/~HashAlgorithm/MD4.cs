using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class MD4 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 128;
        private const string NAME = "MD4";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the MD4 class.
        /// </summary>
        public MD4() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static MD4 Create()
        {
            return new MD4();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new MD4Digest(); }, () => { return new MD4(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new MD4Digest();
        }
    }
}