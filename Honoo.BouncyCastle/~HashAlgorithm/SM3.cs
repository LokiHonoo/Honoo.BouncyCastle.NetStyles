using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SM3 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 256;
        private const string NAME = "SM3";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SM3 class.
        /// </summary>
        public SM3() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SM3 Create()
        {
            return new SM3();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new SM3Digest(); }, () => { return new SM3(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new SM3Digest();
        }
    }
}