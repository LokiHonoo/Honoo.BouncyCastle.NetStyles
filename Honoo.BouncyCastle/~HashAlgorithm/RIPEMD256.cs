using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD256 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 256;
        private const string NAME = "RIPEMD256";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD256 class.
        /// </summary>
        public RIPEMD256() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD256 Create()
        {
            return new RIPEMD256();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD256Digest(); }, () => { return new RIPEMD256(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new RipeMD256Digest();
        }
    }
}