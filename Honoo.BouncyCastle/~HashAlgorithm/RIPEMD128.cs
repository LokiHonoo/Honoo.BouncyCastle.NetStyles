using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD128 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 128;
        private const string NAME = "RIPEMD128";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD128 class.
        /// </summary>
        public RIPEMD128() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD128 Create()
        {
            return new RIPEMD128();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD128Digest(); }, () => { return new RIPEMD128(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new RipeMD128Digest();
        }
    }
}