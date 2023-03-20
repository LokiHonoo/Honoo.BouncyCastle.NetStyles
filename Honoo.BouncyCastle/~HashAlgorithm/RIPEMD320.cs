using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD320 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 320;
        private const string NAME = "RIPEMD320";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD320 class.
        /// </summary>
        public RIPEMD320() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD320 Create()
        {
            return new RIPEMD320();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD320Digest(); }, () => { return new RIPEMD320(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new RipeMD320Digest();
        }
    }
}