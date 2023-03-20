using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RIPEMD160 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 160;
        private const string NAME = "RIPEMD160";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RIPEMD160 class.
        /// </summary>
        public RIPEMD160() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RIPEMD160 Create()
        {
            return new RIPEMD160();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new RipeMD160Digest(); }, () => { return new RIPEMD160(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new RipeMD160Digest();
        }
    }
}