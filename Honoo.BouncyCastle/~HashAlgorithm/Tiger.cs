using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Tiger : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 192;
        private const string NAME = "Tiger";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Tiger class.
        /// </summary>
        public Tiger() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static Tiger Create()
        {
            return new Tiger();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new TigerDigest(); }, () => { return new Tiger(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new TigerDigest();
        }
    }
}