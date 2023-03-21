using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Whirlpool : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 512;
        private const string NAME = "Whirlpool";

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Whirlpool class.
        /// </summary>
        public Whirlpool() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static Whirlpool Create()
        {
            return new Whirlpool();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new WhirlpoolDigest(); }, () => { return new Whirlpool(); });
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new WhirlpoolDigest();
        }
    }
}