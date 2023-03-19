using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA384 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA384 class.
        /// </summary>
        public SHA384() : base("SHA384", 384)
        {
        }

        #endregion Construction
        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA384 Create()
        {
            return new SHA384();
        }
        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("SHA384", 384, () => { return new Sha384Digest(); }, () => { return new SHA384(); });
        }
        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new Sha384Digest();
        }
    }
}