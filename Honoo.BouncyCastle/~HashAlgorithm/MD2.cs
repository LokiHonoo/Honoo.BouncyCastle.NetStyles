using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class MD2 : HashAlgorithm
    {
        #region Construction

        /// <summary>
        /// Initializes a new instance of the MD2 class.
        /// </summary>
        public MD2() : base("MD2", 128)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static MD2 Create()
        {
            return new MD2();
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName("MD2", 128, () => { return new MD2Digest(); }, () => { return new MD2(); });
        }
        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new MD2Digest();
        }
    }
}