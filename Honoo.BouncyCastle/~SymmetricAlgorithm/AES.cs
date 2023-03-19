using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class AES : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _legalKeySizes = new KeySizes[] { new KeySizes(128, 256, 64) };

        /// <summary>
        /// Legal key size 128, 192, 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])_legalKeySizes.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the AES class.
        /// </summary>
        public AES() : base("AES", SymmetricAlgorithmKind.Block, 128)
        {
        }

        #endregion Construction

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName("AES",
                                              SymmetricAlgorithmKind.Block,
                                              () => { return new AesEngine(); },
                                              () => { return new AES(); });
        }

        protected override IBlockCipher GenerateEngine()
        {
            return new AesEngine();
        }
    }
}