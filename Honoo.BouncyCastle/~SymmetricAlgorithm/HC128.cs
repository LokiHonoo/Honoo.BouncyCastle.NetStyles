using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class HC128 : SymmetricStreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _legalIVSizes = new KeySizes[] { new KeySizes(0, 128, 8) };
        private static readonly KeySizes[] _legalKeySizes = new KeySizes[] { new KeySizes(128, 128, 0) };

        /// <summary>
        /// Gets legal iv size bits. Legal IV size 0-128 bits (8 bits increments).
        /// </summary>
        public override KeySizes[] LegalIVSizes => (KeySizes[])_legalIVSizes.Clone();

        /// <summary>
        /// Gets legal key size bits. Legal key size 128 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])_legalKeySizes.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the HC128 class.
        /// </summary>
        public HC128() : base("HC128", SymmetricAlgorithmKind.Stream)
        {
        }

        #endregion Construction

        public override bool ValidIVSize(int ivSize)
        {
            return DetectionUtilities.ValidSize(_legalIVSizes, ivSize);
        }

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName("HC128",
                                              SymmetricAlgorithmKind.Stream,
                                              null,
                                              () => { return new HC128(); });
        }

        protected override IStreamCipher GenerateEngine()
        {
            return new HC128Engine();
        }
    }
}