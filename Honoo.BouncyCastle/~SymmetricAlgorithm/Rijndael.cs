using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Rijndael : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _legalBlockSizes = new KeySizes[] { new KeySizes(128, 256, 32) };
        private static readonly KeySizes[] _legalKeySizes = new KeySizes[] { new KeySizes(128, 256, 32) };

        /// <summary>
        /// Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])_legalKeySizes.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Rijndael class.
        /// </summary>
        /// <param name="blockSize">Legal block size 128, 160, 192, 224, 256 bits.</param>
        public Rijndael(int blockSize) : base($"Rijndael{blockSize}", SymmetricAlgorithmKind.Block, blockSize)
        {
        }

        #endregion Construction

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
        }

        internal static SymmetricAlgorithmName GetAlgorithmName(int blockSize)
        {
            if (DetectionUtilities.ValidSize(_legalBlockSizes, blockSize))
            {
                return new SymmetricAlgorithmName($"Rijndael{blockSize}",
                                                  SymmetricAlgorithmKind.Block,
                                                  () => { return new RijndaelEngine(blockSize); },
                                                  () => { return new Rijndael(blockSize); });
            }
            throw new CryptographicException("Legal block size 128, 160, 192, 224, 256 bits.");
        }

        protected override IBlockCipher GenerateEngine()
        {
            return new RijndaelEngine(_blockSize);
        }
    }
}