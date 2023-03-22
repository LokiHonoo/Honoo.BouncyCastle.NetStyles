using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Rijndael : SymmetricBlockAlgorithm
    {
        #region Properties

        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "Rijndael";
        private static readonly KeySizes[] LEGAL_BLOCK_SIZES = new KeySizes[] { new KeySizes(128, 256, 32) };
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(128, 256, 32) };

        /// <summary>
        /// Gets legal key size bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Rijndael class.
        /// </summary>
        /// <param name="blockSize">Legal block size 128, 160, 192, 224, 256 bits.</param>
        public Rijndael(int blockSize) : base($"{NAME}{blockSize}", blockSize, DEFAULT_KEY_SIZE)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_BLOCK_SIZES, blockSize))
            {
                throw new CryptographicException("Legal block size 128, 160, 192, 224, 256 bits.");
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="blockSize">Legal block size 128, 160, 192, 224, 256 bits.</param>
        /// <returns></returns>
        public static Rijndael Create(int blockSize)
        {
            return new Rijndael(blockSize);
        }

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal block size 128, 160, 192, 224, 256 bits.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName(int blockSize)
        {
            return new SymmetricAlgorithmName($"{NAME}{blockSize}", KIND, blockSize, () => { return new Rijndael(blockSize); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new RijndaelEngine(_blockSize);
        }
    }
}