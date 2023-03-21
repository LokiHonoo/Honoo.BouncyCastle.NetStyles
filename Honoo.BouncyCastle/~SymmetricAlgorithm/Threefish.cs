using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Threefish : SymmetricBlockAlgorithm
    {
        #region Properties

        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "Threefish";

        private static readonly KeySizes[] LEGAL_BLOCK_SIZES = new KeySizes[]
        {
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0),
            new KeySizes(1024, 1024, 0)
        };

        private static readonly IDictionary<int, KeySizes[]> LEGAL_KEY_SIZES = new Dictionary<int, KeySizes[]>()
        {
            { 256, new KeySizes[] { new KeySizes(256, 256, 0) } },
            { 512, new KeySizes[] { new KeySizes(512, 512, 0) } },
            { 1024, new KeySizes[] { new KeySizes(1024, 1024, 0) } }
        };

        /// <summary>
        /// Gets legal key size bits. Legal key size same as block size.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES[_blockSize].Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Threefish class.
        /// </summary>
        /// <param name="blockSize">Legal block size 256, 512, 1024 bits.</param>
        public Threefish(int blockSize) : base($"{NAME}{blockSize}", blockSize, blockSize)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_BLOCK_SIZES, blockSize))
            {
                throw new CryptographicException("Legal block size 256, 512, 1024 bits.");
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="blockSize">Legal block size 256, 512, 1024 bits.</param>
        /// <returns></returns>
        public static Threefish Create(int blockSize)
        {
            return new Threefish(blockSize);
        }

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES[_blockSize], keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size same as block size.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName(int blockSize)
        {
            return new SymmetricAlgorithmName($"{NAME}{blockSize}", KIND, blockSize, () => { return new Threefish(blockSize); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new ThreefishEngine(_blockSize);
        }
    }
}