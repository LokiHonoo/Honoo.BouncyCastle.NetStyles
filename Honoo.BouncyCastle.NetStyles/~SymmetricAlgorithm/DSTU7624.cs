using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class DSTU7624 : SymmetricBlockAlgorithm
    {
        #region Properties

        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "DSTU7624-";

        private static readonly KeySizes[] LEGAL_BLOCK_SIZES = new KeySizes[]
                {
            new KeySizes(128, 128, 0),
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0)
        };

        private static readonly IDictionary<int, KeySizes[]> LEGAL_KEY_SIZES = new Dictionary<int, KeySizes[]>()
        {
            { 128, new KeySizes[] { new KeySizes(128, 256, 128) } },
            { 256, new KeySizes[] { new KeySizes(256, 512, 256) } },
            { 512, new KeySizes[] { new KeySizes(512, 512, 0) } }
        };

        /// <summary>
        /// Gets legal key size bits.
        /// <para/>Legal key size 128, 256 bits when block size is 128 bits.
        /// <br/>Legal key size 256, 512 bits when block size is 256 bits.
        /// <br/>Legal key size 512 bits when block size is 512 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES[_blockSize].Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the DSTU7624 class.
        /// </summary>
        /// <param name="blockSize">Legal block size 128, 256, 512 bits.</param>
        public DSTU7624(int blockSize) : base($"{NAME}{blockSize}", blockSize, blockSize < 512 ? 256 : 512)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_BLOCK_SIZES, blockSize))
            {
                throw new CryptographicException("Legal block size 128, 256, 512 bits.");
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="blockSize">Legal block size 128, 256, 512 bits.</param>
        /// <returns></returns>
        public static DSTU7624 Create(int blockSize)
        {
            return new DSTU7624(blockSize);
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
                switch (_blockSize)
                {
                    case 128: exception = "Legal key size 128, 256 bits when block size is 128 bits."; break;
                    case 256: exception = "Legal key size 256, 512 bits when block size is 256 bits."; break;
                    case 512: exception = "Legal key size 512 bits when block size is 512 bits."; break;
                    default: exception = "Block size is invalid."; break;
                }
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName(int blockSize)
        {
            return new SymmetricAlgorithmName($"{NAME}{blockSize}", KIND, blockSize, () => { return new DSTU7624(blockSize); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new Dstu7624Engine(_blockSize);
        }
    }
}