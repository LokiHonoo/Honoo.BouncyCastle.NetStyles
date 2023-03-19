using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Blowfish : SymmetricBlockAlgorithm
    {
        #region Properties

        private const int BLOCK_SIZE = 64;
        private const int DEFAULT_KEY_SIZE = 128;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "Blowfish";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(128, 128, 0) };

        /// <summary>
        /// Gets legal key size bits. Legal key size 128 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Blowfish class.
        /// </summary>
        public Blowfish() : base(NAME, BLOCK_SIZE, DEFAULT_KEY_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static Blowfish Create()
        {
            return new Blowfish();
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
                exception = "Legal key size 128 bits.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, BLOCK_SIZE, () => { return new Blowfish(); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new BlowfishEngine();
        }
    }
}