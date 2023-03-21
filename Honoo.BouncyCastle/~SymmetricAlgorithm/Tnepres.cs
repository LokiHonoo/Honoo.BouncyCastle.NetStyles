using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Tnepres : SymmetricBlockAlgorithm
    {
        #region Properties

        private const int BLOCK_SIZE = 128;
        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "Tnepres";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(32, 512, 32) };

        /// <summary>
        /// Gets legal key size bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Tnepres class.
        /// </summary>
        public Tnepres() : base(NAME, BLOCK_SIZE, DEFAULT_KEY_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static Tnepres Create()
        {
            return new Tnepres();
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
                exception = "Legal key size 32-512 bits (32 bits increments).";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, BLOCK_SIZE, () => { return new Tnepres(); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new TnepresEngine();
        }
    }
}