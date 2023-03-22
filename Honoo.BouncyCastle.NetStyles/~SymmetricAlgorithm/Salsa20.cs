using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Salsa20 : SymmetricStreamAlgorithm
    {
        #region Properties

        private const int DEFAULT_IV_SIZE = 64;
        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Stream;
        private const string NAME = "Salsa20";
        private static readonly KeySizes[] LEGAL_IV_SIZES = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(128, 256, 128) };
        private readonly int _rounds;

        /// <summary>
        /// Gets legal iv size bits. Legal iv size 64 bits.
        /// </summary>
        public override KeySizes[] LegalIVSizes => (KeySizes[])LEGAL_IV_SIZES.Clone();

        /// <summary>
        /// Gets legal key size bits. Legal key size 128, 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Salsa20 class.
        /// </summary>
        /// <param name="rounds">Rounds must be an even number.</param>
        public Salsa20(int rounds = 20) : base(NAME, DEFAULT_KEY_SIZE, DEFAULT_IV_SIZE)
        {
            if (rounds <= 0 || rounds % 2 > 0)
            {
                throw new CryptographicException("Rounds must be an even number.");
            }
            _rounds = rounds;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="rounds">Rounds must be an even number.</param>
        /// <returns></returns>
        public static Salsa20 Create(int rounds = 20)
        {
            return new Salsa20(rounds);
        }

        /// <inheritdoc/>
        public override bool ValidIVSize(int ivSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_IV_SIZES, ivSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal iv size 64 bits.";
                return false;
            }
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
                exception = "Legal key size 128, 256 bits.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, 0, () => { return new Salsa20(); });
        }

        /// <inheritdoc/>
        internal override IStreamCipher GetEngine()
        {
            return new Salsa20Engine(_rounds);
        }
    }
}