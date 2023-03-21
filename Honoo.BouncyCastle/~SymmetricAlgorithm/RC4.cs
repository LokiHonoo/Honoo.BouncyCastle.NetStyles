using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RC4 : SymmetricStreamAlgorithm
    {
        #region Properties

        private const int DEFAULT_IV_SIZE = 0;
        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Stream;
        private const string NAME = "RC4";
        private static readonly KeySizes[] LEGAL_IV_SIZES = new KeySizes[] { new KeySizes(0, 0, 0) };
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(256, 256, 0) };

        /// <summary>
        /// Gets legal iv size bits. Not need iv.
        /// </summary>
        public override KeySizes[] LegalIVSizes => (KeySizes[])LEGAL_IV_SIZES.Clone();

        /// <summary>
        /// Gets legal key size bits. Legal key size 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RC4 class.
        /// </summary>
        public RC4() : base(NAME, DEFAULT_KEY_SIZE, DEFAULT_IV_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RC4 Create()
        {
            return new RC4();
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
                exception = "Not need iv.";
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
                exception = "Legal key size 256 bits.";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, 0, () => { return new RC4(); });
        }

        /// <inheritdoc/>
        internal override IStreamCipher GetEngine()
        {
            return new RC4Engine();
        }
    }
}