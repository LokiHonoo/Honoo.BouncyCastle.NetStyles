using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class XSalsa20 : SymmetricStreamAlgorithm
    {
        #region Properties

        private const int DEFAULT_IV_SIZE = 192;
        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Stream;
        private const string NAME = "XSalsa20";
        private static readonly KeySizes[] LEGAL_IV_SIZES = new KeySizes[] { new KeySizes(192, 192, 0) };
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(256, 256, 0) };

        /// <summary>
        /// Gets legal iv size bits. Legal iv size 192 bits.
        /// </summary>
        public override KeySizes[] LegalIVSizes => (KeySizes[])LEGAL_IV_SIZES.Clone();

        /// <summary>
        /// Gets legal key size bits. Legal key size 256 bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the XSalsa20 class.
        /// </summary>
        public XSalsa20() : base(NAME, DEFAULT_KEY_SIZE, DEFAULT_IV_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static XSalsa20 Create()
        {
            return new XSalsa20();
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
                exception = "Legal iv size 192 bits.";
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
            return new SymmetricAlgorithmName(NAME, KIND, 0, () => { return new XSalsa20(); });
        }

        /// <inheritdoc/>
        internal override IStreamCipher GetEngine()
        {
            return new XSalsa20Engine();
        }
    }
}