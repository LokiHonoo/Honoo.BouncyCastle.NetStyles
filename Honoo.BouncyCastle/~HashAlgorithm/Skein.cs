using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Skein : HashAlgorithm
    {
        #region Properties

        private const string NAME = "Skein";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };

        private static readonly KeySizes[] LEGAL_STATE_SIZES = new KeySizes[]
        {
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0),
            new KeySizes(1024, 1024, 0)
        };

        private readonly int _stateSize;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Skein class.
        /// </summary>
        /// <param name="hashSize">Legal hash size is greater than or equal to 8 bits (8 bits increments).</param>
        /// <param name="stateSize">Legal state size 256, 512, 1024 bits.</param>

        public Skein(int hashSize, int stateSize = 256) : base($"{NAME}{hashSize}-{stateSize}", hashSize)
        {
            if (!DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                throw new CryptographicException("Legal hash size is greater than or equal to 8 bits (8 bits increments).");
            }
            if (!DetectionUtilities.ValidSize(LEGAL_STATE_SIZES, stateSize))
            {
                throw new CryptographicException("Legal state size 256, 512, 1024 bits.");
            }
            _stateSize = stateSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size is greater than or equal to 8 bits (8 bits increments).</param>
        /// <param name="stateSize">Legal state size 256, 512, 1024 bits.</param>
        /// <returns></returns>
        public static Skein Create(int hashSize, int stateSize = 256)
        {
            return new Skein(hashSize, stateSize);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize, int stateSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}-{stateSize}",
                                         hashSize,
                                         () => { return new SkeinDigest(stateSize, hashSize); },
                                         () => { return new Skein(hashSize, stateSize); });
        }

        internal static bool ValidHashSize(int hashSize)
        {
            return DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize);
        }

        internal static bool ValidStateSize(int stateSize)
        {
            return DetectionUtilities.ValidSize(LEGAL_STATE_SIZES, stateSize);
        }

        /// <inheritdoc/>
        protected override IDigest GetDigest()
        {
            return new SkeinDigest(_stateSize, _hashSize);
        }
    }
}