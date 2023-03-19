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

        private static readonly KeySizes[] _legalHashSizes = new KeySizes[] { new KeySizes(8, Global.SizeMax, 8) };

        private static readonly KeySizes[] _legalStateSizes = new KeySizes[]
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
        /// <param name="hashSize">Legal hash size 8-512 bits (8 bits increments).</param>

        public Skein(int hashSize, int stateSize) : base($"Skein{hashSize}-{stateSize}", hashSize)
        {
            if (!DetectionUtilities.ValidSize(_legalHashSizes, hashSize))
            {
                throw new CryptographicException("Legal hash size is greater than or equal to 8 bits (8 bits increments).");
            }
            if (!DetectionUtilities.ValidSize(_legalStateSizes, stateSize))
            {
                throw new CryptographicException("Legal state size 256, 512, 1024 bits.");
            }
            _stateSize = stateSize;
        }

        #endregion Construction

        internal static HashAlgorithmName GetAlgorithmName(int hashSize, int stateSize)
        {
            if (!DetectionUtilities.ValidSize(_legalHashSizes, hashSize))
            {
                throw new CryptographicException("Legal hash size is greater than or equal to 8 bits (8 bits increments).");
            }
            if (!DetectionUtilities.ValidSize(_legalStateSizes, stateSize))
            {
                throw new CryptographicException("Legal state size 256, 512, 1024 bits.");
            }
            return new HashAlgorithmName($"Skein{hashSize}-{stateSize}",
                                         hashSize,
                                         () => { return new SkeinDigest(stateSize, hashSize); },
                                         () => { return new Skein(hashSize, stateSize); });
        }

        internal static bool ValidHashSize(int hashSize)
        {
            return DetectionUtilities.ValidSize(_legalHashSizes, hashSize);
        }

        internal static bool ValidStateSize(int stateSize)
        {
            return DetectionUtilities.ValidSize(_legalStateSizes, stateSize);
        }

        /// <inheritdoc/>
        protected override IDigest GenerateDigest()
        {
            return new SkeinDigest(_stateSize, _hashSize);
        }
    }
}