using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class GOST3411_2012 : HashAlgorithm
    {
        #region Properties

        private const string NAME = "GOST3411-2012-";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(256, 512, 256) };
        private IDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the GOST3411_2012 class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        public GOST3411_2012(int hashSize) : base($"{NAME}{hashSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        /// <returns></returns>
        public static GOST3411_2012 Create(int hashSize)
        {
            return new GOST3411_2012(hashSize);
        }

        /// <inheritdoc/>
        public override byte[] ComputeFinal()
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            byte[] hash = new byte[_hashSize / 8];
            _digest.DoFinal(hash, 0);
            return hash;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <inheritdoc/>
        public override void Update(byte[] buffer, int offset, int length)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}",
                                         hashSize,
                                         () => { return GetDigest(hashSize); },
                                         () => { return new GOST3411_2012(hashSize); });
        }

        internal static bool ValidHashSize(int hashSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal hash size 256, 512 bits.";
                return false;
            }
        }

        private IDigest GetDigest()
        {
            return GetDigest(_hashSize);
        }

        private static IDigest GetDigest(int hashSize)
        {
            if (hashSize == 512)
            {
                return new Gost3411_2012_512Digest();
            }
            else
            {
                return new Gost3411_2012_256Digest();
            }
        }
    }
}