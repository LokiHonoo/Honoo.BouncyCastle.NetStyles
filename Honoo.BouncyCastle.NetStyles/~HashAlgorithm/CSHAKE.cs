using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class CSHAKE : HashAlgorithm
    {
        #region Properties

        private const string NAME = "CSHAKE";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(256, 512, 256) };
        private readonly byte[] _customization;
        private readonly byte[] _nist;
        private IDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the CSHAKE class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        /// <param name="nist">Nist bytes.</param>
        /// <param name="customization">Customization bytes.</param>
        public CSHAKE(int hashSize, byte[] nist = null, byte[] customization = null) : base($"{NAME}{hashSize / 2}-{hashSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            _nist = nist;
            _customization = customization;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 512 bits.</param>
        /// <param name="nist">NIST name. Avoid using it if not required.</param>
        /// <param name="customization">Customization bytes.</param>
        /// <returns></returns>
        public static CSHAKE Create(int hashSize, byte[] nist = null, byte[] customization = null)
        {
            return new CSHAKE(hashSize, nist, customization);
        }

        /// <inheritdoc/>
        public override int ComputeFinal(byte[] outputBuffer, int offset)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.DoFinal(outputBuffer, offset);
            return _hashSize / 8;
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
            return new HashAlgorithmName($"{NAME}{hashSize / 2}-{hashSize}",
                                         hashSize,
                                         () => { return new CShakeDigest(hashSize / 2, null, null); },
                                         () => { return new CSHAKE(hashSize); });
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
            return new CShakeDigest(_hashSize / 2, _nist, _customization);
        }
    }
}