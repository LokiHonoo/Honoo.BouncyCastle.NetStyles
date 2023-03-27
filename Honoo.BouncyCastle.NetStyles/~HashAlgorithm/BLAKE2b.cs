using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class BLAKE2b : HashAlgorithm
    {
        #region Properties

        private const string NAME = "BLAKE2b";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(8, 512, 8) };
        private readonly byte[] _key;
        private readonly byte[] _personalization;
        private readonly byte[] _salt;
        private IDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the BLAKE2b class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-512 bits (8 bits increments).</param>
        /// <param name="key">Key need null or less than 64 bytes.</param>
        /// <param name="salt">Salt need null or less than 16 bytes.</param>
        /// <param name="personalization">Personalization need null or less than 16 bytes.</param>
        public BLAKE2b(int hashSize, byte[] key = null, byte[] salt = null, byte[] personalization = null) : base($"{NAME}{hashSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (key != null && key.Length != 64)
            {
                throw new CryptographicException("Argument key length need null or less than 64 bytes.");
            }
            if (salt != null && key.Length != 16)
            {
                throw new CryptographicException("Argument salt length need null or less than 16 bytes.");
            }
            if (personalization != null && key.Length != 16)
            {
                throw new CryptographicException("Argument personalization length need null or less than 16 bytes.");
            }
            _key = key;
            _salt = salt;
            _personalization = personalization;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 8-512 bits (8 bits increments).</param>
        /// <param name="key">Key need null or less than 64 bytes.</param>
        /// <param name="salt">Salt need null or less than 16 bytes.</param>
        /// <param name="personalization">Personalization need null or less than 16 bytes.</param>
        /// <returns></returns>
        public static BLAKE2b Create(int hashSize, byte[] key = null, byte[] salt = null, byte[] personalization = null)
        {
            return new BLAKE2b(hashSize, key, salt, personalization);
        }

        /// <inheritdoc/>
        public override int ComputeFinal( byte[] outputBuffer, int offset)
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
            return new HashAlgorithmName($"{NAME}{hashSize}",
                                         hashSize,
                                         () => { return new Blake2bDigest(hashSize); },
                                         () => { return new BLAKE2b(hashSize); });
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
                exception = "Legal hash size 8-512 bits (8 bits increments).";
                return false;
            }
        }

        private IDigest GetDigest()
        {
            return new Blake2bDigest(_key, _hashSize / 8, _salt, _personalization);
        }
    }
}