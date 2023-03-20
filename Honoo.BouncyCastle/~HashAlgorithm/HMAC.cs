using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Computes a HMAC using the specified hash algorithm.
    /// </summary>
    public sealed class HMAC
    {
        #region Properties

        private const int DEFAULT_KEY_SIZE = 128;
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashSize;
        private readonly string _name;
        private IMac _digest;
        private bool _initialized = false;
        private int _keySize = DEFAULT_KEY_SIZE;
        private KeyParameter _parameters = null;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        internal HMAC(HashAlgorithm hashAlgorithm)
        {
            HashAlgorithmName.TryGetAlgorithmName(hashAlgorithm.Name, out _hashAlgorithm);
            _name = $"{hashAlgorithm.Name}/HMAC";
            _hashSize = hashAlgorithm.HashSize;
        }

        /// <summary>
        /// Initializes a new instance of the HMAC class.
        /// </summary>
        /// <param name="algorithmName">Hash algorithm name.</param>
        private HMAC(HashAlgorithmName algorithmName)
        {
            _hashAlgorithm = algorithmName;
            _name = $"{algorithmName.Name}/HMAC";
            _hashSize = algorithmName.HashSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Hash algorithm name.</param>
        /// <returns></returns>
        public static HMAC Create(HashAlgorithmName algorithmName)
        {
            return new HMAC(algorithmName);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeHash()
        {
            InspectParameters();
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            byte[] hash = new byte[_hashSize / 8];
            _digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] rgb)
        {
            return ComputeHash(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
            byte[] hash = new byte[_hashSize / 8];
            _digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Exports key.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key)
        {
            InspectParameters();
            key = _parameters.GetKey();
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size.
        /// </summary>
        public void GenerateParameters()
        {
            byte[] key = new byte[DEFAULT_KEY_SIZE / 8];
            Common.SecureRandom.NextBytes(key);
            _parameters = new KeyParameter(key);
            _keySize = DEFAULT_KEY_SIZE;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        public void GenerateParameters(int keySize)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            byte[] key = new byte[keySize / 8];
            Common.SecureRandom.NextBytes(key);
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports key.
        /// </summary>
        /// <param name="key">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        public void ImportParameters(byte[] key)
        {
            int keySize = key.Length * 8;
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        public void Update(byte[] rgb)
        {
            Update(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public void Update(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size is more than or equal to 8 bits (8 bits increments).";
                return false;
            }
        }

        private IMac GetDigest()
        {
            IMac digest = new HMac(_hashAlgorithm.GetDigest());
            digest.Init(_parameters);
            return digest;
        }

        private void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}