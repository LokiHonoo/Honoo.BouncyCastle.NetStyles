using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Computes a HMAC using the specified hash algorithm.
    /// </summary>
    public sealed class HMAC : HashAlgorithm
    {
        #region Properties

        private const int DEFAULT_KEY_SIZE = 128;
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };
        private readonly IDigest _core;
        private IMac _digest;
        private bool _initialized = false;
        private int _keySize = DEFAULT_KEY_SIZE;
        private KeyParameter _parameters = null;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the HMAC class.
        /// </summary>
        /// <param name="algorithmName">HMAC name.</param>
        public HMAC(HMACName algorithmName) : base(algorithmName.Name, algorithmName.HashSize)
        {
            _core = algorithmName.HashAlgorithm.GetEngine();
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">HMAC name.</param>
        /// <returns></returns>
        public static HMAC Create(HMACName algorithmName)
        {
            return new HMAC(algorithmName);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
        public override byte[] ComputeFinal()
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
        /// Exports a <see cref="ICipherParameters"/> containing the HMAC parameters information associated.
        /// </summary>
        /// <returns></returns>
        public ICipherParameters ExportParameters()
        {
            InspectParameters();
            return _parameters;
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
            Common.SecureRandom.Value.NextBytes(key);
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
            Common.SecureRandom.Value.NextBytes(key);
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports a <see cref="ICipherParameters"/> that represents HMAC parameters information.
        /// </summary>
        /// <param name="parameters">A BouncyCastle <see cref="ICipherParameters"/> that represents an HMAC parameters.</param>
        public void ImportParameters(ICipherParameters parameters)
        {
            byte[] key = ((KeyParameter)parameters).GetKey();
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

        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="buffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public override void Update(byte[] buffer, int offset, int length)
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
            IMac digest = new HMac(_core);
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