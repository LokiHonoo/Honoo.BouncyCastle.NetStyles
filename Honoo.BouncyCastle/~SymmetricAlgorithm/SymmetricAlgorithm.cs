using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0079:请删除不必要的忽略", Justification = "<挂起>")]
    public abstract class SymmetricAlgorithm
    {
        #region Properties

#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释
        protected int _blockSize;
        protected IBufferedCipher _decryptor = null;
        protected IBufferedCipher _encryptor = null;
        protected bool _initialized = false;
        protected int _ivSize;
        protected int _keySize;
        protected SymmetricCipherMode _mode = SymmetricCipherMode.CBC;
        protected SymmetricPaddingMode _padding = SymmetricPaddingMode.PKCS7;
        protected ICipherParameters _parameters = null;
        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;
#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释

        /// <summary>
        /// Gets block size bits. The value will be 0 if the algorithm is a stream algorithm.
        /// </summary>
        public int BlockSize => _blockSize;

        /// <summary>
        /// Gets iv size bits.
        /// </summary>
        public int IVSize => _ivSize;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets symmetric algorithm kind of the algorithm.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public abstract KeySizes[] LegalIVSizes { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public abstract KeySizes[] LegalKeySizes { get; }

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm. Valid for block algorithm only.
        /// </summary>
        public abstract SymmetricCipherMode Mode { get; set; }

        /// <summary>
        /// Gets symmetric algorithm name of the algorithm.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm. Valid for block algorithm only.
        /// </summary>
        public abstract SymmetricPaddingMode Padding { get; set; }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        /// <param name="blockSize"></param>
        /// <param name="defaultKeySize"></param>
        protected SymmetricAlgorithm(string name, SymmetricAlgorithmKind kind, int blockSize, int defaultKeySize, int defaultIVSize)
        {
            _name = name;
            _kind = kind;
            _blockSize = blockSize;
            _keySize = defaultKeySize;
            _ivSize = defaultIVSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static SymmetricAlgorithm Create(SymmetricAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Create CMAC by this symmetric algorithm. Throw <see cref="CryptographicException"/> if the algorithm is not a block algorithm.
        /// </summary>
        /// <returns></returns>
        public CMAC CreateCMAC()
        {
            return CreateCMAC(_blockSize);
        }

        /// <summary>
        /// Create CMAC by this symmetric algorithm. Throw <see cref="CryptographicException"/> if the algorithm is not a block algorithm.
        /// </summary>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        /// <returns></returns>
        public CMAC CreateCMAC(int macSize)
        {
            SymmetricAlgorithmName.TryGetAlgorithmName(_name, out SymmetricAlgorithmName algorithmName);
            return new CMAC(algorithmName, macSize);
        }

        /// <summary>
        /// Create MAC by this symmetric algorithm. Throw <see cref="CryptographicException"/> if the algorithm is not a block algorithm.
        /// </summary>
        /// <returns></returns>
        public MAC CreateMAC()
        {
            return CreateMAC(_blockSize);
        }

        /// <summary>
        /// Create MAC by this symmetric algorithm. Throw <see cref="CryptographicException"/> if the algorithm is not a block algorithm.
        /// </summary>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        /// <returns></returns>
        public MAC CreateMAC(int macSize)
        {
            SymmetricAlgorithmName.TryGetAlgorithmName(_name, out SymmetricAlgorithmName algorithmName);
            return new MAC(algorithmName, macSize);
        }

        /// <summary>
        /// Decrypts data with the symmetric algorithm.
        /// </summary>
        /// <returns></returns>
        public byte[] DecryptFinal()
        {
            InspectKey();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false);
            }
            byte[] result = _decryptor.DoFinal();
            FixDecrypted();
            return result;
        }

        /// <summary>
        /// Decrypts data with the symmetric algorithm.
        /// </summary>
        /// <param name="rgb">The encrypted data.</param>
        /// <returns></returns>
        public byte[] DecryptFinal(byte[] rgb)
        {
            return DecryptFinal(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Decrypts data with the symmetric algorithm.
        /// </summary>
        /// <param name="buffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] DecryptFinal(byte[] buffer, int offset, int length)
        {
            InspectKey();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false);
            }
            byte[] result = _decryptor.DoFinal(buffer, offset, length);
            FixDecrypted();
            return result;
        }

        /// <summary>
        /// Decrypts data with the symmetric algorithm. Return write length of output.
        /// </summary>
        /// <param name="inputBuffer">The encrypted data buffer.</param>
        /// <param name="inOffset">The starting offset to read.</param>
        /// <param name="inLength">The length to read.</param>
        /// <param name="outputBuffer">The output buffer to write.</param>
        /// <param name="outOffset">The starting offset to write.</param>
        /// <returns></returns>
        public int DecryptUpdate(byte[] inputBuffer, int inOffset, int inLength, byte[] outputBuffer, int outOffset)
        {
            InspectKey();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false);
            }
            return _decryptor.ProcessBytes(inputBuffer, inOffset, inLength, outputBuffer, outOffset);
        }

        /// <summary>
        /// Encrypts data with the symmetric algorithm.
        /// </summary>
        /// <returns></returns>
        public byte[] EncryptFinal()
        {
            InspectKey();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true);
            }
            byte[] result = _encryptor.DoFinal();
            FixEncrypted();
            return result;
        }

        /// <summary>
        /// Encrypts data with the symmetric algorithm.
        /// </summary>
        /// <param name="rgb">The data to be decrypted.</param>
        /// <returns></returns>
        public byte[] EncryptFinal(byte[] rgb)
        {
            return EncryptFinal(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Encrypts data with the symmetric algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer to be decrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] EncryptFinal(byte[] buffer, int offset, int length)
        {
            InspectKey();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true);
            }
            byte[] result = _encryptor.DoFinal(buffer, offset, length);
            FixEncrypted();
            return result;
        }

        /// <summary>
        /// Encrypts data with the symmetric algorithm. Return write length of output.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be decrypted.</param>
        /// <param name="inOffset">The starting offset to read.</param>
        /// <param name="inLength">The length to read.</param>
        /// <param name="outputBuffer">The output buffer to write.</param>
        /// <param name="outOffset">The starting offset to write.</param>
        /// <returns></returns>
        public int EncryptUpdate(byte[] inputBuffer, int inOffset, int inLength, byte[] outputBuffer, int outOffset)
        {
            InspectKey();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true);
            }
            return _encryptor.ProcessBytes(inputBuffer, inOffset, inLength, outputBuffer, outOffset);
        }

        /// <summary>
        /// Exports key and iv.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <param name="iv">Output iv bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key, out byte[] iv)
        {
            InspectKey();
            if (_parameters.GetType() == typeof(AeadParameters))
            {
                AeadParameters parameters = (AeadParameters)_parameters;
                key = parameters.Key.GetKey();
                // BouncyCastle has not clone nonce and associatedText.
                iv = (byte[])parameters.GetNonce().Clone();
            }
            else if (_parameters.GetType() == typeof(ParametersWithIV))
            {
                ParametersWithIV parameters = (ParametersWithIV)_parameters;
                key = ((KeyParameter)parameters.Parameters).GetKey();
                iv = parameters.GetIV();
            }
            else
            {
                KeyParameter parameter = (KeyParameter)_parameters;
                key = parameter.GetKey();
                iv = null;
            }
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="ivSize">IV size bits.</param>
        public void GenerateParameters(int keySize, int ivSize)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (!ValidIVSize(ivSize, out exception))
            {
                throw new CryptographicException(exception);
            }
            byte[] key = new byte[keySize / 8];
            Common.SecureRandom.NextBytes(key);
            _parameters = GetKeyParameter(key);
            if (ivSize > 0)
            {
                byte[] iv = new byte[ivSize / 8];
                Common.SecureRandom.NextBytes(iv);
                _parameters = new ParametersWithIV(_parameters, iv);
            }
            _keySize = keySize;
            _ivSize = ivSize;
            _encryptor = null;
            _decryptor = null;
            _initialized = true;
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        public abstract void GenerateParameters();

        /// <summary>
        /// Imports key and iv.
        /// </summary>
        /// <param name="key">Import key bytes.</param>
        /// <param name="iv">Import iv bytes.</param>
        public void ImportParameters(byte[] key, byte[] iv)
        {
            int keySize = key.Length * 8;
            int ivSize = iv == null || iv.Length == 0 ? 0 : iv.Length * 8;
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (!ValidIVSize(ivSize, out exception))
            {
                throw new CryptographicException(exception);
            }
            _parameters = GetKeyParameter(key);
            if (ivSize > 0)
            {
                _parameters = new ParametersWithIV(_parameters, iv);
            }
            _keySize = keySize;
            _ivSize = ivSize;
            _encryptor = null;
            _decryptor = null;
            _initialized = true;
        }

        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public void Reset()
        {
            /*
             * BUG: GCM cipher mode cannot be auto reused. So set null.
             */
            _encryptor = null;
            _decryptor = null;
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public abstract bool ValidIVSize(int ivSize, out string exception);

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public abstract bool ValidKeySize(int keySize, out string exception);

        internal ICipherParameters ExportParameters()
        {
            InspectKey();
            return _parameters;
        }

        /// <summary>
        /// Do fix at final decrypted.
        /// </summary>
        protected virtual void FixDecrypted()
        { }

        /// <summary>
        /// Do fix at final encrypted.
        /// </summary>
        protected virtual void FixEncrypted()
        { }

        /// <summary>
        ///
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <returns></returns>
        protected abstract IBufferedCipher GetCipher(bool forEncryption);

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected virtual KeyParameter GetKeyParameter(byte[] key)
        {
            return new KeyParameter(key);
        }

        private void InspectKey()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}