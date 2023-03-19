using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using System.Xml.Linq;
using static Org.BouncyCastle.Crypto.Digests.SkeinEngine;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
    /// </summary>
    public abstract class SymmetricStreamAlgorithm : SymmetricAlgorithm
    {
        #region Properties


        private IBufferedCipher _decryptor = null;
        private IBufferedCipher _encryptor = null;
        private int _ivSize = 0;
        private int _keySize = 0;
        private ICipherParameters _parameters = null;

        #endregion Properties

        #region Construction


        protected SymmetricStreamAlgorithm(string name, SymmetricAlgorithmKind kind) : base(name, kind)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public new static SymmetricStreamAlgorithm Create(SymmetricAlgorithmName algorithmName)
        {
            return (SymmetricStreamAlgorithm)algorithmName.GenerateAlgorithm();
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
                _decryptor = GenerateCipher(false);
            }
            return _decryptor.DoFinal();
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
                _decryptor = GenerateCipher(false);
            }
            return _decryptor.DoFinal(buffer, offset, length);
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
                _decryptor = GenerateCipher(false);
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
                _encryptor = GenerateCipher(true);
            }
            return _encryptor.DoFinal();
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
                _encryptor = GenerateCipher(true);
            }
            return _encryptor.DoFinal(buffer, offset, length);

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
                _encryptor = GenerateCipher(true);
            }
            return _encryptor.ProcessBytes(inputBuffer, inOffset, inLength, outputBuffer, outOffset);
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        public void GenerateParameters()
        {
            int keySize = _blockSize;
            int ivSize;
            switch (_mode)
            {
                case SymmetricCipherMode.CBC: ivSize = _blockSize; break;
                case SymmetricCipherMode.ECB: ivSize = 0; break;
                case SymmetricCipherMode.OFB: ivSize = _blockSize; break;
                case SymmetricCipherMode.CFB: ivSize = _blockSize; break;
                case SymmetricCipherMode.CTS: ivSize = _blockSize; break;
                case SymmetricCipherMode.CTR: ivSize = _blockSize; break;
                case SymmetricCipherMode.CTS_ECB: ivSize = 0; break;
                case SymmetricCipherMode.GOFB: ivSize = _blockSize; break;
                case SymmetricCipherMode.OpenPGPCFB: ivSize = _blockSize; break;
                case SymmetricCipherMode.SIC: ivSize = _blockSize; break;
                case SymmetricCipherMode.CCM: ivSize = 104; break;
                case SymmetricCipherMode.EAX: ivSize = _blockSize; break;
                case SymmetricCipherMode.GCM: ivSize = _blockSize; break;
                case SymmetricCipherMode.OCB: ivSize = 120; break;
                default: throw new CryptographicException("Unsupported cipher mode.");
            }
            GenerateParameters(keySize, ivSize);
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="ivSize">IV size bits.</param>
        public void GenerateParameters(int keySize, int ivSize)
        {
            byte[] key = new byte[keySize / 8];
            Common.SecureRandom.NextBytes(key);
            _parameters = GenerateKeyParameter(key);
            if (ivSize > 0)
            {
                byte[] iv = new byte[ivSize / 8];
                Common.SecureRandom.NextBytes(iv);
                _parameters = new ParametersWithIV(_parameters, iv);
            }
            _keySize = keySize;
            _ivSize = ivSize;
        }

        /// <summary>
        /// Imports key and iv.
        /// </summary>
        /// <param name="key">Import key bytes.</param>
        /// <param name="iv">Import iv bytes.</param>
        public void ImportParameters(byte[] key, byte[] iv)
        {
            _parameters = GenerateKeyParameter(key);
            if (iv == null || iv.Length == 0)
            {
                _ivSize = 0;
            }
            else
            {
                _parameters = new ParametersWithIV(_parameters, iv);
                _ivSize = iv.Length * 8;
            }
            _keySize = key.Length * 8;
        }

        protected abstract IStreamCipher GenerateEngine();

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected virtual KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new KeyParameter(key);
        }

        private IBufferedCipher GenerateCipher(bool forEncryption)
        {
            IStreamCipher engine = GenerateEngine();
            IBufferedCipher cipher = new BufferedStreamCipher(engine);
            cipher.Init(forEncryption, _parameters);
            return cipher;
        }


        private void InspectKey()
        {
            if (_keySize == 0)
            {
                GenerateParameters();
            }
        }


    }
}