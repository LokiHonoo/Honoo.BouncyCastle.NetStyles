using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric algorithms must inherit.
    /// </summary>
    public abstract class SymmetricBlockAlgorithm : SymmetricAlgorithm
    {
        #region Properties

        protected readonly int _blockSize;
        private static readonly IBlockCipherPadding _iso10126d2Padding;
        private static readonly IBlockCipherPadding _iso7816d4Padding = new ISO7816d4Padding();
        private static readonly IBlockCipherPadding _pkcs7Padding = new Pkcs7Padding();
        private static readonly IBlockCipherPadding _tbcPadding = new TbcPadding();
        private static readonly IBlockCipherPadding _x923Padding = new X923Padding();
        private static readonly IBlockCipherPadding _zeroBytePadding = new ZeroBytePadding();
        private IBufferedCipher _decryptor = null;
        private IBufferedCipher _encryptor = null;
        private int _ivSize = 0;
        private int _keySize = 0;
        private SymmetricCipherMode _mode = SymmetricCipherMode.CBC;
        private SymmetricPaddingMode _padding = SymmetricPaddingMode.PKCS7;
        private ICipherParameters _parameters = null;

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => _blockSize;

        /// <summary>
        /// Gets iv size bits.
        /// </summary>
        public override int IVSize
        {
            get
            {
                if (_keySize == 0)
                {
                    switch (_mode)
                    {
                        case SymmetricCipherMode.CBC: return _blockSize;
                        case SymmetricCipherMode.ECB: return 0;
                        case SymmetricCipherMode.OFB: return _blockSize;
                        case SymmetricCipherMode.CFB: return _blockSize;
                        case SymmetricCipherMode.CTS: return _blockSize;
                        case SymmetricCipherMode.CTR: return _blockSize;
                        case SymmetricCipherMode.CTS_ECB: return 0;
                        case SymmetricCipherMode.GOFB: return _blockSize;
                        case SymmetricCipherMode.OpenPGPCFB: return _blockSize;
                        case SymmetricCipherMode.SIC: return _blockSize;
                        case SymmetricCipherMode.CCM: return 104;
                        case SymmetricCipherMode.EAX: return _blockSize;
                        case SymmetricCipherMode.GCM: return _blockSize;
                        case SymmetricCipherMode.OCB: return 120;
                        default: throw new CryptographicException("Unsupported cipher mode.");
                    }
                }
                return _ivSize;
            }
        }

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public override int KeySize => _keySize == 0 ? _blockSize : _keySize;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public override KeySizes[] LegalIVSizes => GetIVSizes();

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public SymmetricCipherMode Mode
        {
            get => _mode;
            set
            {
                if (value != _mode)
                {
                    _encryptor = null;
                    _decryptor = null;
                    _mode = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm.
        /// </summary>
        public SymmetricPaddingMode Padding
        {
            get => _padding;
            set
            {
                if (value != _padding)
                {
                    _encryptor = null;
                    _decryptor = null;
                    _padding = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        static SymmetricBlockAlgorithm()
        {
            _iso10126d2Padding = new ISO10126d2Padding();
            _iso10126d2Padding.Init(Common.SecureRandom);
        }

        protected SymmetricBlockAlgorithm(string name, SymmetricAlgorithmKind kind, int blockSize) : base(name, kind)
        {
            _blockSize = blockSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public new static SymmetricBlockAlgorithm Create(SymmetricAlgorithmName algorithmName)
        {
            return (SymmetricBlockAlgorithm)algorithmName.GenerateAlgorithm();
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
            byte[] result = _decryptor.DoFinal();
            RestoreGCM(false);
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
                _decryptor = GenerateCipher(false);
            }
            byte[] result = _decryptor.DoFinal(buffer, offset, length);
            RestoreGCM(false);
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
            byte[] result = _encryptor.DoFinal();
            RestoreGCM(true);
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
                _encryptor = GenerateCipher(true);
            }
            byte[] result = _encryptor.DoFinal(buffer, offset, length);
            RestoreGCM(true);
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
                _encryptor = GenerateCipher(true);
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

        /// <summary>
        /// Imports key, iv, macSize and associated text.
        /// </summary>
        /// <param name="key">Import key bytes.</param>
        /// <param name="nonce">Import nonce bytes.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="associatedText">Import associated text bytes.</param>
        public void ImportParameters(byte[] key, byte[] nonce, int macSize, byte[] associatedText)
        {
            _keySize = key.Length * 8;
            _ivSize = nonce.Length * 8;
            // BouncyCastle has not clone nonce and associatedText.
            _parameters = new AeadParameters(GenerateKeyParameter(key), macSize, (byte[])nonce.Clone(), (byte[])associatedText.Clone());
        }

        /// <summary>
        /// Determines whether the specified iv size is valid for the current algorithm.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        public override bool ValidIVSize(int ivSize)
        {
            return DetectionUtilities.ValidSize(GetIVSizes(), ivSize);
        }

        protected abstract IBlockCipher GenerateEngine();

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
            IBlockCipherPadding pad;
            switch (_padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = null; break;
                case SymmetricPaddingMode.PKCS7: pad = _pkcs7Padding; break;
                case SymmetricPaddingMode.Zeros: pad = _zeroBytePadding; break;
                case SymmetricPaddingMode.X923: pad = _x923Padding; break;
                case SymmetricPaddingMode.ISO10126: pad = _iso10126d2Padding; break;
                case SymmetricPaddingMode.ISO7816_4: pad = _iso7816d4Padding; break;
                case SymmetricPaddingMode.TBC: pad = _tbcPadding; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IBlockCipher engine = GenerateEngine();
            IBufferedCipher cipher;
            switch (_mode)
            {
                case SymmetricCipherMode.CBC:
                    cipher = pad == null ? new BufferedBlockCipher(new CbcBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.ECB:
                    cipher = pad == null ? new BufferedBlockCipher(engine) : new PaddedBufferedBlockCipher(engine, pad);
                    break;

                case SymmetricCipherMode.OFB:
                    int ofbs = ((ParametersWithIV)_parameters).GetIV().Length * 8;
                    cipher = pad == null ? new BufferedBlockCipher(new OfbBlockCipher(engine, ofbs))
                        : new PaddedBufferedBlockCipher(new OfbBlockCipher(engine, ofbs), pad);
                    break;

                case SymmetricCipherMode.CFB:
                    int cfbs = ((ParametersWithIV)_parameters).GetIV().Length * 8;
                    cipher = pad == null ? new BufferedBlockCipher(new CfbBlockCipher(engine, cfbs))
                        : new PaddedBufferedBlockCipher(new CfbBlockCipher(engine, cfbs), pad);
                    break;

                case SymmetricCipherMode.CTS:
                    if (pad == null)
                    {
                        cipher = new CtsBlockCipher(new CbcBlockCipher(engine));
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.CTR:
                    cipher = pad == null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.CTS_ECB:
                    if (pad == null)
                    {
                        cipher = new CtsBlockCipher(engine);
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.GOFB:
                    if (_blockSize == 64)
                    {
                        cipher = pad == null ? new BufferedBlockCipher(new GOfbBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new GOfbBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).");

                case SymmetricCipherMode.OpenPGPCFB:
                    cipher = pad == null ? new BufferedBlockCipher(new OpenPgpCfbBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new OpenPgpCfbBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.SIC:
                    if (_blockSize >= 128)
                    {
                        cipher = pad == null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("SIC cipher mode uses with a block size of at least 128 bits algorithm (e.g. AES).");

                case SymmetricCipherMode.CCM:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new CcmBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("CCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("CCM cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.EAX:
                    if (pad == null)
                    {
                        if (_blockSize == 64 || _blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new EaxBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("EAX cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).");
                    }
                    throw new CryptographicException("EAX cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.GCM:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new GcmBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("GCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("GCM cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.OCB:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new OcbBlockCipher(engine, GenerateEngine()));
                            break;
                        }
                        throw new CryptographicException("OCB cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("OCB cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                default: throw new CryptographicException("Unsupported cipher mode.");
            }
            cipher.Init(forEncryption, _parameters);
            return cipher;
        }

        private KeySizes[] GetIVSizes()
        {
            bool pad;
            switch (_padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = false; break;
                case SymmetricPaddingMode.PKCS7:
                case SymmetricPaddingMode.Zeros:
                case SymmetricPaddingMode.X923:
                case SymmetricPaddingMode.ISO10126:
                case SymmetricPaddingMode.ISO7816_4:
                case SymmetricPaddingMode.TBC: pad = true; break;
                default: return new KeySizes[] { new KeySizes(0, 0, 0) };
            }
            switch (_mode)
            {
                case SymmetricCipherMode.CBC: return new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) };
                case SymmetricCipherMode.ECB: return new KeySizes[] { new KeySizes(0, 0, 0) };
                case SymmetricCipherMode.OFB: return new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                case SymmetricCipherMode.CFB: return new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                case SymmetricCipherMode.CTS:
                    if (!pad)
                    {
                        return new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) };
                    }
                    break;

                case SymmetricCipherMode.CTR:
                    {
                        int min = Math.Max(_blockSize / 2, _blockSize - 64);
                        return new KeySizes[] { new KeySizes(min, _blockSize, 8) };
                    }
                case SymmetricCipherMode.CTS_ECB:
                    if (!pad)
                    {
                        return new KeySizes[] { new KeySizes(0, 0, 0) };
                    }
                    break;

                case SymmetricCipherMode.GOFB:
                    if (_blockSize == 64)
                    {
                        return new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) };
                    }
                    break;

                case SymmetricCipherMode.OpenPGPCFB: return new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                case SymmetricCipherMode.SIC:
                    if (_blockSize >= 128)
                    {
                        int min = Math.Max(_blockSize / 2, _blockSize - 64);
                        return new KeySizes[] { new KeySizes(min, _blockSize, 8) };
                    }
                    break;

                case SymmetricCipherMode.CCM:
                    if (!pad && _blockSize == 128)
                    {
                        return new KeySizes[] { new KeySizes(56, 104, 8) };
                    }
                    break;

                case SymmetricCipherMode.EAX:
                    if (!pad && (_blockSize == 64 || _blockSize == 128))
                    {
                        return new KeySizes[] { new KeySizes(8, Global.SizeMax, 8) };
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (!pad && _blockSize == 128)
                    {
                        return new KeySizes[] { new KeySizes(8, Global.SizeMax, 8) };
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (!pad && _blockSize == 128)
                    {
                        /*
                         * BUG: OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that. (BouncyCastle 1.9.0 has not been fixed).
                         * So use limit min value 8.
                         */

                        return new KeySizes[] { new KeySizes(8, 120, 8) };
                    }
                    break;

                default: break;
            }
            return new KeySizes[] { new KeySizes(0, 0, 0) };
        }

        private void InspectKey()
        {
            if (_keySize == 0)
            {
                GenerateParameters();
            }
        }

        private void RestoreGCM(bool forEncryption)
        {
            if (_mode == SymmetricCipherMode.GCM)
            {
                if (forEncryption)
                {
                    _encryptor = GenerateCipher(true);
                }
                else
                {
                    _decryptor = GenerateCipher(false);
                }
            }
        }
    }
}