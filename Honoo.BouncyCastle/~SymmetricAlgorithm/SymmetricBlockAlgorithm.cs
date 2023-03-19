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
    /// Represents the abstract base class from which all implementations of symmetric block algorithms must inherit.
    /// </summary>
    public abstract class SymmetricBlockAlgorithm : SymmetricAlgorithm
    {
        #region Properties

        private readonly int _defaultKeySize;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public override KeySizes[] LegalIVSizes => GetIVSizes();

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override SymmetricCipherMode Mode
        {
            get => _mode;
            set
            {
                if (value != _mode)
                {
                    _parameters = null;
                    _encryptor = null;
                    _decryptor = null;
                    _initialized = false;
                }
                _mode = value;
            }
        }

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm.
        /// </summary>
        public override SymmetricPaddingMode Padding
        {
            get => _padding;
            set
            {
                if (value != _padding)
                {
                    _encryptor = null;
                    _decryptor = null;
                }
                _padding = value;
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SymmetricBlockAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="blockSize"></param>
        /// <param name="defaultKeySize"></param>
        protected SymmetricBlockAlgorithm(string name, int blockSize, int defaultKeySize)
            : base(name, SymmetricAlgorithmKind.Block, blockSize, defaultKeySize, blockSize)
        {
            _defaultKeySize = defaultKeySize;
        }

        #endregion Construction

        public override void GenerateParameters()
        {
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
            GenerateParameters(_defaultKeySize, ivSize);
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
            _parameters = new AeadParameters(GetKeyParameter(key), macSize, (byte[])nonce.Clone(), (byte[])associatedText.Clone());
            _encryptor = null;
            _decryptor = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override bool ValidIVSize(int ivSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(GetIVSizes(), ivSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                switch (_mode)
                {
                    case SymmetricCipherMode.CBC: exception = $"Legal IV size {_blockSize} bits."; break;
                    case SymmetricCipherMode.ECB: exception = $"Not need IV."; break;
                    case SymmetricCipherMode.OFB: exception = $"Legal IV size between 8 and {_blockSize} bits (8 bits increments)."; break;
                    case SymmetricCipherMode.CFB: exception = $"Legal IV size between 8 and {_blockSize} bits (8 bits increments)."; break;
                    case SymmetricCipherMode.CTS: exception = $"Legal IV size {_blockSize} bits."; break;
                    case SymmetricCipherMode.CTR: exception = $"Legal IV size between {Math.Max(_blockSize / 2, _blockSize - 64)} and {_blockSize} bits (8 bits increments)."; break;
                    case SymmetricCipherMode.CTS_ECB: exception = $"Not need IV."; break;
                    case SymmetricCipherMode.GOFB: exception = $"Legal IV size {_blockSize} bits."; break;
                    case SymmetricCipherMode.OpenPGPCFB: exception = $"Legal IV size between 8 and {_blockSize} bits (8 bits increments)."; break;
                    case SymmetricCipherMode.SIC: exception = $"Legal IV size between {Math.Max(_blockSize / 2, _blockSize - 64)} and {_blockSize} bits (8 bits increments)."; break;
                    case SymmetricCipherMode.CCM: exception = $"Legal IV size between 56 and 104 bits (8 bits increments)."; break;
                    case SymmetricCipherMode.EAX: exception = $"Legal IV size is more than or equal to 8 bits (8 bits increments)."; break;
                    case SymmetricCipherMode.GCM: exception = $"Legal IV size is more than or equal to 8 bits (8 bits increments)."; break;
                    case SymmetricCipherMode.OCB: exception = $"Legal IV size between 8 and 120 bits (8 bits increments)."; break;
                    default: throw new CryptographicException("Unsupported cipher mode.");
                }
                return false;
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        internal abstract IBlockCipher GetEngine();

        /// <summary>
        /// BUG: GCM cipher mode cannot be auto reused. The cipher instance needs to be recreated every time (BouncyCastle 1.9.0).
        /// BUG: GOFB cipher mode N3, N4 value omitted at reset. The cipher instance needs to be recreated every time (BouncyCastle 1.9.0).
        /// </summary>
        protected override void FixDecrypted()
        {
            if (_mode == SymmetricCipherMode.GCM)
            {
                _decryptor = null;
            }
            if (_mode == SymmetricCipherMode.GOFB)
            {
                _decryptor = null;
            }
        }

        /// <summary>
        /// BUG: GCM cipher mode cannot be auto reused. The cipher instance needs to be recreated every time (BouncyCastle 1.9.0).
        /// BUG: GOFB cipher mode N3, N4 value omitted at reset. The cipher instance needs to be recreated every time (BouncyCastle 1.9.0).
        /// </summary>
        protected override void FixEncrypted()
        {
            if (_mode == SymmetricCipherMode.GCM)
            {
                _encryptor = null;
            }
            if (_mode == SymmetricCipherMode.GOFB)
            {
                _encryptor = null;
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        protected override IBufferedCipher GetCipher(bool forEncryption)
        {
            IBlockCipherPadding pad;
            switch (_padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = null; break;
                case SymmetricPaddingMode.PKCS7: pad = SymmetricPadding.PKCS7_PADDING; break;
                case SymmetricPaddingMode.Zeros: pad = SymmetricPadding.ZEROBYTE_PADDING; break;
                case SymmetricPaddingMode.X923: pad = SymmetricPadding.X923_PADDING; break;
                case SymmetricPaddingMode.ISO10126: pad = SymmetricPadding.ISO10126_2_PADDING; break;
                case SymmetricPaddingMode.ISO7816_4: pad = SymmetricPadding.ISO7816_4_PADDING; break;
                case SymmetricPaddingMode.TBC: pad = SymmetricPadding.TBC_PADDING; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IBlockCipher engine = GetEngine();
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
                            cipher = new BufferedAeadBlockCipher(new OcbBlockCipher(engine, GetEngine()));
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
                    return new KeySizes[] { new KeySizes(Math.Max(_blockSize / 2, _blockSize - 64), _blockSize, 8) };

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
                        return new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (!pad && _blockSize == 128)
                    {
                        return new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (!pad && _blockSize == 128)
                    {
                        /*
                         * BUG: OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that (BouncyCastle 1.9.0).
                         * So use limit min value 8.
                         */

                        return new KeySizes[] { new KeySizes(8, 120, 8) };
                    }
                    break;

                default: break;
            }
            return new KeySizes[] { new KeySizes(0, 0, 0) };
        }
    }
}