using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Computes a MAC using the specified symmetric algorithm.
    /// </summary>
    public sealed class MAC : HashAlgorithm
    {
        #region Properties

        private readonly SymmetricBlockAlgorithm _core;
        private readonly int _macSize;
        private IMac _digest;

        /// <summary>
        /// Gets iv size bits.
        /// </summary>
        public int IVSize => _core.IVSize;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _core.KeySize;

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        public int MacSize => _macSize;

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm. The parameters recreated if change this operation.
        /// <para/>MAC only supported CBC and CFB cipher mode.
        /// </summary>
        public SymmetricCipherMode Mode
        {
            get => _core.Mode;
            set
            {
                if (value != _core.Mode)
                {
                    _digest = null;
                }
                _core.Mode = value;
            }
        }

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm.
        /// <para/>MAC only supported NoPadding, PKCS7, Zeros, X923, ISO7816-4 and TBC padding mode.
        /// </summary>
        public SymmetricPaddingMode Padding
        {
            get => _core.Padding;
            set
            {
                if (value != _core.Padding)
                {
                    _digest = null;
                }
                _core.Padding = value;
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the MAC class.
        /// </summary>
        /// <param name="algorithmName">MAC name.</param>
        public MAC(MACName algorithmName) : this(algorithmName, algorithmName.BlockSize)
        {
        }

        /// <summary>
        /// Initializes a new instance of the MAC class.
        /// </summary>
        /// <param name="algorithmName">MAC name.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        public MAC(MACName algorithmName, int macSize) : base(algorithmName.Name, macSize)
        {
            if (macSize < 8 || macSize > algorithmName.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException($"Legal mac size is between 8 and {algorithmName.BlockSize} bits (8 bits increments).");
            }
            _core = (SymmetricBlockAlgorithm)SymmetricAlgorithm.Create(algorithmName.SymmetricAlgorithm);
            _macSize = macSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">MAC name.</param>
        /// <returns></returns>
        public static MAC Create(MACName algorithmName)
        {
            return new MAC(algorithmName);
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">MAC name.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        /// <returns></returns>
        public static MAC Create(MACName algorithmName, int macSize)
        {
            return new MAC(algorithmName, macSize);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Exports a <see cref="ICipherParameters"/> containing the MAC parameters information associated.
        /// </summary>
        /// <returns></returns>
        public ICipherParameters ExportParameters()
        {
            return _core.ExportParameters();
        }

        /// <summary>
        /// Exports key and iv.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <param name="iv">Output iv bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key, out byte[] iv)
        {
            var parameters = ((ParametersWithIV)_core.ExportParameters());
            key = ((KeyParameter)parameters.Parameters).GetKey();
            iv = parameters.GetIV();
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        public void GenerateParameters()
        {
            _core.GenerateParameters();
            _digest = null;
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is determined by the symmetric algorithm.</param>
        /// <param name="ivSize">Legal iv size is determined by the symmetric algorithm and cipher mode.</param>
        public void GenerateParameters(int keySize, int ivSize)
        {
            _core.GenerateParameters(keySize, ivSize);
            _digest = null;
        }

        /// <summary>
        /// Imports a <see cref="ICipherParameters"/> that represents MAC parameters information.
        /// </summary>
        /// <param name="parameters">A BouncyCastle <see cref="ICipherParameters"/> that represents an MAC parameters.</param>
        public void ImportParameters(ICipherParameters parameters)
        {
            _core.ImportParameters(parameters);
            _digest = null;
        }

        /// <summary>
        /// Imports key.
        /// </summary>
        /// <param name="key">Legal key size is determined by the symmetric algorithm.</param>
        /// <param name="iv">Legal iv size is determined by the symmetric algorithm and cipher mode.</param>
        public void ImportParameters(byte[] key, byte[] iv)
        {
            _core.ImportParameters(key, iv);
            _digest = null;
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
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(buffer, offset, length);
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public bool ValidIVSize(int ivSize, out string exception)
        {
            return _core.ValidIVSize(ivSize, out exception);
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize, out string exception)
        {
            return _core.ValidKeySize(keySize, out exception);
        }

        private IMac GetDigest()
        {
            IBlockCipherPadding pad;
            switch (_core.Padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = null; break;
                case SymmetricPaddingMode.PKCS7: pad = SymmetricPadding.PKCS7_PADDING; break;
                case SymmetricPaddingMode.Zeros: pad = SymmetricPadding.ZEROBYTE_PADDING; break;
                case SymmetricPaddingMode.X923: pad = SymmetricPadding.X923_PADDING; break;
                case SymmetricPaddingMode.ISO7816_4: pad = SymmetricPadding.ISO7816_4_PADDING; break;
                case SymmetricPaddingMode.TBC: pad = SymmetricPadding.TBC_PADDING; break;
                default: throw new CryptographicException("MAC only supported NoPadding, PKCS7, Zeros, X923, ISO7816-4 and TBC padding mode.");
            }
            IMac digest;
            switch (_core.Mode)
            {
                case SymmetricCipherMode.CBC:
                    digest = pad == null ? new CbcBlockCipherMac(_core.GetEngine(), _macSize)
                        : new CbcBlockCipherMac(_core.GetEngine(), _macSize, pad);
                    break;

                case SymmetricCipherMode.CFB:
                    int cfbs = _core.IVSize;
                    digest = pad == null ? new CfbBlockCipherMac(_core.GetEngine(), cfbs, _macSize)
                        : new CfbBlockCipherMac(_core.GetEngine(), cfbs, _macSize, pad);
                    break;

                default: throw new CryptographicException("MAC only supported CBC and CFB cipher mode.");
            }
            digest.Init(_core.ExportParameters());
            return digest;
        }
    }
}