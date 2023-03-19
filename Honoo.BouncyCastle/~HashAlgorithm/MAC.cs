using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Computes a MAC using the specified symmetric algorithm.
    /// </summary>
    public sealed class MAC
    {
        #region Properties

        private readonly int _hashSize;
        private readonly int _macSize;
        private readonly string _name;
        private readonly SymmetricBlockAlgorithm _symmetricAlgorithm;
        private IMac _digest;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets iv size bits.
        /// </summary>
        public int IVSize => _symmetricAlgorithm.IVSize;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _symmetricAlgorithm.KeySize;

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        public int MacSize => _macSize;

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// <para/>MAC only supported CBC and CFB cipher mode.
        /// </summary>
        public SymmetricCipherMode Mode
        {
            get => _symmetricAlgorithm.Mode;
            set
            {
                if (value != _symmetricAlgorithm.Mode)
                {
                    _digest = null;
                }
                _symmetricAlgorithm.Mode = value;
            }
        }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm.
        /// <para/>MAC only supported NoPadding, PKCS7, Zeros, X923, ISO7816-4 and TBC padding mode.
        /// </summary>
        public SymmetricPaddingMode Padding
        {
            get => _symmetricAlgorithm.Padding;
            set
            {
                if (value != _symmetricAlgorithm.Padding)
                {
                    _digest = null;
                }
                _symmetricAlgorithm.Padding = value;
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the MAC class.
        /// </summary>
        /// <param name="algorithmName">Symmetric block algorithm name.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        public MAC(SymmetricAlgorithmName algorithmName, int macSize)
        {
            if (algorithmName.Kind == SymmetricAlgorithmKind.Stream)
            {
                throw new CryptographicException("Legal algorithms is symmetric block algorithm.");
            }
            if (macSize < 8 || macSize > algorithmName.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException($"Legal mac size is between 8 and {algorithmName.BlockSize} bits (8 bits increments).");
            }
            _name = $"{algorithmName.Name}/MAC";
            _symmetricAlgorithm = (SymmetricBlockAlgorithm)SymmetricAlgorithm.Create(algorithmName);
            _symmetricAlgorithm.Mode = SymmetricCipherMode.CBC;
            _symmetricAlgorithm.Padding = SymmetricPaddingMode.PKCS7;
            _macSize = macSize;
            _hashSize = macSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Symmetric block algorithm name.</param>
        /// <returns></returns>
        public static MAC Create(SymmetricAlgorithmName algorithmName)
        {
            return new MAC(algorithmName, algorithmName.BlockSize);
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Symmetric block algorithm name.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        /// <returns></returns>
        public static MAC Create(SymmetricAlgorithmName algorithmName, int macSize)
        {
            return new MAC(algorithmName, macSize);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeHash()
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
        /// Exports key and iv.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <param name="iv">Output iv bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key, out byte[] iv)
        {
            var parameters = ((ParametersWithIV)_symmetricAlgorithm.ExportParameters());
            key = ((KeyParameter)parameters.Parameters).GetKey();
            iv = parameters.GetIV();
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        public void GenerateParameters()
        {
            _symmetricAlgorithm.GenerateParameters();
            _digest = null;
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is determined by the symmetric algorithm.</param>
        /// <param name="ivSize">Legal iv size is determined by the symmetric algorithm and cipher mode.</param>
        public void GenerateParameters(int keySize, int ivSize)
        {
            _symmetricAlgorithm.GenerateParameters(keySize, ivSize);
            _digest = null;
        }

        /// <summary>
        /// Imports key.
        /// </summary>
        /// <param name="key">Legal key size is determined by the symmetric algorithm.</param>
        /// <param name="iv">Legal iv size is determined by the symmetric algorithm and cipher mode.</param>
        public void ImportParameters(byte[] key, byte[] iv)
        {
            _symmetricAlgorithm.ImportParameters(key, iv);
            _digest = null;
        }

        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public void Reset()
        {
            _digest.Reset();
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
            return _symmetricAlgorithm.ValidIVSize(ivSize, out exception);
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize, out string exception)
        {
            return _symmetricAlgorithm.ValidKeySize(keySize, out exception);
        }

        private IMac GetDigest()
        {
            IBlockCipherPadding pad;
            switch (_symmetricAlgorithm.Padding)
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
            switch (_symmetricAlgorithm.Mode)
            {
                case SymmetricCipherMode.CBC:
                    digest = pad == null ? new CbcBlockCipherMac(_symmetricAlgorithm.GetEngine(), _macSize)
                        : new CbcBlockCipherMac(_symmetricAlgorithm.GetEngine(), _macSize, pad);
                    break;

                case SymmetricCipherMode.CFB:
                    int cfbs = _symmetricAlgorithm.IVSize;
                    digest = pad == null ? new CfbBlockCipherMac(_symmetricAlgorithm.GetEngine(), cfbs, _macSize)
                        : new CfbBlockCipherMac(_symmetricAlgorithm.GetEngine(), cfbs, _macSize, pad);
                    break;

                default: throw new CryptographicException("MAC only supported CBC and CFB cipher mode.");
            }
            digest.Init(_symmetricAlgorithm.ExportParameters());
            return digest;
        }
    }
}