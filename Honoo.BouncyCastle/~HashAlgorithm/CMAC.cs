using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Computes a CMAC using the specified symmetric algorithm.
    /// </summary>
    public sealed class CMAC
    {
        #region Properties

        private readonly SymmetricBlockAlgorithm _core;
        private readonly int _hashSize;
        private readonly int _macSize;
        private readonly string _name;
        private IMac _digest;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _core.KeySize;

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        public int MacSize => _macSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the CMAC class.
        /// </summary>
        /// <param name="algorithmName">Symmetric block algorithm name. Legal algorithms of block size 64 or 128 bits.</param>
        public CMAC(SymmetricAlgorithmName algorithmName) : this(algorithmName, algorithmName.BlockSize)
        {
        }

        /// <summary>
        /// Initializes a new instance of the CMAC class.
        /// </summary>
        /// <param name="algorithmName">Symmetric block algorithm name. Legal algorithms of block size 64 or 128 bits.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        public CMAC(SymmetricAlgorithmName algorithmName, int macSize)
        {
            if (algorithmName.BlockSize != 64 && algorithmName.BlockSize != 128)
            {
                throw new CryptographicException("Legal algorithms of block size 64 or 128 bits.");
            }
            if (macSize < 8 || macSize > algorithmName.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException($"Legal mac size is between 8 and {algorithmName.BlockSize} bits (8 bits increments).");
            }
            _name = $"{algorithmName.Name}/CMAC";
            _core = (SymmetricBlockAlgorithm)SymmetricAlgorithm.Create(algorithmName);
            _core.Mode = SymmetricCipherMode.ECB;
            _core.Padding = SymmetricPaddingMode.NoPadding;
            _macSize = macSize;
            _hashSize = macSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Symmetric algorithm name. Legal algorithms of block size 64 or 128 bits.</param>
        /// <returns></returns>
        public static CMAC Create(SymmetricAlgorithmName algorithmName)
        {
            return new CMAC(algorithmName);
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Symmetric algorithm name. Legal algorithms of block size 64 or 128 bits.</param>
        /// <param name="macSize">Legal mac size is between 8 and symmetric algorithm block size bits (8 bits increments).</param>
        /// <returns></returns>
        public static CMAC Create(SymmetricAlgorithmName algorithmName, int macSize)
        {
            return new CMAC(algorithmName, macSize);
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
        /// Exports key.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key)
        {
            key = ((KeyParameter)_core.ExportParameters()).GetKey();
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size.
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
        public void GenerateParameters(int keySize)
        {
            _core.GenerateParameters(keySize, 0);
            _digest = null;
        }

        /// <summary>
        /// Imports key.
        /// </summary>
        /// <param name="key">Legal key size is determined by the symmetric algorithm.</param>
        public void ImportParameters(byte[] key)
        {
            _core.ImportParameters(key, null);
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
        /// <param name="keySize">Key size bits.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize, out string exception)
        {
            return _core.ValidKeySize(keySize, out exception);
        }

        private IMac GetDigest()
        {
            IMac digest = new CMac(_core.GetEngine(), _macSize);
            digest.Init(_core.ExportParameters());
            return digest;
        }
    }
}