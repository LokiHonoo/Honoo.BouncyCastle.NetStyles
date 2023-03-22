using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of asymmetric algorithms must inherit.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        protected bool _initialized = false;
        protected AsymmetricKeyParameter _privateKey = null;
        protected AsymmetricKeyParameter _publicKey = null;
        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <inheritdoc/>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <inheritdoc/>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the AsymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        protected AsymmetricAlgorithm(string name, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction

        #region Interfaces

        /// <summary>
        /// Gets encryption algorithm interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a encryption algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IAsymmetricEncryptionAlgorithm GetEncryptionInterface();

        /// <summary>
        /// Gets key exchange algorithm party A's interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a key exchange algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IKeyExchangeA GetKeyExchangeAInterface();

        /// <summary>
        /// Gets key exchange algorithm party B's interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a key exchange algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IKeyExchangeB GetKeyExchangeBInterface();

        /// <summary>
        /// Gets signature algorithm interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a signature algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IAsymmetricSignatureAlgorithm GetSignatureInterface();

        #endregion Interfaces

        #region Export/Import Parameters

        /// <inheritdoc/>
        public byte[] ExportKeyInfo(bool includePrivate)
        {
            InspectParameters();
            if (includePrivate)
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
                return privateKeyInfo.GetEncoded();
            }
            else
            {
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
                return publicKeyInfo.GetEncoded();
            }
        }

        /// <inheritdoc/>
        public byte[] ExportKeyInfo(PBEAlgorithmName pbeAlgorithmName, string password)
        {
            InspectParameters();
            byte[] salt = new byte[16];
            Common.SecureRandom.Value.NextBytes(salt);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                pbeAlgorithmName.Oid, password.ToCharArray(), salt, 2048, _privateKey);
            return enc.GetEncoded();
        }

        /// <inheritdoc/>
        public AsymmetricKeyParameter ExportParameters(bool privateKey)
        {
            InspectParameters();
            return privateKey ? _privateKey : _publicKey;
        }

        /// <inheritdoc/>
        public string ExportPem(bool includePrivate)
        {
            InspectParameters();
            AsymmetricKeyParameter asymmetricKey = includePrivate ? _privateKey : _publicKey;
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public string ExportPem(DEKAlgorithmName dekAlgorithmName, string password)
        {
            InspectParameters();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(_privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom.Value);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public abstract void ImportKeyInfo(byte[] keyInfo);

        /// <inheritdoc/>
        public abstract void ImportKeyInfo(byte[] privateKeyInfo, string password);

        /// <inheritdoc/>
        public abstract void ImportParameters(AsymmetricKeyParameter asymmetricKey);

        /// <inheritdoc/>
        public abstract void ImportParameters(AsymmetricCipherKeyPair keyPair);

        /// <inheritdoc/>
        public abstract void ImportPem(string keyPem);

        /// <inheritdoc/>
        public abstract void ImportPem(string privateKeyPem, string password);

        #endregion Export/Import Parameters

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(AsymmetricAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Signature algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(SignatureAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <inheritdoc/>
        public abstract void GenerateParameters();

        /// <summary>
        ///
        /// </summary>
        protected void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}