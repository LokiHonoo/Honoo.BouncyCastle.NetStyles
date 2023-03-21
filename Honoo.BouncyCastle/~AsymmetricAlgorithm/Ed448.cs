using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Ed448 : AsymmetricAlgorithm, IAsymmetricSignatureAlgorithm
    {
        #region Properties

        private const string NAME = "Ed448";
        private readonly byte[] _context;
        private bool _initialized = false;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private Ed448SignatureInstance _signatureInstance = Ed448SignatureInstance.Ed448;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Ed448 not need hash algorithm. Throw <see cref="NotImplementedException"/> always.
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        /// <inheritdoc/>
        public string SignatureAlgorithm => GetSignatureAlgorithmMechanism(_signatureInstance);

        /// <summary>
        /// Represents the signature EdDSA instance (RFC-8032) used in the symmetric algorithm.
        /// </summary>
        public Ed448SignatureInstance SignatureInstance
        {
            get => _signatureInstance;
            set
            {
                if (value != _signatureInstance)
                {
                    _signer = null;
                    _verifier = null;
                    _signatureInstance = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Ed448 class.
        /// </summary>
        /// <param name="context">Context using for signature Ed448/Ed448ph instance.</param>
        public Ed448(byte[] context = null) : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
            if (context == null || context.Length == 0)
            {
                _context = Arrays.EmptyBytes;
            }
            else
            {
                _context = (byte[])context.Clone();
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="context">Context using for signature Ed25519ctx/Ed25519ph instance.</param>
        /// <returns></returns>
        public static Ed448 Create(byte[] context = null)
        {
            return new Ed448(context);
        }

        #region GenerateParameters

        /// <inheritdoc/>
        public void GenerateParameters()
        {
            Ed448KeyGenerationParameters parameters = new Ed448KeyGenerationParameters(Common.SecureRandom);
            Ed448KeyPairGenerator generator = new Ed448KeyPairGenerator();
            generator.Init(parameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        #endregion GenerateParameters

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
            Common.SecureRandom.NextBytes(salt);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                pbeAlgorithmName.Oid, password.ToCharArray(), salt, 2048, _privateKey);
            return enc.GetEncoded();
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
                pemWriter.WriteObject(_privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public void ImportKeyInfo(byte[] keyInfo)
        {
            Ed448PrivateKeyParameters privateKey = null;
            Ed448PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                publicKey = privateKey.GeneratePublicKey();
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Ed448PublicKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
                }
                catch
                {
                }
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public void ImportKeyInfo(byte[] keyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
            Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public void ImportPem(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                Ed448PrivateKeyParameters privateKey = null;
                Ed448PublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(Ed448PrivateKeyParameters))
                {
                    privateKey = (Ed448PrivateKeyParameters)obj;
                    publicKey = privateKey.GeneratePublicKey();
                }
                else
                {
                    publicKey = (Ed448PublicKeyParameters)obj;
                }
                _privateKey = privateKey;
                _publicKey = publicKey;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        /// <inheritdoc/>
        public void ImportPem(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)obj;
                Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
                _privateKey = privateKey;
                _publicKey = publicKey;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        #endregion Export/Import Parameters

        /// <inheritdoc/>
        public override IAsymmetricEncryptionAlgorithm GetEncryptionInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IKeyExchangeA GetKeyExchangeAInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IKeyExchangeB GetKeyExchangeBInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IAsymmetricSignatureAlgorithm GetSignatureInterface()
        {
            return this;
        }

        /// <inheritdoc/>
        public void ResetSigner()
        {
            if (_signer != null)
            {
                _signer.Reset();
            }
            if (_verifier != null)
            {
                _verifier.Reset();
            }
        }

        /// <inheritdoc/>
        public byte[] SignFinal()
        {
            InspectParameters();
            InspectSigner(true);
            return _signer.GenerateSignature();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] rgb)
        {
            SignUpdate(rgb, 0, rgb.Length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] buffer, int offset, int length)
        {
            SignUpdate(buffer, offset, length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(true);
            _signer.BlockUpdate(buffer, offset, length);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] signature)
        {
            InspectParameters();
            InspectSigner(false);
            return _verifier.VerifySignature(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] rgb, byte[] signature)
        {
            VerifyUpdate(rgb, 0, rgb.Length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] buffer, int offset, int length, byte[] signature)
        {
            VerifyUpdate(buffer, offset, length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new Ed448(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(Ed448SignatureInstance instance)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(instance), () => { return new Ed448() { SignatureInstance = instance }; });
        }

        private static string GetSignatureAlgorithmMechanism(Ed448SignatureInstance instance)
        {
            switch (instance)
            {
                case Ed448SignatureInstance.Ed448: return "Ed448";
                case Ed448SignatureInstance.Ed448ph: return "Ed448ph";
                default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
            }
        }

        private void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    switch (_signatureInstance)
                    {
                        case Ed448SignatureInstance.Ed448: _signer = new Ed448Signer(_context); break;
                        case Ed448SignatureInstance.Ed448ph: _signer = new Ed448phSigner(_context); break;
                        default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
                    }
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    switch (_signatureInstance)
                    {
                        case Ed448SignatureInstance.Ed448: _verifier = new Ed448Signer(_context); break;
                        case Ed448SignatureInstance.Ed448ph: _verifier = new Ed448phSigner(_context); break;
                        default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}