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
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Ed448 : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const string NAME = "Ed448";
        private readonly byte[] _context;
        private Ed448SignatureInstance _signatureInstance = Ed448SignatureInstance.Ed448;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Ed448 not need hash algorithm. It's null always.
        /// </summary>
        public HashAlgorithmName HashAlgorithmName { get => null; set { } }

        /// <inheritdoc/>
        public SignatureAlgorithmName SignatureAlgorithmName
        {
            get
            {
                string mechanism = GetSignatureAlgorithmMechanism(_signatureInstance);
                SignatureAlgorithmName.TryGetAlgorithmName(mechanism, out SignatureAlgorithmName algorithmName);
                return algorithmName;
            }
        }

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

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            Ed448KeyGenerationParameters parameters = new Ed448KeyGenerationParameters(Common.SecureRandom.Value);
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
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            Ed448PrivateKeyParameters privateKey = null;
            Ed448PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                publicKey = privateKey.GeneratePublicKey();
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Ed448PublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
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
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(privateKeyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo priInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            Ed448PrivateKeyParameters privateKey = null;
            Ed448PublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (Ed448PrivateKeyParameters)asymmetricKey;
                publicKey = privateKey.GeneratePublicKey();
            }
            else
            {
                publicKey = (Ed448PublicKeyParameters)asymmetricKey;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            _privateKey = (Ed448PrivateKeyParameters)keyPair.Private;
            _publicKey = (Ed448PublicKeyParameters)keyPair.Public;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
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
        public override void ImportPem(string privateKeyPem, string password)
        {
            using (StringReader reader = new StringReader(privateKeyPem))
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

        #region Signature

        /// <inheritdoc/>
        public void Reset()
        {
            _signer?.Reset();
            _verifier?.Reset();
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
        public void SignUpdate(byte[] rgb)
        {
            SignUpdate(rgb, 0, rgb.Length);
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
        public void VerifyUpdate(byte[] rgb)
        {
            VerifyUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
        }

        #endregion Signature

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="context">Context using for signature Ed25519ctx/Ed25519ph instance.</param>
        /// <returns></returns>
        public static Ed448 Create(byte[] context = null)
        {
            return new Ed448(context);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new Ed448(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(Ed448SignatureInstance instance)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(instance), () => { return new Ed448() { _signatureInstance = instance }; });
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