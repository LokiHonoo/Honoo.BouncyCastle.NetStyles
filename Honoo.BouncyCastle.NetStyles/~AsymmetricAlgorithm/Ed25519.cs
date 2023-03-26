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
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Ed25519 : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const string NAME = "Ed25519";
        private readonly byte[] _context;
        private Ed25519SignatureInstance _signatureInstance = Ed25519SignatureInstance.Ed25519;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Ed25519 not need hash algorithm. It's null always.
        /// </summary>
        public HashAlgorithmName HashAlgorithmName
        { get => null; set { } }

        /// <inheritdoc/>
        public SignatureAlgorithmName SignatureAlgorithmName => GetSignatureAlgorithmName(_signatureInstance);

        /// <summary>
        /// Represents the signature EdDSA instance (RFC-8032) used in the symmetric algorithm.
        /// </summary>
        public Ed25519SignatureInstance SignatureInstance
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
        /// Initializes a new instance of the Ed25519 class.
        /// </summary>
        /// <param name="context">Context using for signature Ed25519ctx/Ed25519ph instance.</param>
        public Ed25519(byte[] context = null) : base(NAME, AsymmetricAlgorithmKind.Signature)
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
            Ed25519KeyGenerationParameters parameters = new Ed25519KeyGenerationParameters(Common.SecureRandom.Value);
            Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
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
            Ed25519PrivateKeyParameters privateKey = null;
            Ed25519PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                publicKey = privateKey.GeneratePublicKey();
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
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
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            Ed25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            Ed25519PrivateKeyParameters privateKey = null;
            Ed25519PublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (Ed25519PrivateKeyParameters)asymmetricKey;
                publicKey = privateKey.GeneratePublicKey();
            }
            else
            {
                publicKey = (Ed25519PublicKeyParameters)asymmetricKey;
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
            _privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
            _publicKey = (Ed25519PublicKeyParameters)keyPair.Public;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                Ed25519PrivateKeyParameters privateKey = null;
                Ed25519PublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(Ed25519PrivateKeyParameters))
                {
                    privateKey = (Ed25519PrivateKeyParameters)obj;
                    publicKey = privateKey.GeneratePublicKey();
                }
                else
                {
                    publicKey = (Ed25519PublicKeyParameters)obj;
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
                Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)obj;
                Ed25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
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
        public static Ed25519 Create(byte[] context = null)
        {
            return new Ed25519(context);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new Ed25519(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(Ed25519SignatureInstance instance)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(instance), () => { return new Ed25519() { _signatureInstance = instance }; });
        }

        private static string GetSignatureAlgorithmMechanism(Ed25519SignatureInstance instance)
        {
            switch (instance)
            {
                case Ed25519SignatureInstance.Ed25519: return "Ed25519";
                case Ed25519SignatureInstance.Ed25519ctx: return "Ed25519ctx";
                case Ed25519SignatureInstance.Ed25519ph: return "Ed25519ph";
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
                        case Ed25519SignatureInstance.Ed25519: _signer = new Ed25519Signer(); break;
                        case Ed25519SignatureInstance.Ed25519ctx: _signer = new Ed25519ctxSigner(_context); break;
                        case Ed25519SignatureInstance.Ed25519ph: _signer = new Ed25519phSigner(_context); break;
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
                        case Ed25519SignatureInstance.Ed25519: _verifier = new Ed25519Signer(); break;
                        case Ed25519SignatureInstance.Ed25519ctx: _verifier = new Ed25519ctxSigner(_context); break;
                        case Ed25519SignatureInstance.Ed25519ph: _verifier = new Ed25519phSigner(_context); break;
                        default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}