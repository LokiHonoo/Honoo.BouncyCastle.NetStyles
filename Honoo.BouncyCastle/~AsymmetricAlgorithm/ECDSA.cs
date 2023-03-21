using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECDSA : AsymmetricAlgorithm, IAsymmetricSignatureAlgorithm
    {
        #region Properties

        private const EllipticCurve DEFAULT_CURVE = EllipticCurve.Prime256v1;
        private const string NAME = "ECDSA";
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private bool _initialized = false;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private ECDSASignatureExtension _signatureExtension = ECDSASignatureExtension.ECDSA;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <inheritdoc/>
        public HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            set
            {
                if (value != _hashAlgorithm)
                {
                    _signer = null;
                    _verifier = null;
                    _hashAlgorithm = value ?? throw new CryptographicException("This hash algorithm can't be null.");
                }
            }
        }

        /// <inheritdoc/>
        public string SignatureAlgorithm => GetSignatureAlgorithmMechanism(_hashAlgorithm, _signatureExtension);

        /// <summary>
        /// Represents the signature extension used in the symmetric algorithm.
        /// </summary>
        public ECDSASignatureExtension SignatureExtension
        {
            get => _signatureExtension;
            set
            {
                if (value != _signatureExtension)
                {
                    _signer = null;
                    _verifier = null;
                    _signatureExtension = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECDSA class.
        /// </summary>
        public ECDSA() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ECDSA Create()
        {
            return new ECDSA();
        }

        #region GenerateParameters

        /// <inheritdoc/>
        public void GenerateParameters()
        {
            GenerateParameters(DEFAULT_CURVE);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve to be uesd.</param>
        public void GenerateParameters(EllipticCurve ellipticCurve = DEFAULT_CURVE)
        {
            X9ECParameters x9Parameters = GetX9ECParameters(ellipticCurve);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
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
            ECPrivateKeyParameters privateKey = null;
            ECPublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
                publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
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
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
            var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
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
                ECPrivateKeyParameters privateKey = null;
                ECPublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                    privateKey = (ECPrivateKeyParameters)keyPair.Private;
                    publicKey = (ECPublicKeyParameters)keyPair.Public;
                }
                else
                {
                    publicKey = (ECPublicKeyParameters)obj;
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
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                _privateKey = (ECPrivateKeyParameters)keyPair.Private;
                _publicKey = (ECPublicKeyParameters)keyPair.Public;
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
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new ECDSA(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm, ECDSASignatureExtension signatureExtension)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm, signatureExtension),
                                              () => { return new ECDSA() { HashAlgorithm = hashAlgorithm, SignatureExtension = signatureExtension }; });
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm, ECDSASignatureExtension signatureExtension)
        {
            string suffix;
            switch (signatureExtension)
            {
                case ECDSASignatureExtension.ECDSA: suffix = "ECDSA"; break;
                case ECDSASignatureExtension.ECNR: suffix = "ECNR"; break;
                case ECDSASignatureExtension.Plain: suffix = "PLAIN-ECDSA"; break;
                case ECDSASignatureExtension.CVC: suffix = "CVC-ECDSA"; break;
                default: throw new CryptographicException("Unsupported signature extension.");
            }
            return $"{hashAlgorithm.Name}with{suffix}";
        }

        private static X9ECParameters GetX9ECParameters(EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case EllipticCurve.Prime192v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v1);
                case EllipticCurve.Prime192v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v2);
                case EllipticCurve.Prime192v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v3);
                case EllipticCurve.Prime239v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v1);
                case EllipticCurve.Prime239v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v2);
                case EllipticCurve.Prime239v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v3);
                case EllipticCurve.Prime256v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
                case EllipticCurve.C2Pnb163v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v1);
                case EllipticCurve.C2Pnb163v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v2);
                case EllipticCurve.C2Pnb163v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v3);
                case EllipticCurve.C2Pnb176w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb176w1);
                case EllipticCurve.C2Tnb191v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v1);
                case EllipticCurve.C2Tnb191v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v2);
                case EllipticCurve.C2Tnb191v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v3);
                case EllipticCurve.C2Pnb208w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb208w1);
                case EllipticCurve.C2Tnb239v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v1);
                case EllipticCurve.C2Tnb239v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v2);
                case EllipticCurve.C2Tnb239v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v3);
                case EllipticCurve.C2Pnb272w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb272w1);
                case EllipticCurve.C2Pnb304w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb304w1);
                case EllipticCurve.C2Tnb359v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb359v1);
                case EllipticCurve.C2Pnb368w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb368w1);
                case EllipticCurve.C2Tnb431r1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb431r1);

                case EllipticCurve.SecP112r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r1);
                case EllipticCurve.SecP112r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r2);
                case EllipticCurve.SecP128r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r1);
                case EllipticCurve.SecP128r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r2);
                case EllipticCurve.SecP160k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160k1);
                case EllipticCurve.SecP160r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r1);
                case EllipticCurve.SecP160r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r2);
                case EllipticCurve.SecP192k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192k1);
                case EllipticCurve.SecP192r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192r1);
                case EllipticCurve.SecP224k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224k1);
                case EllipticCurve.SecP224r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224r1);
                case EllipticCurve.SecP256k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256k1);
                case EllipticCurve.SecP256r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
                case EllipticCurve.SecP384r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
                case EllipticCurve.SecP521r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1);
                case EllipticCurve.SecT113r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r1);
                case EllipticCurve.SecT113r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r2);
                case EllipticCurve.SecT131r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r2);
                case EllipticCurve.SecT131r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r1);
                case EllipticCurve.SecT163k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1);
                case EllipticCurve.SecT163r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r1);
                case EllipticCurve.SecT163r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r2);
                case EllipticCurve.SecT193r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r1);
                case EllipticCurve.SecT193r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r2);
                case EllipticCurve.SecT233k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233k1);
                case EllipticCurve.SecT233r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233r1);
                case EllipticCurve.SecT239k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT239k1);
                case EllipticCurve.SecT283k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283k1);
                case EllipticCurve.SecT283r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283r1);
                case EllipticCurve.SecT409k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409k1);
                case EllipticCurve.SecT409r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409r1);
                case EllipticCurve.SecT571k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571k1);
                case EllipticCurve.SecT571r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1);

                case EllipticCurve.NistP192: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP192r1);
                case EllipticCurve.NistP224: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP224r1);
                case EllipticCurve.NistP256: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
                case EllipticCurve.NistP384: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
                case EllipticCurve.NistP521: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1);

                case EllipticCurve.NistB163: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r2);
                case EllipticCurve.NistB233: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT233r1);
                case EllipticCurve.NistB283: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT283r1);
                case EllipticCurve.NistB409: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT409r1);
                case EllipticCurve.NistB571: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1);

                case EllipticCurve.NistK163: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1);
                case EllipticCurve.NistK233: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT233k1);
                case EllipticCurve.NistK283: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT283k1);
                case EllipticCurve.NistK409: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT409k1);
                case EllipticCurve.NistK571: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT571k1);

                case EllipticCurve.BrainpoolP160R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP160R1);
                case EllipticCurve.BrainpoolP160T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP160T1);
                case EllipticCurve.BrainpoolP192R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP192R1);
                case EllipticCurve.BrainpoolP192T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP192T1);
                case EllipticCurve.BrainpoolP224R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP224R1);
                case EllipticCurve.BrainpoolP224T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP224T1);
                case EllipticCurve.BrainpoolP256R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256R1);
                case EllipticCurve.BrainpoolP256T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256T1);
                case EllipticCurve.BrainpoolP320R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP320R1);
                case EllipticCurve.BrainpoolP320T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP320T1);
                case EllipticCurve.BrainpoolP384R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP384R1);
                case EllipticCurve.BrainpoolP384T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP384T1);
                case EllipticCurve.BrainpoolP512R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP512R1);
                case EllipticCurve.BrainpoolP512T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP512T1);

                case EllipticCurve.FRP256v1: return AnssiNamedCurves.GetByOid(AnssiObjectIdentifiers.FRP256v1);

                case EllipticCurve.GostR3410_2001_CryptoPro_A: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
                case EllipticCurve.GostR3410_2001_CryptoPro_B: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProB);
                case EllipticCurve.GostR3410_2001_CryptoPro_C: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProC);
                case EllipticCurve.GostR3410_2001_CryptoPro_XchA: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA);
                case EllipticCurve.GostR3410_2001_CryptoPro_XchB: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB);
                case EllipticCurve.Tc26_Gost3410_12_256_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetB: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetC: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC);

                case EllipticCurve.WapiP192v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.wapip192v1);
                case EllipticCurve.Sm2P256v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);

                default: throw new CryptographicException("Unsupported elliptic curve.");
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
                    IDigest digest = _hashAlgorithm.GetEngine();
                    switch (_signatureExtension)
                    {
                        case ECDSASignatureExtension.ECDSA: _signer = new DsaDigestSigner(new ECDsaSigner(), digest); break;
                        case ECDSASignatureExtension.ECNR: _signer = new DsaDigestSigner(new ECNRSigner(), digest); break;
                        case ECDSASignatureExtension.Plain: _signer = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        case ECDSASignatureExtension.CVC: _signer = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature extension.");
                    }
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithm.GetEngine();
                    switch (_signatureExtension)
                    {
                        case ECDSASignatureExtension.ECDSA: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest); break;
                        case ECDSASignatureExtension.ECNR: _verifier = new DsaDigestSigner(new ECNRSigner(), digest); break;
                        case ECDSASignatureExtension.Plain: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        case ECDSASignatureExtension.CVC: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature extension.");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}