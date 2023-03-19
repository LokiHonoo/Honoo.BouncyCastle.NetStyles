using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm, IECDHTerminalA, IECDHTerminalB
    {
        #region Properties

        private static readonly KeySizes[] _legalKeySizes = new KeySizes[]
        {
            new KeySizes(192, 224, 32),
            new KeySizes(239, 239, 0),
            new KeySizes(256, 384, 128),
            new KeySizes(521, 521, 0)
        };

        // private AsymmetricKeyParameter _privateKey = null;
        // private AsymmetricKeyParameter _publicKey = null;

        private ECDHBasicAgreement _agreementA = null;
        private ECDHBasicAgreement _agreementB = null;
        private byte[] _g = null;
        private bool _initialized = false;
        private byte[] _p = null;
        private BigInteger _pmsB = null;
        private byte[] _publicKeyA = null;
        private byte[] _publicKeyB = null;

        byte[] IECDHTerminalA.G
        {
            get
            {
                InspectKey();
                return (byte[])_g.Clone();
            }
        }

        byte[] IECDHTerminalA.P
        {
            get
            {
                InspectKey();
                return (byte[])_p.Clone();
            }
        }

        byte[] IECDHTerminalA.PublicKeyA
        {
            get
            {
                InspectKey();
                return (byte[])_publicKeyA.Clone();
            }
        }

        byte[] IECDHTerminalB.PublicKeyB => _publicKeyB;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECDH class.
        /// </summary>
        public ECDH() : base("ECDH", AsymmetricAlgorithmKind.KeyExchange)
        {
        }

        #endregion Construction

        byte[] IECDHTerminalB.DeriveKeyMaterial(bool unsigned)
        {
            return unsigned ? _pmsB.ToByteArrayUnsigned() : _pmsB.ToByteArray();
        }

        byte[] IECDHTerminalA.DeriveKeyMaterial(byte[] publicKeyB, bool unsigned)
        {
            AsymmetricKeyParameter publicKeyBob = PublicKeyFactory.CreateKey(publicKeyB);
            BigInteger pmsA = _agreementA.CalculateAgreement(publicKeyBob);
            return unsigned ? pmsA.ToByteArrayUnsigned() : pmsA.ToByteArray();
        }

        void IECDHTerminalA.GenerateParameters(int keySize, int certainty)
        {
            if (!DetectionUtilities.ValidSize(_legalKeySizes, keySize))
            {
                throw new CryptographicException("Legal key size 192, 224, 239, 256, 384, 521.");
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            DHParameters parameters = parametersGenerator.GenerateParameters();
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            _agreementA = new ECDHBasicAgreement();
            _agreementA.Init(keyPair.Private);
            _p = parameters.P.ToByteArray();
            _g = parameters.G.ToByteArray();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKeyA = publicKeyInfo.GetEncoded();
            _initialized = true;
        }

        void IECDHTerminalB.GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA)
        {
            AsymmetricKeyParameter publicKeyAlice = PublicKeyFactory.CreateKey(publicKeyA);
            DHParameters parameters = new DHParameters(new BigInteger(p), new BigInteger(g));
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _agreementB = new ECDHBasicAgreement();
            _agreementB.Init(keyPair.Private);
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKeyB = publicKeyInfo.GetEncoded();
            _pmsB = _agreementB.CalculateAgreement(publicKeyAlice);
        }

        /// <summary>
        /// Gets terminal A's interface.
        /// </summary>
        /// <returns></returns>
        public IECDHTerminalA GetTerminalAInterface()
        {
            return this;
        }

        /// <summary>
        /// Gets terminal B's interface.
        /// </summary>
        /// <returns></returns>
        public IECDHTerminalB GetTerminalBInterface()
        {
            return this;
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName("ECDH", AsymmetricAlgorithmKind.KeyExchange, () => { return new ECDH(); });
        }

        private void GenerateParameters(int keySize = 521, int certainty = 20)
        {
            if (!DetectionUtilities.ValidSize(_legalKeySizes, keySize))
            {
                throw new CryptographicException("Legal key size 192, 224, 239, 256, 384, 521.");
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            DHParameters parameters = parametersGenerator.GenerateParameters();
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(keyPair.Private);
            _p = parameters.P.ToByteArray();
            _g = parameters.G.ToByteArray();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKeyA = publicKeyInfo.GetEncoded();
            _agreementA = agreement;
            _initialized = true;
        }

        private void InspectKey()
        {
            if (!_initialized)
            {
                GenerateParameters(521, 20);
            }
        }
    }
}