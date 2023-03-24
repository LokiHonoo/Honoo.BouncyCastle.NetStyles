using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a generator over the certification request.
    /// </summary>
    public sealed class X509CertificateRequestGenerator
    {
        #region Properties

        private readonly string _asn1Algorithm;
        private readonly X509ExtensionCollection _extensions = new X509ExtensionCollection();
        private readonly AsymmetricKeyParameter _privateKey;
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly X509NameCollection _subjectDN = new X509NameCollection();

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public X509ExtensionCollection Extensions => _extensions;

        /// <summary>
        /// Gets X509 subject distinct name collection.
        /// </summary>
        public X509NameCollection SubjectDN => _subjectDN;

        internal AsymmetricKeyParameter PublicKey => _publicKey;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectKeyPair">Subject asymmetric key pair.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, AsymmetricCipherKeyPair subjectKeyPair)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(subjectKeyPair);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKey">Subject asymmetric private key. Create public key automatically.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, AsymmetricKeyParameter subjectPrivateKey)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(subjectPrivateKey);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyPem">Subject asymmetric private key pem string. Create public key automatically.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, string subjectPrivateKeyPem)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(subjectPrivateKeyPem);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyPem">Subject encrypted asymmetric private key pem string. Create public key automatically.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, string subjectPrivateKeyPem, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(subjectPrivateKeyPem, password);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyInfo">Subject asymmetric private key PKCS#8 info. Create public key automatically.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, byte[] subjectPrivateKeyInfo)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(subjectPrivateKeyInfo);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyInfo">Subject encrypted asymmetric private key PKCS#8 info. Create public key automatically.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, byte[] subjectPrivateKeyInfo, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(subjectPrivateKeyInfo, password);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        #endregion Construction

        /// <summary>
        /// Generates a <see cref="Pkcs10CertificationRequest"/> containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public Pkcs10CertificationRequest Generate()
        {
            return GenerateCore();
        }

        /// <summary>
        /// Generates a byte array containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateDer()
        {
            Pkcs10CertificationRequest csr = GenerateCore();
            return csr.GetDerEncoded();
        }

        /// <summary>
        /// Generates a pem string containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public string GeneratePem()
        {
            Pkcs10CertificationRequest csr = GenerateCore();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(csr);
                return writer.ToString();
            }
        }

        private Pkcs10CertificationRequest GenerateCore()
        {
            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(_asn1Algorithm, _privateKey, Common.SecureRandom.Value);
            X509Name name = X509Utilities.GetX509Name(_subjectDN);
            DerSet attribute = null;
            if (_extensions.Count > 0)
            {
                X509Extensions extensions = X509Utilities.GetX509Extensions(_extensions);
                DerSet extensionsDerSet = new DerSet(extensions);
                AttributePkcs pkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, extensionsDerSet);
                attribute = new DerSet(pkcs);
            }
            return new Pkcs10CertificationRequest(signatureFactory, name, _publicKey, attribute);
        }
    }
}