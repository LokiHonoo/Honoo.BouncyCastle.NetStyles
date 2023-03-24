using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a generator over the X.509 v.3 certificate.
    /// </summary>
    public class X509CertificateV3Generator
    {
        #region Properties

        private readonly string _asn1Algorithm;
        private readonly X509ExtensionCollection _extensions = new X509ExtensionCollection();
        private readonly X509NameCollection _issuerDN = new X509NameCollection();
        private readonly AsymmetricKeyParameter _privateKey;
        private X509CertificateRequestTiled _certificateRequestTiled;

        /// <summary>
        /// Gets certificate request tiled to modify information.
        /// It's 'null' if not <see cref="SetCertificateRequest(Pkcs10CertificationRequest)"/> or <see cref="RemoveCertificateRequest()"/>.
        /// </summary>
        public X509CertificateRequestTiled CertificateRequest => _certificateRequestTiled;

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public X509ExtensionCollection Extensions => _extensions;

        /// <summary>
        /// Gets issuer X509 distinct name collection.
        /// </summary>
        public X509NameCollection IssuerDN => _issuerDN;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKey">Issuer(CA) private key.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, AsymmetricKeyParameter issuerPrivateKey)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(issuerPrivateKey);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        #endregion Construction

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public X509Certificate Generate(DateTime start, DateTime end)
        {
            return GenerateCore(start, end);
        }

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request, And save to a byte array of DER encoding.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public byte[] GenerateDer(DateTime start, DateTime end)
        {
            X509Certificate cer = GenerateCore(start, end);
            return cer.GetEncoded();
        }

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request, And save to a pem string.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public string GeneratePem(DateTime start, DateTime end)
        {
            X509Certificate cer = GenerateCore(start, end);
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cer);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Remove certificate request.
        /// </summary>
        public void RemoveCertificateRequest()
        {
            _certificateRequestTiled = null;
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        /// <param name="certificationRequest">Certificate request.</param>
        public void SetCertificateRequest(Pkcs10CertificationRequest certificationRequest)
        {
            _certificateRequestTiled = new X509CertificateRequestTiled(certificationRequest);
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        /// <param name="certificationRequestPem">Certificate request of pem string.</param>
        public void SetCertificateRequest(string certificationRequestPem)
        {
            using (StringReader reader = new StringReader(certificationRequestPem))
            {
                object obj = new PemReader(reader).ReadObject();
                Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)obj;
                _certificateRequestTiled = new X509CertificateRequestTiled(csr);
            }
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        /// <param name="certificationRequestDerEncoded">Certificate request of DER encoding.</param>
        public void SetCertificateRequest(byte[] certificationRequestDerEncoded)
        {
            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(certificationRequestDerEncoded);
            _certificateRequestTiled = new X509CertificateRequestTiled(csr);
        }

        private X509Certificate GenerateCore(DateTime start, DateTime end)
        {
            if (end < start)
            {
                throw new Exception("The end time is earlier than the start time.");
            }
            if (_certificateRequestTiled == null)
            {
                throw new CryptographicException("Certificate request is null. Set certificate request be first.");
            }
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(_asn1Algorithm, _privateKey, Common.SecureRandom.Value);
            BigInteger sn = new BigInteger(128, Common.SecureRandom.Value);
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(sn);
            generator.SetIssuerDN(X509Utilities.GetX509Name(_issuerDN));
            generator.SetPublicKey(_certificateRequestTiled.PublicKey);
            generator.SetSubjectDN(X509Utilities.GetX509Name(_certificateRequestTiled.SubjectDN));
            if (_extensions.Count > 0)
            {
                foreach (X509ExtensionEntity entity in _extensions)
                {
                    generator.AddExtension(entity.Oid, entity.IsCritical, entity.Value);
                }
            }
            if (_certificateRequestTiled.Extensions.Count > 0)
            {
                foreach (X509ExtensionEntity entity in _certificateRequestTiled.Extensions)
                {
                    generator.AddExtension(entity.Oid, entity.IsCritical, entity.Value);
                }
            }
            generator.SetNotBefore(start);
            generator.SetNotAfter(end);
            return generator.Generate(signatureFactory);
        }
    }
}