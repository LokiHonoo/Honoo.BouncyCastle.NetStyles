using Honoo.BouncyCastle.NetStyles;
using Honoo.BouncyCastle.NetStyles.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Test
{
    internal static class X509
    {
        private static X509Certificate _issuerCer;
        private static byte[] _issuerPrivateKeyInfo;
        private static SignatureAlgorithmName _issuerSignatureAlgorithm;

        internal static void Test()
        {
            CreateCACert();
            CreateCrl();
            CreateUserCert();
            //
            Console.ReadKey(true);
        }

        private static void CreateCACert()
        {
            //
            // Issuer work, Create CA private key and self sign certificate.
            //
            _issuerSignatureAlgorithm = SignatureAlgorithmName.SHA256withECDSA;
            ISignatureAlgorithm issuerAlgorithm = AsymmetricAlgorithm.Create(_issuerSignatureAlgorithm);
            byte[] issuerPrivateKeyInfo = issuerAlgorithm.ExportKeyInfo(true);
            X509CertificateRequestGenerator issuerCsrGenerator = new X509CertificateRequestGenerator(_issuerSignatureAlgorithm, issuerPrivateKeyInfo);
            issuerCsrGenerator.SubjectDN.Add(X509NameLabel.C, "CN");
            issuerCsrGenerator.SubjectDN.Add(X509NameLabel.CN, "Test CA");
            string issuerCsr = issuerCsrGenerator.GeneratePem();
            X509CertificateV3Generator v3Generator = new X509CertificateV3Generator(_issuerSignatureAlgorithm, issuerPrivateKeyInfo);
            v3Generator.IssuerDN.Add(X509NameLabel.C, "CN");
            v3Generator.IssuerDN.Add(X509NameLabel.CN, "Test CA");
            v3Generator.SetCertificateRequest(issuerCsr);
            _issuerCer = v3Generator.Generate(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(365));
            _issuerPrivateKeyInfo = issuerPrivateKeyInfo;
        }

        private static void CreateCrl()
        {
            //
            // Issuer work, Create CA private key and self sign certificate.
            //
            _issuerSignatureAlgorithm = SignatureAlgorithmName.SHA256withECDSA;
            ISignatureAlgorithm issuerAlgorithm = AsymmetricAlgorithm.Create(_issuerSignatureAlgorithm);
            byte[] issuerPrivateKeyInfo = issuerAlgorithm.ExportKeyInfo(true);
            X509CertificateRevocationListGenerator generator = new X509CertificateRevocationListGenerator(_issuerSignatureAlgorithm, issuerPrivateKeyInfo);
            generator.IssuerDN.CopyFromSubjectDN(_issuerCer);
            generator.Extensions.CopyFrom(_issuerCer);
            generator.Revocations.Add(new X509CertificateRevocationEntity("F38BC566", 16, DateTime.Now, null));
            generator.Revocations.Add(new X509CertificateRevocationEntity("136780432367", 10, DateTime.Now, null));
            generator.Generate(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(365), null);
        }

        private static void CreateUserCert()
        {
            //
            // Issuer work, Create key for subject.
            //
            SignatureAlgorithmName userSignatureAlgorithm = SignatureAlgorithmName.SM3withSM2; //Issuer define of allow user specify.
            ISignatureAlgorithm issuerCreateAlgorithmForSubject = AsymmetricAlgorithm.Create(userSignatureAlgorithm);
            string algorithmMechanism = userSignatureAlgorithm.Oid; // Send to user
            byte[] userPrivateKeyInfo = issuerCreateAlgorithmForSubject.ExportKeyInfo(true); // Send to user
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter userPublicKey = issuerCreateAlgorithmForSubject.ExportParameters(false);

            //
            // User work, Create certificate request.
            //
            SignatureAlgorithmName.TryGetAlgorithmName(algorithmMechanism, out SignatureAlgorithmName userAlgorithmName);
            X509CertificateRequestGenerator userCreateCsr = new X509CertificateRequestGenerator(userAlgorithmName, userPrivateKeyInfo);
            userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.C, "CN"));
            userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.CN, "Test Subject Porject Name"));
            userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.EmailAddress, "abc999@test111222.com"));
            Asn1Encodable asn1 = new BasicConstraints(false);
            userCreateCsr.Extensions.Add(new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, asn1));
            byte[] csrPem = userCreateCsr.GenerateDer(); // Send to issuer

            //
            // Issuer work, Load certificate request and create certificate.
            //
            X509CertificateV3Generator v3generator = new X509CertificateV3Generator(_issuerSignatureAlgorithm, _issuerPrivateKeyInfo);
            v3generator.IssuerDN.CopyFromSubjectDN(_issuerCer);
            Asn1Encodable asn2 = new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.DataEncipherment);
            v3generator.Extensions.Add(new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, false, asn2));
            v3generator.SetCertificateRequest(csrPem);
            if (v3generator.CertificateRequest.Verify(userPublicKey))
            {
                v3generator.CertificateRequest.SubjectDN.Remove(X509NameLabel.EmailAddress);
            }
            byte[] userCer = v3generator.GenerateDer(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(99));
            //
            // User work, Verify.
            //
            File.WriteAllBytes("userCer.cer", userCer);
            var userCerBC = new Org.BouncyCastle.X509.X509Certificate(userCer);
            var userCerNET = new System.Security.Cryptography.X509Certificates.X509Certificate2(userCer); 
            try
            {
                userCerBC.Verify(_issuerCer.GetPublicKey());
                Console.WriteLine($"Verify user certificate by CA certificate - true");
            }
            catch (Exception)
            {
                Console.WriteLine($"Verify user certificate by CA certificate - false");
            }
            Console.WriteLine();
            Console.WriteLine(userCerBC);
            Console.WriteLine();
            Console.WriteLine(userCerNET);
            Console.ReadKey(true);
        }
    }
}