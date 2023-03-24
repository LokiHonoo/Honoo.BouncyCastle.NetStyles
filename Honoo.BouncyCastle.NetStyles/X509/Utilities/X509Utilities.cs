using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;

namespace Honoo.BouncyCastle.NetStyles.X509.Utilities
{
    internal static class X509Utilities
    {
        internal static X509Extensions GetX509Extensions(X509ExtensionCollection entities)
        {
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            List<X509Extension> attributes = new List<X509Extension>();
            foreach (X509ExtensionEntity entity in entities)
            {
                ordering.Add(entity.Oid);
                X509Extension extension = new X509Extension(entity.IsCritical, new DerOctetString(entity.Value));
                attributes.Add(extension);
            }
            return new X509Extensions(ordering, attributes);
        }

        internal static X509Name GetX509Name(X509NameCollection entities)
        {
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            List<string> attributes = new List<string>();
            foreach (X509NameEntity entity in entities)
            {
                ordering.Add(entity.Oid);
                attributes.Add(entity.Value);
            }
            return new X509Name(ordering, attributes);
        }
    }
}