using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 extension collection.
    /// </summary>
    public class X509ExtensionCollection : IEnumerable<X509ExtensionEntity>
    {
        #region Properties

        private readonly IList<X509ExtensionEntity> _elements = new List<X509ExtensionEntity>();
        private readonly ISet<X509ExtensionLabel> _orders = new HashSet<X509ExtensionLabel>();

        /// <summary>
        /// Gets the number of elements contained in the <see cref="X509ExtensionCollection"/>.
        /// </summary>
        public int Count => _orders.Count;

        /// <summary>
        /// Gets the element at the specified label.
        /// </summary>
        /// <param name="label">The label of the element to get.</param>
        /// <returns></returns>
        public X509ExtensionEntity this[X509ExtensionLabel label] { get => Get(label); }

        #endregion Properties

        #region Construction

        internal X509ExtensionCollection()
        {
        }

        #endregion Construction

        /// <summary>
        /// Adds an item to the <see cref="X509ExtensionCollection"/>.
        /// </summary>
        /// <param name="item">The <see cref="X509ExtensionEntity"/> to add to the <see cref="X509ExtensionCollection"/>.</param>
        public void Add(X509ExtensionEntity item)
        {
            _orders.Add(item.Label);
            _elements.Add(item);
        }

        /// <summary>
        /// Adds an item to the <see cref="X509ExtensionCollection"/>.
        /// </summary>
        /// <param name="label">X509 extension label.</param>
        /// <param name="isCritical">X509 extension critical.</param>
        /// <param name="value">X509 extension value.</param>
        public void Add(X509ExtensionLabel label, bool isCritical, Asn1Encodable value)
        {
            _orders.Add(label);
            _elements.Add(new X509ExtensionEntity(label, isCritical, value));
        }

        /// <summary>
        /// Removes all items from the <see cref="X509ExtensionCollection"/>.
        /// </summary>
        public void Clear()
        {
            _orders.Clear();
            _elements.Clear();
        }

        /// <summary>
        /// Determines whether the <see cref="X509ExtensionCollection"/> contains a specific <see cref="X509ExtensionLabel"/>.
        /// </summary>
        /// <param name="label">X509 extension label.</param>
        /// <returns></returns>
        public bool Contains(X509ExtensionLabel label)
        {
            return _orders.Contains(label);
        }

        /// <summary>
        /// Copy extension from other certificate.
        /// </summary>
        /// <param name="certificate">Other certificate.</param>
        public void CopyFrom(X509Certificate certificate)
        {
            ISet oids = certificate.GetCriticalExtensionOids();
            if (oids != null)
            {
                foreach (DerObjectIdentifier oid in oids)
                {
                    Add(new X509ExtensionEntity(oid, true, certificate.GetExtensionValue(oid)));
                }
            }
            oids = certificate.GetNonCriticalExtensionOids();
            if (oids != null)
            {
                foreach (DerObjectIdentifier oid in oids)
                {
                    Add(new X509ExtensionEntity(oid, false, certificate.GetExtensionValue(oid)));
                }
            }
        }

        /// <summary>
        /// Copy extension from other certificate.
        /// </summary>
        /// <param name="certificateDerEncoded">Other certificate of DER endoding.</param>
        public void CopyFrom(byte[] certificateDerEncoded)
        {
            CopyFrom(new X509Certificate(certificateDerEncoded));
        }

        /// <summary>
        /// Copy extension from other certificate.
        /// </summary>
        /// <param name="certificatePem">Other certificate of pem string.</param>
        public void CopyFrom(string certificatePem)
        {
            using (StringReader reader = new StringReader(certificatePem))
            {
                object obj = new PemReader(reader).ReadObject();
                CopyFrom((X509Certificate)obj);
            }
        }

        /// <summary>
        /// Copies the elements of the <see cref="X509ExtensionCollection"/> to an System.Array, starting at a particular System.Array index.
        /// </summary>
        /// <param name="array">The one-dimensional System.Array that is the destination of the elements copied from <see cref="X509ExtensionCollection"/>. The System.Array must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
        public void CopyTo(X509ExtensionEntity[] array, int arrayIndex)
        {
            _elements.CopyTo(array, arrayIndex);
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<X509ExtensionEntity> GetEnumerator()
        {
            return _elements.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Removes the occurrence of a specific <see cref="X509ExtensionLabel"/> from the <see cref="X509ExtensionCollection"/>.
        /// </summary>
        /// <param name="label">X509 extension label.</param>
        /// <returns>Return true if item was successfully removed, otherwise, false. This method also returns false if item is not found.</returns>
        public bool Remove(X509ExtensionLabel label)
        {
            if (_orders.Contains(label))
            {
                _orders.Remove(label);
                for (int i = _elements.Count - 1; i >= 0; i--)
                {
                    if (_elements[i].Label == label)
                    {
                        _elements.RemoveAt(i);
                        return true;
                    }
                }
            }
            return false;
        }

        private X509ExtensionEntity Get(X509ExtensionLabel label)
        {
            if (_orders.Contains(label))
            {
                for (int i = _elements.Count - 1; i >= 0; i--)
                {
                    if (_elements[i].Label == label)
                    {
                        return _elements[i];
                    }
                }
            }
            return null;
        }
    }
}