using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 distinct name collection.
    /// </summary>
    public class X509NameCollection : IEnumerable<X509NameEntity>
    {
        #region Properties

        private readonly IList<X509NameEntity> _elements = new List<X509NameEntity>();
        private readonly ISet<X509NameLabel> _orders = new HashSet<X509NameLabel>();

        /// <summary>
        /// Gets the number of elements contained in the <see cref="X509NameCollection"/>.
        /// </summary>
        public int Count => _orders.Count;

        /// <summary>
        /// Gets the element at the specified label.
        /// </summary>
        /// <param name="label">The label of the element to get.</param>
        /// <returns></returns>
        public X509NameEntity this[X509NameLabel label] { get => Get(label); }

        #endregion Properties

        /// <summary>
        /// Adds an item to the <see cref="X509NameCollection"/>.
        /// </summary>
        /// <param name="item">The <see cref="X509NameEntity"/> to add to the <see cref="X509NameCollection"/>.</param>
        public void Add(X509NameEntity item)
        {
            _orders.Add(item.Label);
            _elements.Add(item);
        }

        /// <summary>
        /// Adds an item to the <see cref="X509NameCollection"/>.
        /// </summary>
        /// <param name="label">X509 distinct name label.</param>
        /// <param name="value">X509 distinct name value.</param>
        public void Add(X509NameLabel label, string value)
        {
            _orders.Add(label);
            _elements.Add(new X509NameEntity(label, value));
        }

        /// <summary>
        /// Removes all items from the <see cref="X509NameCollection"/>.
        /// </summary>
        public void Clear()
        {
            _orders.Clear();
            _elements.Clear();
        }

        /// <summary>
        /// Determines whether the <see cref="X509NameCollection"/> contains a specific <see cref="X509NameLabel"/>.
        /// </summary>
        /// <param name="label">X509 distinct name label.</param>
        /// <returns></returns>
        public bool Contains(X509NameLabel label)
        {
            return _orders.Contains(label);
        }

        /// <summary>
        /// Copy X509 distinct name from SubjectDN of other certificate.
        /// </summary>
        /// <param name="certificate">Other certificate.</param>
        public void CopyFromSubjectDN(X509Certificate certificate)
        {
            IList oids = certificate.SubjectDN.GetOidList();
            if (oids != null)
            {
                IList values = certificate.SubjectDN.GetValueList();
                for (int i = 0; i < oids.Count; i++)
                {
                    Add(new X509NameEntity((DerObjectIdentifier)oids[i], (string)values[i]));
                }
            }
        }

        /// <summary>
        /// Copy X509 distinct name from SubjectDN of other certificate.
        /// </summary>
        /// <param name="certificateDerEncoded">Other certificate of DER endoding.</param>
        public void CopyFromSubjectDN(byte[] certificateDerEncoded)
        {
            CopyFromSubjectDN(new X509Certificate(certificateDerEncoded));
        }

        /// <summary>
        /// Copy X509 distinct name from SubjectDN of other certificate.
        /// </summary>
        /// <param name="certificatePem">Other certificate of pem string.</param>
        public void CopyFromSubjectDN(string certificatePem)
        {
            using (StringReader reader = new StringReader(certificatePem))
            {
                object obj = new PemReader(reader).ReadObject();
                CopyFromSubjectDN((X509Certificate)obj);
            }
        }

        /// <summary>
        /// Copies the elements of the <see cref="X509NameCollection"/> to an System.Array, starting at a particular System.Array index.
        /// </summary>
        /// <param name="array">The one-dimensional System.Array that is the destination of the elements copied from <see cref="X509NameCollection"/>. The System.Array must have zero-based indexing.</param>
        /// <param name="arrayIndex">The zero-based index in array at which copying begins.</param>
        public void CopyTo(X509NameEntity[] array, int arrayIndex)
        {
            _elements.CopyTo(array, arrayIndex);
        }

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<X509NameEntity> GetEnumerator()
        {
            return _elements.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Removes the occurrence of a specific <see cref="X509NameLabel"/> from the <see cref="X509NameCollection"/>.
        /// </summary>
        /// <param name="label">X509 distinct name label.</param>
        /// <returns>Return true if item was successfully removed, otherwise, false. This method also returns false if item is not found.</returns>
        public bool Remove(X509NameLabel label)
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

        private X509NameEntity Get(X509NameLabel label)
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