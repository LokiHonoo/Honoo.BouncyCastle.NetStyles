using Org.BouncyCastle.Security;
using System.Threading;

namespace Honoo.BouncyCastle.NetStyles
{
    internal static class Common
    {
        internal static ThreadLocal<SecureRandom> SecureRandom { get; } = new ThreadLocal<SecureRandom>(() => { return new SecureRandom(); });

        /// <summary>
        /// Control global size max value to 65536 or 2147483640. Must be set at program initialization.
        /// </summary>
        internal static int SizeMax { get; } = 65536;
    }
}