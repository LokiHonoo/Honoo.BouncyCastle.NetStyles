using Org.BouncyCastle.Security;
using System;

namespace Test
{
    internal static class Common
    {
        internal static SecureRandom Random { get; } = new SecureRandom();
    }
}