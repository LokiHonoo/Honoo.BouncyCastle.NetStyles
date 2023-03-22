using System;
using System.Diagnostics;
using System.Linq;

namespace Test
{
    internal static class Temporaries
    {
        internal static void Test()
        {
            byte[] bbb1 = new byte[33];
            byte[] bbb2 = new byte[33];
            Common.Random.NextBytes(bbb1);
            Common.Random.NextBytes(bbb2);
            Stopwatch stopwatch = new Stopwatch();

            stopwatch.Restart();
            for (int i = 0; i < 10009090; i++)
            {
                bbb1.SequenceEqual(bbb2);
            }
            stopwatch.Stop();
            Console.WriteLine("SequenceEqual 10990000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");

            stopwatch.Restart();
            for (int i = 0; i < 10000990; i++)
            {
                Compare(bbb1,0, bbb2,0,33);
            }
            stopwatch.Stop();
            Console.WriteLine("Compare 10099000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");

            stopwatch.Restart();
            for (int i = 0; i < 10009090; i++)
            {
                Compare2(bbb1, bbb2);
            }
            stopwatch.Stop();
            Console.WriteLine("Compare2 10099000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            Console.ReadKey(true);
        }

        private static bool Compare(byte[] first, int firstOffset, byte[] second, int secondOffset, int length)
        {
            if (first.Length - firstOffset >= length && second.Length - secondOffset >= length)
            {
                for (int i = 0; i < length; i++)
                {
                    if (first[firstOffset + i] != second[secondOffset + i])
                    {
                        return false;
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// 比较字节数组。
        /// </summary>
        /// <param name="bytesA"></param>
        /// <param name="bytesB"></param>
        /// <returns></returns>
        /// <exception cref="Exception" />
        public static bool Compare2(byte[] bytesA, byte[] bytesB)
        {
            if (bytesA.Length == bytesB.Length)
            {
                for (int i = 0; i < bytesA.Length; i++)
                {
                    if (bytesA[i] != bytesB[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}