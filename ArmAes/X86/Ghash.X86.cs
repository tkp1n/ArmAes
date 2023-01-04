using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ArmAes;

internal static partial class Ghash
{
    /// <summary>
    /// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
    /// </summary>
    private static class X86
    {
        private static readonly Vector128<byte> BswapMask
            = Vector128.Create((byte) 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

        private static readonly Vector128<byte> BswapEpi64
            = Vector128.Create((byte) 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);

        /// <summary>
        /// Figure 5. Code Sample - Performing Ghash Using Algorithms 1 and 5 (C)
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> Gfmul(Vector128<ulong> a, Vector128<ulong> b)
        {
            Vector128<ulong> tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

            tmp3 = Pclmulqdq.CarrylessMultiply(a, b, 0x00);
            tmp4 = Pclmulqdq.CarrylessMultiply(a, b, 0x10);
            tmp5 = Pclmulqdq.CarrylessMultiply(a, b, 0x01);
            tmp6 = Pclmulqdq.CarrylessMultiply(a, b, 0x11);

            tmp4 = Sse2.Xor(tmp4, tmp5);
            tmp5 = Sse2.ShiftLeftLogical128BitLane(tmp4, 8);
            tmp4 = Sse2.ShiftRightLogical128BitLane(tmp4, 8);
            tmp3 = Sse2.Xor(tmp3, tmp5);
            tmp6 = Sse2.Xor(tmp6, tmp4);

            tmp7 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 31).AsUInt64();
            tmp8 = Sse2.ShiftRightLogical(tmp6.AsUInt32(), 31).AsUInt64();
            tmp3 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 1).AsUInt64();
            tmp6 = Sse2.ShiftLeftLogical(tmp6.AsUInt32(), 1).AsUInt64();

            tmp9 = Sse2.ShiftRightLogical128BitLane(tmp7, 12);
            tmp8 = Sse2.ShiftLeftLogical128BitLane(tmp8, 4);
            tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 4);
            tmp3 = Sse2.Or(tmp3, tmp7);
            tmp6 = Sse2.Or(tmp6, tmp8);
            tmp6 = Sse2.Or(tmp6, tmp9);

            tmp7 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 31).AsUInt64();
            tmp8 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 30).AsUInt64();
            tmp9 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 25).AsUInt64();

            tmp7 = Sse2.Xor(tmp7, tmp8);
            tmp7 = Sse2.Xor(tmp7, tmp9);
            tmp8 = Sse2.ShiftRightLogical128BitLane(tmp7, 4);
            tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 12);
            tmp3 = Sse2.Xor(tmp3, tmp7);

            tmp2 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 1).AsUInt64();
            tmp4 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 2).AsUInt64();
            tmp5 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 7).AsUInt64();
            tmp2 = Sse2.Xor(tmp2, tmp4);
            tmp2 = Sse2.Xor(tmp2, tmp5);
            tmp2 = Sse2.Xor(tmp2, tmp8);
            tmp3 = Sse2.Xor(tmp3, tmp2);
            tmp6 = Sse2.Xor(tmp6, tmp3);

            return tmp6;
        }

        /// <summary>
        /// Figure 8. Code Sample -Performing GhashUsing an Aggregated Reduction Method
        /// Algorithm by Krzysztof Jankowski,  Pierre Laurent - Intel
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> Reduce4(
            Vector128<ulong> h1, Vector128<ulong> h2, Vector128<ulong> h3, Vector128<ulong> h4,
            Vector128<ulong> x1, Vector128<ulong> x2, Vector128<ulong> x3, Vector128<ulong> x4)
        {
            Unsafe.SkipInit(out Vector128<ulong> h1x1Lo);
            Unsafe.SkipInit(out Vector128<ulong> h1x1Hi);
            Unsafe.SkipInit(out Vector128<ulong> h2x2Lo);
            Unsafe.SkipInit(out Vector128<ulong> h2x2Hi);
            Unsafe.SkipInit(out Vector128<ulong> h3x3Lo);
            Unsafe.SkipInit(out Vector128<ulong> h3x3Hi);
            Unsafe.SkipInit(out Vector128<ulong> h4x4Lo);
            Unsafe.SkipInit(out Vector128<ulong> h4x4Hi);
            Unsafe.SkipInit(out Vector128<ulong> lo);
            Unsafe.SkipInit(out Vector128<ulong> hi);

            Unsafe.SkipInit(out Vector128<ulong> tmp0);
            Unsafe.SkipInit(out Vector128<ulong> tmp1);
            Unsafe.SkipInit(out Vector128<ulong> tmp2);
            Unsafe.SkipInit(out Vector128<ulong> tmp3);
            Unsafe.SkipInit(out Vector128<ulong> tmp4);
            Unsafe.SkipInit(out Vector128<ulong> tmp5);
            Unsafe.SkipInit(out Vector128<ulong> tmp6);
            Unsafe.SkipInit(out Vector128<ulong> tmp7);
            Unsafe.SkipInit(out Vector128<ulong> tmp8);
            Unsafe.SkipInit(out Vector128<ulong> tmp9);

            h1x1Lo = Pclmulqdq.CarrylessMultiply(h1, x1, 0x00);
            h2x2Lo = Pclmulqdq.CarrylessMultiply(h2, x2, 0x00);
            h3x3Lo = Pclmulqdq.CarrylessMultiply(h3, x3, 0x00);
            h4x4Lo = Pclmulqdq.CarrylessMultiply(h4, x4, 0x00);

            lo = Sse2.Xor(h1x1Lo, h2x2Lo);
            lo = Sse2.Xor(lo, h3x3Lo);
            lo = Sse2.Xor(lo, h4x4Lo);

            h1x1Hi = Pclmulqdq.CarrylessMultiply(h1, x1, 0x11);
            h2x2Hi = Pclmulqdq.CarrylessMultiply(h2, x2, 0x11);
            h3x3Hi = Pclmulqdq.CarrylessMultiply(h3, x3, 0x11);
            h4x4Hi = Pclmulqdq.CarrylessMultiply(h4, x4, 0x11);

            hi = Sse2.Xor(h1x1Hi, h2x2Hi);
            hi = Sse2.Xor(hi, h3x3Hi);
            hi = Sse2.Xor(hi, h4x4Hi);

            tmp0 = Sse2.Shuffle(h1.AsUInt32(), 78).AsUInt64();
            tmp4 = Sse2.Shuffle(x1.AsUInt32(), 78).AsUInt64();
            tmp0 = Sse2.Xor(tmp0, h1);
            tmp4 = Sse2.Xor(tmp4, x1);
            tmp1 = Sse2.Shuffle(h2.AsUInt32(), 78).AsUInt64();
            tmp5 = Sse2.Shuffle(x2.AsUInt32(), 78).AsUInt64();
            tmp1 = Sse2.Xor(tmp1, h2);
            tmp5 = Sse2.Xor(tmp5, x2);
            tmp2 = Sse2.Shuffle(h3.AsUInt32(), 78).AsUInt64();
            tmp6 = Sse2.Shuffle(x3.AsUInt32(), 78).AsUInt64();
            tmp2 = Sse2.Xor(tmp2, h3);
            tmp6 = Sse2.Xor(tmp6, x3);
            tmp3 = Sse2.Shuffle(h4.AsUInt32(), 78).AsUInt64();
            tmp7 = Sse2.Shuffle(x4.AsUInt32(), 78).AsUInt64();
            tmp3 = Sse2.Xor(tmp3, h4);
            tmp7 = Sse2.Xor(tmp7, x4);

            tmp0 = Pclmulqdq.CarrylessMultiply(tmp0, tmp4, 0x00);
            tmp1 = Pclmulqdq.CarrylessMultiply(tmp1, tmp5, 0x00);
            tmp2 = Pclmulqdq.CarrylessMultiply(tmp2, tmp6, 0x00);
            tmp3 = Pclmulqdq.CarrylessMultiply(tmp3, tmp7, 0x00);

            tmp0 = Sse2.Xor(tmp0, lo);
            tmp0 = Sse2.Xor(tmp0, hi);
            tmp0 = Sse2.Xor(tmp1, tmp0);
            tmp0 = Sse2.Xor(tmp2, tmp0);
            tmp0 = Sse2.Xor(tmp3, tmp0);

            tmp4 = Sse2.ShiftLeftLogical128BitLane(tmp0, 8);
            tmp0 = Sse2.ShiftRightLogical128BitLane(tmp0, 8);

            lo = Sse2.Xor(tmp4, lo);
            hi = Sse2.Xor(tmp0, hi);

            tmp3 = lo;
            tmp6 = hi;

            tmp7 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 31).AsUInt64();
            tmp8 = Sse2.ShiftRightLogical(tmp6.AsUInt32(), 31).AsUInt64();
            tmp3 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 1).AsUInt64();
            tmp6 = Sse2.ShiftLeftLogical(tmp6.AsUInt32(), 1).AsUInt64();

            tmp9 = Sse2.ShiftRightLogical128BitLane(tmp7, 12);
            tmp8 = Sse2.ShiftLeftLogical128BitLane(tmp8, 4);
            tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 4);
            tmp3 = Sse2.Or(tmp3, tmp7);
            tmp6 = Sse2.Or(tmp6, tmp8);
            tmp6 = Sse2.Or(tmp6, tmp9);

            tmp7 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 31).AsUInt64();
            tmp8 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 30).AsUInt64();
            tmp9 = Sse2.ShiftLeftLogical(tmp3.AsUInt32(), 25).AsUInt64();

            tmp7 = Sse2.Xor(tmp7, tmp8);
            tmp7 = Sse2.Xor(tmp7, tmp9);
            tmp8 = Sse2.ShiftRightLogical128BitLane(tmp7, 4);
            tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 12);
            tmp3 = Sse2.Xor(tmp3, tmp7);

            tmp2 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 1).AsUInt64();
            tmp4 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 2).AsUInt64();
            tmp5 = Sse2.ShiftRightLogical(tmp3.AsUInt32(), 7).AsUInt64();
            tmp2 = Sse2.Xor(tmp2, tmp4);
            tmp2 = Sse2.Xor(tmp2, tmp5);
            tmp2 = Sse2.Xor(tmp2, tmp8);
            tmp3 = Sse2.Xor(tmp3, tmp2);
            tmp6 = Sse2.Xor(tmp6, tmp3);

            return tmp6;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> BswapVec(Vector128<byte> v)
        {
            return Ssse3.Shuffle(v, BswapMask);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Bswap64(Vector128<byte> v)
        {
            return Ssse3.Shuffle(v, BswapEpi64);
        }
    }
}