using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

internal static partial class Ghash
{
    private static class Arm
    {
        private static readonly Vector128<byte> BswapMask
            = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> Reduce(Vector128<uint> b0, Vector128<uint> b1)
        {
            var T4 = AdvSimd.ShiftRightLogical(b0, 31);
            var T0 = AdvSimd.ShiftLeftLogical(b0, 1);
            var T5 = AdvSimd.ShiftRightLogical(b1, 31);
            var T3 = AdvSimd.ShiftLeftLogical(b1, 1);

            var T2 = AdvSimd.ExtractVector128(T4, Vector128<uint>.Zero, 3);
            T5 = AdvSimd.ExtractVector128(Vector128<uint>.Zero, T5, 3);
            T4 = AdvSimd.ExtractVector128(Vector128<uint>.Zero, T4, 3);
            T0 = AdvSimd.Or(T0, T4);
            T3 = AdvSimd.Or(T3, T5);
            T3 = AdvSimd.Or(T3, T2);

            T4 = AdvSimd.ShiftLeftLogical(T0, 31);
            T5 = AdvSimd.ShiftLeftLogical(T0, 30);
            T2 = AdvSimd.ShiftLeftLogical(T0, 25);

            T4 = AdvSimd.Xor(T4, T5);
            T4 = AdvSimd.Xor(T4, T2);
            T5 = AdvSimd.ExtractVector128(T4, Vector128<uint>.Zero, 1);
            T3 = AdvSimd.Xor(T3, T5);
            T4 = AdvSimd.ExtractVector128(Vector128<uint>.Zero, T4, 1);
            T0 = AdvSimd.Xor(T0, T4);
            T3 = AdvSimd.Xor(T3, T0);

            T4 = AdvSimd.ShiftRightLogical(T0, 1);
            var T1 = AdvSimd.ShiftRightLogical(T0, 2);
            T2 = AdvSimd.ShiftRightLogical(T0, 7);
            T3 = AdvSimd.Xor(T3, T1);
            T3 = AdvSimd.Xor(T3, T2);
            T3 = AdvSimd.Xor(T3, T4);

            return T3.AsUInt64();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> Gfmul(Vector128<ulong> H, Vector128<ulong> X)
        {
            var x_hi = X.GetLower();
            var x_lo = X.GetUpper();
            var H_hi = H.GetLower();
            var H_lo = H.GetUpper();

            var T0 = Aes.PolynomialMultiplyWideningLower(x_hi, H_hi).AsUInt32();
            var T1 = Aes.PolynomialMultiplyWideningLower(x_lo, H_hi).AsUInt32();
            var T2 = Aes.PolynomialMultiplyWideningLower(x_hi, H_lo).AsUInt32();
            var T3 = Aes.PolynomialMultiplyWideningLower(x_lo, H_lo).AsUInt32();

            T1 = AdvSimd.Xor(T1, T2);
            T0 = AdvSimd.Xor(T0, AdvSimd.ExtractVector128(Vector128<uint>.Zero, T1, 2));
            T3 = AdvSimd.Xor(T3, AdvSimd.ExtractVector128(T1, Vector128<uint>.Zero, 2));

            return Reduce(T0, T3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<ulong> Reduce4(
            Vector128<ulong> H1, Vector128<ulong> H2, Vector128<ulong> H3, Vector128<ulong> H4,
            Vector128<ulong> X1, Vector128<ulong> X2, Vector128<ulong> X3, Vector128<ulong> X4)
        {
            var H1_hi = H1.GetLower();
            var H1_lo = H1.GetUpper();
            var H2_hi = H2.GetLower();
            var H2_lo = H2.GetUpper();
            var H3_hi = H3.GetLower();
            var H3_lo = H3.GetUpper();
            var H4_hi = H4.GetLower();
            var H4_lo = H4.GetUpper();

            var X1_hi = X1.GetLower();
            var X1_lo = X1.GetUpper();
            var X2_hi = X2.GetLower();
            var X2_lo = X2.GetUpper();
            var X3_hi = X3.GetLower();
            var X3_lo = X3.GetUpper();
            var X4_hi = X4.GetLower();
            var X4_lo = X4.GetUpper();

            var H1_X1_lo = Aes.PolynomialMultiplyWideningLower(X1_lo, H1_lo);
            var H2_X2_lo = Aes.PolynomialMultiplyWideningLower(X2_lo, H2_lo);
            var H3_X3_lo = Aes.PolynomialMultiplyWideningLower(X3_lo, H3_lo);
            var H4_X4_lo = Aes.PolynomialMultiplyWideningLower(X4_lo, H4_lo);

            var lo = AdvSimd.Xor(
                AdvSimd.Xor(H1_X1_lo, H2_X2_lo),
                AdvSimd.Xor(H3_X3_lo, H4_X4_lo)
            ).AsUInt32();

            var H1_X1_hi = Aes.PolynomialMultiplyWideningLower(X1_hi, H1_hi);
            var H2_X2_hi = Aes.PolynomialMultiplyWideningLower(X2_hi, H2_hi);
            var H3_X3_hi = Aes.PolynomialMultiplyWideningLower(X3_hi, H3_hi);
            var H4_X4_hi = Aes.PolynomialMultiplyWideningLower(X4_hi, H4_hi);

            var hi = AdvSimd.Xor(
                AdvSimd.Xor(H1_X1_hi, H2_X2_hi),
                AdvSimd.Xor(H3_X3_hi, H4_X4_hi)
            ).AsUInt32();

            var T0 =  AdvSimd.Xor(lo, hi).AsUInt32();

            T0 = AdvSimd.Xor(T0, Aes.PolynomialMultiplyWideningLower(X1_hi ^ X1_lo, H1_hi ^ H1_lo).AsUInt32());
            T0 = AdvSimd.Xor(T0, Aes.PolynomialMultiplyWideningLower(X2_hi ^ X2_lo, H2_hi ^ H2_lo).AsUInt32());
            T0 = AdvSimd.Xor(T0, Aes.PolynomialMultiplyWideningLower(X3_hi ^ X3_lo, H3_hi ^ H3_lo).AsUInt32());
            T0 = AdvSimd.Xor(T0, Aes.PolynomialMultiplyWideningLower(X4_hi ^ X4_lo, H4_hi ^ H4_lo).AsUInt32());

            var B0 = AdvSimd.Xor(AdvSimd.ExtractVector128(Vector128<uint>.Zero, T0, 2), hi);
            var B1 = AdvSimd.Xor(AdvSimd.ExtractVector128(T0, Vector128<uint>.Zero, 2), lo);

            return Reduce(B0, B1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> BswapVec(Vector128<byte> v)
        {
            if (AdvSimd.Arm64.IsSupported)
            {
                return AdvSimd.Arm64.VectorTableLookup(v, BswapMask);
            }
            else
            {
                var tmp = AdvSimd.ReverseElement8(v.AsUInt64());
                return Vector128.Create(tmp.GetUpper(), tmp.GetLower()).AsByte();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Bswap64(Vector128<byte> v)
        {
            return AdvSimd.ReverseElement8(v.AsUInt64()).AsByte();
        }
    }
}