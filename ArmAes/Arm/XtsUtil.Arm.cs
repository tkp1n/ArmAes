using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

public static partial class XtsUtil
{
    private static class Arm
    {
        private static readonly Vector128<sbyte> AlphaMask = Vector128.Create(0x87, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1).AsSByte();
        private static readonly Vector64<byte> AlphaMultiplier = Vector64.Create((long)0x0000000000000086).AsByte();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha(Vector128<byte> input)
        {
            var t1 = AdvSimd.ShiftLeftLogical(input, 1);
            var t2 = AdvSimd.ShiftRightArithmetic(input.AsSByte(), 7);
            t2 = AdvSimd.ExtractVector128(t2, t2, 15);
            t2 = AdvSimd.And(t2, AlphaMask);
            return AdvSimd.Xor(t2.AsByte(), t1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha2(Vector128<byte> input)
        {
            var t1 = AdvSimd.ShiftLeftLogical(input.AsUInt32(), 2);
            var t2 = AdvSimd.ShiftRightLogical(input.AsUInt32(), 30);
            t1 ^= AdvSimd.ExtractVector128(Vector128<uint>.Zero, t2, 3);
            t2 = AdvSimd.ExtractVector128(t2, Vector128<uint>.Zero, 3);
            t2 ^= AdvSimd.ShiftLeftLogical(t2, 7) ^ AdvSimd.ShiftLeftLogical(t2, 2) ^ AdvSimd.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha4(Vector128<byte> input)
        {
            var t1 = AdvSimd.ShiftLeftLogical(input.AsUInt32(), 4);
            var t2 = AdvSimd.ShiftRightLogical(input.AsUInt32(), 28);
            t1 ^= AdvSimd.ExtractVector128(Vector128<uint>.Zero, t2, 3);
            t2 = AdvSimd.ExtractVector128(t2, Vector128<uint>.Zero, 3);
            t2 ^= AdvSimd.ShiftLeftLogical(t2, 7) ^ AdvSimd.ShiftLeftLogical(t2, 2) ^ AdvSimd.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha5(Vector128<byte> input)
        {
            var t1 = AdvSimd.ShiftLeftLogical(input.AsUInt32(), 5);
            var t2 = AdvSimd.ShiftRightLogical(input.AsUInt32(), 27);
            t1 ^= AdvSimd.ExtractVector128(Vector128<uint>.Zero, t2, 3);
            t2 = AdvSimd.ExtractVector128(t2, Vector128<uint>.Zero, 3);
            t2 ^= AdvSimd.ShiftLeftLogical(t2, 7) ^ AdvSimd.ShiftLeftLogical(t2, 2) ^ AdvSimd.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha8(Vector128<byte> input)
        {
            var t1 = AdvSimd.ExtractVector128(input, input, 15);
            var t2 = AdvSimd.PolynomialMultiplyWideningLower(t1.GetLower(), AlphaMultiplier);
            return t1 ^ t2.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Pad(Vector128<byte> lastFull, ref byte lastInSlice, nuint lastSliceLen, ref byte lastOutSlice)
        {
            Span<byte> block = stackalloc byte[Vector128<byte>.Count];
            ref var blockRef = ref MemoryMarshal.GetReference(block);

            Unsafe.CopyBlockUnaligned(ref blockRef, ref lastInSlice, (uint)lastSliceLen);

            var m1 = AdvSimd.ExtractVector128(
                Vector128<byte>.Zero,
                Vector128<byte>.AllBitsSet,
                (byte)(16 - lastSliceLen)
            );
            var m2 = m1 ^ Vector128<byte>.AllBitsSet;
            var r1 = lastFull & m1;
            var r2 = Vector128.LoadUnsafe(ref blockRef) & m2;
            var result = r1 | r2;

            lastFull.StoreUnsafe(ref blockRef);
            Unsafe.CopyBlockUnaligned(ref lastOutSlice, ref blockRef, (uint)lastSliceLen);

            return result;
        }
    }
}