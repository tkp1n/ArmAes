using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ArmAes;

public static partial class XtsUtil
{
    private static class X86
    {
        private static readonly Vector128<int> AlphaMask = Vector128.Create(1, 1, 1, 0x87);
        private static readonly Vector128<byte> Rot
            = Vector128.Create((byte)15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);
        private static readonly Vector128<long> Mul = Vector128.Create(0x0000000000000086, 0x0000000000000086);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha(Vector128<byte> input)
        {
            var t1 = Sse2.ShiftLeftLogical(input.AsInt32(), 1);
            var t2 = Sse2.ShiftRightLogical(input.AsInt32(), 31);
            t2 = Sse2.Shuffle(t2, 0b10_01_00_11);
            t2 = Sse2.And(t2, AlphaMask);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha2(Vector128<byte> input)
        {
            var t1 = Sse2.ShiftLeftLogical(input.AsInt32(), 2);
            var t2 = Sse2.ShiftRightLogical(input.AsInt32(), 30);
            t1 ^= Sse2.ShiftLeftLogical(t2, 4);
            t2 = Sse2.ShiftRightLogical(t2, 12);
            t2 ^= Sse2.ShiftLeftLogical(t2, 7) ^ Sse2.ShiftLeftLogical(t2, 2) ^ Sse2.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha4(Vector128<byte> input)
        {
            var t1 = Sse2.ShiftLeftLogical(input.AsInt32(), 4);
            var t2 = Sse2.ShiftRightLogical(input.AsInt32(), 28);
            t1 ^= Sse2.ShiftLeftLogical(t2, 4);
            t2 = Sse2.ShiftRightLogical(t2, 12);
            t2 ^= Sse2.ShiftLeftLogical(t2, 7) ^ Sse2.ShiftLeftLogical(t2, 2) ^ Sse2.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha5(Vector128<byte> input)
        {
            var t1 = Sse2.ShiftLeftLogical(input.AsInt32(), 5);
            var t2 = Sse2.ShiftRightLogical(input.AsInt32(), 27);
            t1 ^= Sse2.ShiftLeftLogical(t2, 4);
            t2 = Sse2.ShiftRightLogical(t2, 12);
            t2 ^= Sse2.ShiftLeftLogical(t2, 7) ^ Sse2.ShiftLeftLogical(t2, 2) ^ Sse2.ShiftLeftLogical(t2, 1);
            return (t1 ^ t2).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> XtsMulAlpha8(Vector128<byte> input)
        {
            var t1 = Ssse3.Shuffle(input, Rot);
            var t2 = Pclmulqdq.CarrylessMultiply(t1.AsInt64(), Mul, 0x00);
            return t1 ^ t2.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Pad(Vector128<byte> lastFull, ref byte lastInSlice, nuint lastSliceLen, ref byte lastOutSlice)
        {
            Span<byte> block = stackalloc byte[Vector128<byte>.Count];
            ref var blockRef = ref MemoryMarshal.GetReference(block);

            Unsafe.CopyBlockUnaligned(ref blockRef, ref lastInSlice, (uint)lastSliceLen);

            var m1 = Sse2.ShiftRightLogical128BitLane(Vector128<byte>.AllBitsSet, (byte)lastSliceLen);
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