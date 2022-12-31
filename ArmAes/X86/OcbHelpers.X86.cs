using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ArmAes;

internal static partial class OcbHelpers
{
    private static class X86
    {
        private static readonly Vector128<int> DoubleMask = Vector128.Create(1, 1, 1, 135);
        private static readonly Vector128<byte> NonceShuffle = Vector128.Create((byte)7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
        private static readonly Vector128<byte> SwapShuffle = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Double(Vector128<byte> b)
        {
            var tmp = Sse2.ShiftRightArithmetic(b.AsInt32(), 31);
            tmp = Sse2.And(tmp, DoubleMask);
            tmp = Sse2.Shuffle(tmp, 0b10_01_00_11);
            tmp ^= Sse2.ShiftLeftLogical(b.AsInt32(), 1);
            return tmp.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce128(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                tmp[0] = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                tmp[0] = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            var idx = (int)(lastNonceByte & 0x3fu); // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt128(ref keySchedule, tmpV).AsUInt64();

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var lShift = Sse2.ConvertScalarToVector128Int32(idx).AsInt64();
            var rShift =  Sse2.ConvertScalarToVector128Int32(64 - idx).AsInt64();
            var rValue = lo = Sse2.ShiftLeftLogical(hi, lShift) ^ Sse2.ShiftRightLogical(lo, rShift);

            if (Ssse3.IsSupported)
            {
                return Ssse3.Shuffle(rValue.AsByte(), NonceShuffle);
            }
            else
            {
                return SwapIfLe(Sse2.Shuffle(rValue.AsInt32(), 0b01_00_11_10).AsByte());
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce192(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                tmp[0] = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                tmp[0] = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            var idx = (int)(lastNonceByte & 0x3fu); // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt192(ref keySchedule, tmpV).AsUInt64();

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var lShift = Sse2.ConvertScalarToVector128Int32(idx).AsInt64();
            var rShift =  Sse2.ConvertScalarToVector128Int32(64 - idx).AsInt64();
            var rValue = lo = Sse2.ShiftLeftLogical(hi, lShift) ^ Sse2.ShiftRightLogical(lo, rShift);

            if (Ssse3.IsSupported)
            {
                return Ssse3.Shuffle(rValue.AsByte(), NonceShuffle);
            }
            else
            {
                return SwapIfLe(Sse2.Shuffle(rValue.AsInt32(), 0b01_00_11_10).AsByte());
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce256(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                tmp[0] = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                tmp[0] = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            var idx = (int)(lastNonceByte & 0x3fu); // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt256(ref keySchedule, tmpV).AsUInt64();

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var lShift = Sse2.ConvertScalarToVector128Int32(idx).AsInt64();
            var rShift =  Sse2.ConvertScalarToVector128Int32(64 - idx).AsInt64();
            var rValue = lo = Sse2.ShiftLeftLogical(hi, lShift) ^ Sse2.ShiftRightLogical(lo, rShift);

            if (Ssse3.IsSupported)
            {
                return Ssse3.Shuffle(rValue.AsByte(), NonceShuffle);
            }
            else
            {
                return SwapIfLe(Sse2.Shuffle(rValue.AsInt32(), 0b01_00_11_10).AsByte());
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> SwapIfLe(Vector128<byte> block)
        {
            if (Ssse3.IsSupported)
            {
                return Ssse3.Shuffle(block, SwapShuffle);
            }
            else
            {
                var a = Sse2.Shuffle(block.AsInt32(), 0b00_01_10_11);
                var b = Sse2.ShuffleHigh(a.AsInt16(), 0b10_11_00_01);
                var c = Sse2.ShuffleLow(b.AsInt16(), 0b10_11_00_01);
                var d = Sse2.ShiftRightLogical(c, 8) ^ Sse2.ShiftLeftLogical(c, 8);
                return d.AsByte();
            }
        }
    }
}