using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

internal static partial class OcbHelpers
{
    private static class Arm
    {
        private static readonly Vector128<sbyte> DoubleMask = Vector128.Create(-121, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        private static readonly Vector128<long> K64 = Vector128.Create(-64, -64);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Double(Vector128<byte> b)
        {
            var tmp = AdvSimd.ShiftRightArithmetic(b.AsSByte(), 7);
            tmp = AdvSimd.And(tmp, DoubleMask);
            tmp = AdvSimd.ExtractVector128(tmp, tmp, 1);
            b = AdvSimd.ShiftLeftLogical(b, 1);
            return tmp.AsByte() ^ b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce128(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            long idx = lastNonceByte & 0x3fu; // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt128(ref keySchedule, tmpV).AsUInt64();
            if (BitConverter.IsLittleEndian)
                ktop = AdvSimd.ReverseElement8(ktop);

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var ls = Vector128.Create(idx);

            var rs = AdvSimd.AddSaturate(K64, ls);
            var rval = (AdvSimd.ShiftLogical(hi, ls) ^ AdvSimd.ShiftLogical(lo, rs));
            if (BitConverter.IsLittleEndian)
                return AdvSimd.ReverseElement8(rval).AsByte();

            return rval.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce192(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            long idx = lastNonceByte & 0x3fu; // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt192(ref keySchedule, tmpV).AsUInt64();
            if (BitConverter.IsLittleEndian)
                ktop = AdvSimd.ReverseElement8(ktop);

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var ls = Vector128.Create(idx);

            var rs = AdvSimd.AddSaturate(K64, ls);
            var rval = (AdvSimd.ShiftLogical(hi, ls) ^ AdvSimd.ShiftLogical(lo, rs));
            if (BitConverter.IsLittleEndian)
                return AdvSimd.ReverseElement8(rval).AsByte();

            return rval.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> GenOffsetFromNonce256(ref byte nonce, ref byte keySchedule, nuint tagLen)
        {
            Span<uint> tmp = stackalloc uint[4];
            ref var tmpRef = ref MemoryMarshal.GetReference(tmp);

            if (BitConverter.IsLittleEndian)
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x01000000 + ((tagLen * 8 % 128) << 1));
            else
                Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 0) = (uint)(0x00000001 + ((tagLen * 8 % 128) << 25));

            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 1) = Unsafe.As<byte, uint>(ref nonce);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 2) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 1);
            Unsafe.Add(ref MemoryMarshal.GetReference(tmp), 3) = Unsafe.Add(ref Unsafe.As<byte, uint>(ref nonce), 2);

            ref var lastNonceByte = ref Unsafe.AddByteOffset(ref nonce, 11);
            long idx = lastNonceByte & 0x3fu; // Get low 6 bits of nonce
            Unsafe.AddByteOffset(ref Unsafe.As<uint, byte>(ref tmpRef), 15) = (byte)(lastNonceByte & 0xc0);  // Zero low 6 bits of nonce

            var tmpV = Vector128.LoadUnsafe(ref tmpRef).AsByte();
            var ktop = AesUtil.Encrypt256(ref keySchedule, tmpV).AsUInt64();
            if (BitConverter.IsLittleEndian)
                ktop = AdvSimd.ReverseElement8(ktop);

            Span<ulong> ktopStr = stackalloc ulong[3];

            ref var ktopRef = ref MemoryMarshal.GetReference(ktopStr);
            ktop.StoreUnsafe(ref ktopRef);
            Unsafe.Add(ref ktopRef, 2) = ktopRef ^ (ktopRef << 8) ^ (Unsafe.Add(ref ktopRef, 1) >> 56);

            var hi = ktop.AsInt64();
            var lo = Vector128.LoadUnsafe(ref ktopRef, 1).AsInt64();
            var ls = Vector128.Create(idx);

            var rs = AdvSimd.AddSaturate(K64, ls);
            var rval = (AdvSimd.ShiftLogical(hi, ls) ^ AdvSimd.ShiftLogical(lo, rs));
            if (BitConverter.IsLittleEndian)
                return AdvSimd.ReverseElement8(rval).AsByte();

            return rval.AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> SwapIfLe(Vector128<byte> block)
        {
            return block;
        }
    }
}