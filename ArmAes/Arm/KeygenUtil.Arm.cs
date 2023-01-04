using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

internal static partial class KeygenUtil
{
    private static class Arm
    {
        private static readonly Vector128<byte> KeygenShuffle
            = Vector128.Create((byte)0x04, 0x01, 0x0E, 0x0B, 0x01, 0x0E, 0x0B, 0x04, 0x0C, 0x09, 0x06, 0x03, 0x09, 0x06, 0x03, 0x0C);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeygenAssist(Vector128<byte> bytes, byte imm8, byte idx)
        {
            if (AdvSimd.Arm64.IsSupported)
            {
                var temp = KeygenAssist64(bytes, imm8);
                return AdvSimd.DuplicateSelectedScalarToVector128(temp.AsInt32(), idx).AsByte();
            }
            else
            {
                var temp = AdvSimd.DuplicateSelectedScalarToVector128(bytes.AsUInt32(), idx).AsByte();
                return KeygenAssist32(temp, imm8);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeygenAssist2(Vector128<byte> bytes)
        {
            var temp = AdvSimd.DuplicateSelectedScalarToVector128(bytes.AsUInt32(), 3).AsByte();
            return Aes.Encrypt(temp, Vector128<byte>.Zero);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeygenAssist64(Vector128<byte> bytes, byte imm8)
        {
            bytes = Aes.Encrypt(bytes, Vector128<byte>.Zero);
            bytes = AdvSimd.Arm64.VectorTableLookup(bytes, KeygenShuffle);
            return AdvSimd.Xor(bytes.AsUInt32(), Vector128.Create<uint>(imm8)).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeygenAssist32(Vector128<byte> bytes, byte imm8)
        {
            bytes = Aes.Encrypt(bytes, Vector128<byte>.Zero);
            var x3 = bytes.AsUInt32().GetElement(0);
            x3 = uint.RotateRight(x3, 8);
            x3 ^= imm8;
            return Vector128.Create(x3).AsByte();
        }

        #region 128

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes128KeyExp(Vector128<byte> key, byte rcon)
        {
            var temp = KeygenAssist(key, rcon, 3);
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 12));
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 8));
            return AdvSimd.Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncKeygen128(ReadOnlySpan<byte> key, ref byte encKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0
            var tmp = Vector128.LoadUnsafe(ref keyRef);
            tmp.StoreUnsafe(ref encKeySchedule);

            // ENC: 1
            tmp = Aes128KeyExp(tmp, 0x01);
            tmp.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);

            // ENC: 2
            tmp = Aes128KeyExp(tmp, 0x02);
            tmp.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 3
            tmp = Aes128KeyExp(tmp, 0x04);
            tmp.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 4
            tmp = Aes128KeyExp(tmp, 0x08);
            tmp.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);

            // ENC: 5
            tmp = Aes128KeyExp(tmp, 0x10);
            tmp.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 6
            tmp = Aes128KeyExp(tmp, 0x20);
            tmp.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 7
            tmp = Aes128KeyExp(tmp, 0x40);
            tmp.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);

            // ENC: 8
            tmp = Aes128KeyExp(tmp, 0x80);
            tmp.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 9
            tmp = Aes128KeyExp(tmp, 0x1B);
            tmp.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 10
            tmp = Aes128KeyExp(tmp, 0x36);
            tmp.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncDecKeygen128(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0 / DEC: 10
            var tmp = Vector128.LoadUnsafe(ref keyRef);
            tmp.StoreUnsafe(ref encKeySchedule);
            tmp.StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // ENC: 1 / DEC: 9
            tmp = Aes128KeyExp(tmp, 0x01);
            tmp.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 2 / DEC: 8
            tmp = Aes128KeyExp(tmp, 0x02);
            tmp.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 3 / DEC: 7
            tmp = Aes128KeyExp(tmp, 0x04);
            tmp.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // ENC: 4 / DEC: 6
            tmp = Aes128KeyExp(tmp, 0x08);
            tmp.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 5 / DEC: 5
            tmp = Aes128KeyExp(tmp, 0x10);
            tmp.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 6 / DEC: 4
            tmp = Aes128KeyExp(tmp, 0x20);
            tmp.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 4 * BytesPerRoundKey);

            // ENC: 7 / DEC: 3
            tmp = Aes128KeyExp(tmp, 0x40);
            tmp.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 8 / DEC: 2
            tmp = Aes128KeyExp(tmp, 0x80);
            tmp.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 9 / DEC: 1
            tmp = Aes128KeyExp(tmp, 0x1B);
            tmp.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // ENC: 10 / DEC: 0
            tmp = Aes128KeyExp(tmp, 0x36);
            tmp.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);
            tmp.StoreUnsafe(ref decKeySchedule);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void DecKeygen128(ReadOnlySpan<byte> key, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // DEC: 10
            var tmp = Vector128.LoadUnsafe(ref keyRef);
            tmp.StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // DEC: 9
            tmp = Aes128KeyExp(tmp, 0x01);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // DEC: 8
            tmp = Aes128KeyExp(tmp, 0x02);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);

            // DEC: 7
            tmp = Aes128KeyExp(tmp, 0x04);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // DEC: 6
            tmp = Aes128KeyExp(tmp, 0x08);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // DEC: 5
            tmp = Aes128KeyExp(tmp, 0x10);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);

            // DEC: 4
            tmp = Aes128KeyExp(tmp, 0x20);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 4 * BytesPerRoundKey);

            // DEC: 3
            tmp = Aes128KeyExp(tmp, 0x40);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // DEC: 2
            tmp = Aes128KeyExp(tmp, 0x80);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);

            // DEC: 1
            tmp = Aes128KeyExp(tmp, 0x1B);
            Aes.InverseMixColumns(tmp).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // DEC: 0
            tmp = Aes128KeyExp(tmp, 0x36);
            tmp.StoreUnsafe(ref decKeySchedule);
        }

        #endregion

        #region 192

        private static Vector128<byte> ZipLow(Vector128<byte> a, Vector128<byte> b)
        {
            if (AdvSimd.Arm64.IsSupported)
            {
                return AdvSimd.Arm64.ZipLow(a.AsUInt64(), b.AsUInt64()).AsByte();
            }
            else
            {
                return Vector128.Create(a.GetLower(), b.GetLower());
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes192KeyExp(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3, rcon, 1);
            tmp1 = AdvSimd.Xor(tmp1, AdvSimd.ExtractVector128(Vector128<byte>.Zero, tmp1, 8));
            tmp1 = AdvSimd.Xor(tmp1, AdvSimd.ExtractVector128(Vector128<byte>.Zero, tmp1, 12));
            tmp1 = AdvSimd.Xor(tmp1, tmp2);
            tmp2 = AdvSimd.DuplicateSelectedScalarToVector128(tmp1.AsInt32(), 3).AsByte();
            var tmp4 = AdvSimd.Xor(tmp3, AdvSimd.ExtractVector128(Vector128<byte>.Zero, tmp3, 12));
            return AdvSimd.Xor(tmp4, tmp2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncKeygen192(ReadOnlySpan<byte> key, ref byte encKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref encKeySchedule);

            // ENC: 1, 2
            var tmp3 = Vector128.Create(Vector64.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey), Vector64<byte>.Zero);
            var tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x01);
            var tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 3
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            tmp1.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 4, 5
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 6
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            tmp1.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 7, 8
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 9
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            tmp1.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 10, 11
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 11 * BytesPerRoundKey);

            // ENC: 12
            Aes192KeyExp(ref tmp1, tmp4, 0x80);
            tmp1.StoreUnsafe(ref encKeySchedule, 12 * BytesPerRoundKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncDecKeygen192(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0 / DEC: 12
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref encKeySchedule);
            tmp1.StoreUnsafe(ref decKeySchedule, 12 * BytesPerRoundKey);

            // ENC: 1, 2 / DEC: 11, 10
            var tmp3 = Vector128.Create(Vector64.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey), Vector64<byte>.Zero);
            var tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x01);
            var tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 11 * BytesPerRoundKey);

            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // ENC: 3 / DEC: 9
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            tmp1.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 4, 5 / DEC: 8, 7
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // ENC: 6 / DEC: 6
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            tmp1.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 7, 8 / DEC: 5, 4
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 4 * BytesPerRoundKey);

            // ENC: 9 / DEC: 3
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            tmp1.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 10, 11 / DEC: 2, 1
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = ZipLow(tmp3, tmp1);
            tmp2.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 11 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // ENC: 12 / DEC: 0
            Aes192KeyExp(ref tmp1, tmp4, 0x80);
            tmp1.StoreUnsafe(ref encKeySchedule, 12 * BytesPerRoundKey);
            tmp1.StoreUnsafe(ref decKeySchedule);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void DecKeygen192(ReadOnlySpan<byte> key, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // DEC: 12
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref decKeySchedule, 12 * BytesPerRoundKey);

            // DEC: 10, 11
            var tmp3 = Vector128.Create(Vector64.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey), Vector64<byte>.Zero);
            var tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x01);
            var tmp2 = ZipLow(tmp3, tmp1);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 11 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // DEC: 9
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // DEC: 7, 8
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = ZipLow(tmp3, tmp1);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // DEC: 6
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // DEC: 4, 5
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = ZipLow(tmp3, tmp1);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 4 * BytesPerRoundKey);

            // DEC: 3
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // DEC: 1, 2
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = ZipLow(tmp3, tmp1);
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // DEC: 0
            Aes192KeyExp(ref tmp1, tmp4, 0x80);
            tmp1.StoreUnsafe(ref decKeySchedule);
        }

        #endregion

        #region 256

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp1(ref Vector128<byte> key, Vector128<byte> input, byte rcon)
        {
            var temp = KeygenAssist(input, rcon, 3);
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(AdvSimd.DuplicateToVector128((byte)0), key, 12));
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(AdvSimd.DuplicateToVector128((byte)0), key, 8));
            key = AdvSimd.Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp2(ref Vector128<byte> key, Vector128<byte> input)
        {
            var temp = KeygenAssist2(input);
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 12));
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 8));
            key = AdvSimd.Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncKeygen256(ReadOnlySpan<byte> key, ref byte encKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref encKeySchedule);

            // ENC: 1
            var tmp3 = Vector128.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey);
            tmp3.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);

            // ENC: 2
            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            tmp1.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 3
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 4
            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            tmp1.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);

            // ENC: 5
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 6
            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            tmp1.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 7
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);

            // ENC: 8
            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            tmp1.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 9
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 10
            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            tmp1.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);

            // ENC: 11
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 11 * BytesPerRoundKey);

            // ENC: 12
            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            tmp1.StoreUnsafe(ref encKeySchedule, 12 * BytesPerRoundKey);

            // ENC: 13
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 13 * BytesPerRoundKey);

            // ENC: 14
            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            tmp1.StoreUnsafe(ref encKeySchedule, 14 * BytesPerRoundKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void EncDecKeygen256(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // ENC: 0 / DEC: 14
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref encKeySchedule, 0 * BytesPerRoundKey);
            tmp1.StoreUnsafe(ref decKeySchedule, 14 * BytesPerRoundKey);

            // ENC: 1 / DEC: 13
            var tmp3 = Vector128.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey);
            tmp3.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 13 * BytesPerRoundKey);

            // ENC: 2 / DEC: 12
            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            tmp1.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 12 * BytesPerRoundKey);

            // ENC: 3 / DEC: 11
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 11 * BytesPerRoundKey);

            // ENC: 4 / DEC: 10
            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            tmp1.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // ENC: 5 / DEC: 9
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 6 / DEC: 8
            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            tmp1.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 7 / DEC: 7
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // ENC: 8 / DEC: 6
            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            tmp1.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 9 / DEC: 5
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 10 / DEC: 4
            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            tmp1.StoreUnsafe(ref encKeySchedule, 10 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 4  * BytesPerRoundKey);

            // ENC: 11 / DEC: 3
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 11 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 12 / DEC: 2
            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            tmp1.StoreUnsafe(ref encKeySchedule, 12 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 13 / DEC: 1
            Aes256KeyExp2(ref tmp3, tmp1);
            tmp3.StoreUnsafe(ref encKeySchedule, 13 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // ENC: 14 / DEC: 0
            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            tmp1.StoreUnsafe(ref encKeySchedule, 14 * BytesPerRoundKey);
            tmp1.StoreUnsafe(ref decKeySchedule);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void DecKeygen256(ReadOnlySpan<byte> key, ref byte decKeySchedule)
        {
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // DEC: 14
            var tmp1 = Vector128.LoadUnsafe(ref keyRef);
            tmp1.StoreUnsafe(ref decKeySchedule, 14 * BytesPerRoundKey);

            // DEC: 13
            var tmp3 = Vector128.LoadUnsafe(ref keyRef, 1 * BytesPerRoundKey);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 13 * BytesPerRoundKey);

            // DEC: 12
            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 12 * BytesPerRoundKey);

            // DEC: 11
            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 11 * BytesPerRoundKey);

            // DEC: 10
            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // DEC: 9
            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // DEC: 8
            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);

            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // DEC: 6
            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // DEC: 5
            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);

            // DEC: 4
            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 4  * BytesPerRoundKey);

            // DEC: 3
            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // DEC: 2
            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);

            // DEC: 1
            Aes256KeyExp2(ref tmp3, tmp1);
            Aes.InverseMixColumns(tmp3).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // DEC: 0
            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            tmp1.StoreUnsafe(ref decKeySchedule);
        }

        #endregion
    }
}