using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace ArmAes;

internal static partial class AesUtil
{
    private static class Arm
    {
        private static readonly Vector128<byte> KeygenShuffle
            = Vector128.Create((byte)0x04, 0x01, 0x0E, 0x0B, 0x01, 0x0E, 0x0B, 0x04, 0x0C, 0x09, 0x06, 0x03, 0x09, 0x06, 0x03, 0x0C);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> KeygenAssist(Vector128<byte> bytes, byte imm8)
        {
            bytes = Aes.Encrypt(bytes, Vector128<byte>.Zero);
            bytes = AdvSimd.Arm64.VectorTableLookup(bytes, KeygenShuffle);
            return AdvSimd.Xor(bytes.AsUInt32(), Vector128.Create(0u, imm8, 0u, imm8)).AsByte();
        }

        #region 128

        #region KeyGen

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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes128KeyExp(Vector128<byte> key, byte rcon)
        {
            var temp = KeygenAssist(key, rcon);
            temp = AdvSimd.DuplicateSelectedScalarToVector128(temp.AsInt32(), 3).AsByte();
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 12));
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(Vector128<byte>.Zero, key, 8));
            return AdvSimd.Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            // ROUND 0
            ta0 = Aes.Encrypt(ta0, key0);
            ta1 = Aes.Encrypt(ta1, key0);
            ta2 = Aes.Encrypt(ta2, key0);
            ta3 = Aes.Encrypt(ta3, key0);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 9 + 10
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);
            ta0 ^= key10;
            ta1 ^= key10;
            ta2 ^= key10;
            ta3 ^= key10;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt128(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            return block ^ key10;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);

            // ROUND 0
            ta0 = Aes.Decrypt(ta0, key0);
            ta1 = Aes.Decrypt(ta1, key0);
            ta2 = Aes.Decrypt(ta2, key0);
            ta3 = Aes.Decrypt(ta3, key0);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 9 + 10
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);
            ta0 ^= key10;
            ta1 ^= key10;
            ta2 ^= key10;
            ta3 ^= key10;
        }

        #endregion

        #region 192

        #region KeyGen

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes192KeyExp(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3, rcon);
            tmp2 = AdvSimd.DuplicateSelectedScalarToVector128(tmp2.AsInt32(), 1).AsByte();
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
            var tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 1 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 2 * BytesPerRoundKey);

            // ENC: 3
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            tmp1.StoreUnsafe(ref encKeySchedule, 3 * BytesPerRoundKey);

            // ENC: 4, 5
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 4 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 5 * BytesPerRoundKey);

            // ENC: 6
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            tmp1.StoreUnsafe(ref encKeySchedule, 6 * BytesPerRoundKey);

            // ENC: 7, 8
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 7 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            tmp2.StoreUnsafe(ref encKeySchedule, 8 * BytesPerRoundKey);

            // ENC: 9
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            tmp1.StoreUnsafe(ref encKeySchedule, 9 * BytesPerRoundKey);

            // ENC: 10, 11
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
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
            var tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
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
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
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
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
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
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
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
            var tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 11 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 10 * BytesPerRoundKey);

            // DEC: 9
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 9 * BytesPerRoundKey);

            // DEC: 7, 8
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 8 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 7 * BytesPerRoundKey);

            // DEC: 6
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 6 * BytesPerRoundKey);

            // DEC: 4, 5
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 5 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 4 * BytesPerRoundKey);

            // DEC: 3
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            Aes.InverseMixColumns(tmp1).StoreUnsafe(ref decKeySchedule, 3 * BytesPerRoundKey);

            // DEC: 1, 2
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = AdvSimd.Arm64.ZipLow(tmp3.AsUInt64(), tmp1.AsUInt64()).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 2 * BytesPerRoundKey);
            tmp2 = AdvSimd.ExtractVector128(tmp1.AsUInt64(), tmp4.AsUInt64(), 1).AsByte();
            Aes.InverseMixColumns(tmp2).StoreUnsafe(ref decKeySchedule, 1 * BytesPerRoundKey);

            // DEC: 0
            Aes192KeyExp(ref tmp1, tmp4, 0x80);
            tmp1.StoreUnsafe(ref decKeySchedule);
        }

        #endregion

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt192(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            // ROUND 0
            ta0 = Aes.Encrypt(ta0, key0);
            ta1 = Aes.Encrypt(ta1, key0);
            ta2 = Aes.Encrypt(ta2, key0);
            ta3 = Aes.Encrypt(ta3, key0);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);
            ta2 = Aes.Encrypt(ta2, key10);
            ta3 = Aes.Encrypt(ta3, key10);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 11 + 12
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);
            ta2 = Aes.Encrypt(ta2, key11);
            ta3 = Aes.Encrypt(ta3, key11);
            ta0 ^= key12;
            ta1 ^= key12;
            ta2 ^= key12;
            ta3 ^= key12;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt192(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key10);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key11);
            return block ^ key12;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt192(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);

            // ROUND 0
            ta0 = Aes.Decrypt(ta0, key0);
            ta1 = Aes.Decrypt(ta1, key0);
            ta2 = Aes.Decrypt(ta2, key0);
            ta3 = Aes.Decrypt(ta3, key0);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 9
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 10
            ta0 = Aes.Decrypt(ta0, key10);
            ta1 = Aes.Decrypt(ta1, key10);
            ta2 = Aes.Decrypt(ta2, key10);
            ta3 = Aes.Decrypt(ta3, key10);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 11 + 12
            ta0 = Aes.Decrypt(ta0, key11);
            ta1 = Aes.Decrypt(ta1, key11);
            ta2 = Aes.Decrypt(ta2, key11);
            ta3 = Aes.Decrypt(ta3, key11);
            ta0 ^= key12;
            ta1 ^= key12;
            ta2 ^= key12;
            ta3 ^= key12;
        }

        #endregion

        #region 256

        #region KeyGen

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp1(ref Vector128<byte> key, Vector128<byte> input, byte rcon)
        {
            var temp = KeygenAssist(input, rcon);
            temp = AdvSimd.DuplicateSelectedScalarToVector128(temp.AsInt32(), 3).AsByte(); //  Sse2.Shuffle(temp.AsInt32(), 0xAA).AsByte();
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(AdvSimd.DuplicateToVector128((byte)0), key, 12));
            key = AdvSimd.Xor(key, AdvSimd.ExtractVector128(AdvSimd.DuplicateToVector128((byte)0), key, 8));
            key = AdvSimd.Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp2(ref Vector128<byte> key, Vector128<byte> input)
        {
            var temp = Aes.Encrypt(input, Vector128<byte>.Zero);
            temp = AdvSimd.Arm64.VectorTableLookup(temp, KeygenShuffle);
            temp = AdvSimd.DuplicateSelectedScalarToVector128(temp.AsInt32(), 2).AsByte(); //  Sse2.Shuffle(temp.AsInt32(), 0xFF).AsByte();
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            // ROUND 0
            ta0 = Aes.Encrypt(ta0, key0);
            ta1 = Aes.Encrypt(ta1, key0);
            ta2 = Aes.Encrypt(ta2, key0);
            ta3 = Aes.Encrypt(ta3, key0);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Encrypt(ta0, key1);
            ta1 = Aes.Encrypt(ta1, key1);
            ta2 = Aes.Encrypt(ta2, key1);
            ta3 = Aes.Encrypt(ta3, key1);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Encrypt(ta0, key2);
            ta1 = Aes.Encrypt(ta1, key2);
            ta2 = Aes.Encrypt(ta2, key2);
            ta3 = Aes.Encrypt(ta3, key2);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Encrypt(ta0, key3);
            ta1 = Aes.Encrypt(ta1, key3);
            ta2 = Aes.Encrypt(ta2, key3);
            ta3 = Aes.Encrypt(ta3, key3);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Encrypt(ta0, key4);
            ta1 = Aes.Encrypt(ta1, key4);
            ta2 = Aes.Encrypt(ta2, key4);
            ta3 = Aes.Encrypt(ta3, key4);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Encrypt(ta0, key5);
            ta1 = Aes.Encrypt(ta1, key5);
            ta2 = Aes.Encrypt(ta2, key5);
            ta3 = Aes.Encrypt(ta3, key5);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Encrypt(ta0, key6);
            ta1 = Aes.Encrypt(ta1, key6);
            ta2 = Aes.Encrypt(ta2, key6);
            ta3 = Aes.Encrypt(ta3, key6);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Encrypt(ta0, key7);
            ta1 = Aes.Encrypt(ta1, key7);
            ta2 = Aes.Encrypt(ta2, key7);
            ta3 = Aes.Encrypt(ta3, key7);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Encrypt(ta0, key8);
            ta1 = Aes.Encrypt(ta1, key8);
            ta2 = Aes.Encrypt(ta2, key8);
            ta3 = Aes.Encrypt(ta3, key8);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 9
            ta0 = Aes.Encrypt(ta0, key9);
            ta1 = Aes.Encrypt(ta1, key9);
            ta2 = Aes.Encrypt(ta2, key9);
            ta3 = Aes.Encrypt(ta3, key9);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 10
            ta0 = Aes.Encrypt(ta0, key10);
            ta1 = Aes.Encrypt(ta1, key10);
            ta2 = Aes.Encrypt(ta2, key10);
            ta3 = Aes.Encrypt(ta3, key10);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 11
            ta0 = Aes.Encrypt(ta0, key11);
            ta1 = Aes.Encrypt(ta1, key11);
            ta2 = Aes.Encrypt(ta2, key11);
            ta3 = Aes.Encrypt(ta3, key11);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 12
            ta0 = Aes.Encrypt(ta0, key12);
            ta1 = Aes.Encrypt(ta1, key12);
            ta2 = Aes.Encrypt(ta2, key12);
            ta3 = Aes.Encrypt(ta3, key12);
            ta0 = Aes.MixColumns(ta0);
            ta1 = Aes.MixColumns(ta1);
            ta2 = Aes.MixColumns(ta2);
            ta3 = Aes.MixColumns(ta3);

            // ROUND 13 + 14
            ta0 = Aes.Encrypt(ta0, key13);
            ta1 = Aes.Encrypt(ta1, key13);
            ta2 = Aes.Encrypt(ta2, key13);
            ta3 = Aes.Encrypt(ta3, key13);
            ta0 ^= key14;
            ta1 ^= key14;
            ta2 ^= key14;
            ta3 ^= key14;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Encrypt256(ref byte keySchedule, Vector128<byte> input)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            var block = Aes.Encrypt(input, key0);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key1);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key2);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key3);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key4);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key5);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key6);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key7);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key8);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key9);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key10);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key11);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key12);
            block = Aes.MixColumns(block);

            block = Aes.Encrypt(block, key13);
            return block ^ key14;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref byte keySchedule)
        {
            var key0 = Vector128.LoadUnsafe(ref keySchedule);
            var key1 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 1);
            var key2 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 2);
            var key3 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 3);
            var key4 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 4);
            var key5 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 5);
            var key6 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 6);
            var key7 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 7);
            var key8 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 8);
            var key9 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 9);
            var key10 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 10);
            var key11 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 11);
            var key12 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 12);
            var key13 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 13);
            var key14 = Vector128.LoadUnsafe(ref keySchedule, BytesPerRoundKey * 14);

            // ROUND 0
            ta0 = Aes.Decrypt(ta0, key0);
            ta1 = Aes.Decrypt(ta1, key0);
            ta2 = Aes.Decrypt(ta2, key0);
            ta3 = Aes.Decrypt(ta3, key0);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 1
            ta0 = Aes.Decrypt(ta0, key1);
            ta1 = Aes.Decrypt(ta1, key1);
            ta2 = Aes.Decrypt(ta2, key1);
            ta3 = Aes.Decrypt(ta3, key1);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 2
            ta0 = Aes.Decrypt(ta0, key2);
            ta1 = Aes.Decrypt(ta1, key2);
            ta2 = Aes.Decrypt(ta2, key2);
            ta3 = Aes.Decrypt(ta3, key2);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 3
            ta0 = Aes.Decrypt(ta0, key3);
            ta1 = Aes.Decrypt(ta1, key3);
            ta2 = Aes.Decrypt(ta2, key3);
            ta3 = Aes.Decrypt(ta3, key3);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 4
            ta0 = Aes.Decrypt(ta0, key4);
            ta1 = Aes.Decrypt(ta1, key4);
            ta2 = Aes.Decrypt(ta2, key4);
            ta3 = Aes.Decrypt(ta3, key4);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 5
            ta0 = Aes.Decrypt(ta0, key5);
            ta1 = Aes.Decrypt(ta1, key5);
            ta2 = Aes.Decrypt(ta2, key5);
            ta3 = Aes.Decrypt(ta3, key5);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 6
            ta0 = Aes.Decrypt(ta0, key6);
            ta1 = Aes.Decrypt(ta1, key6);
            ta2 = Aes.Decrypt(ta2, key6);
            ta3 = Aes.Decrypt(ta3, key6);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 7
            ta0 = Aes.Decrypt(ta0, key7);
            ta1 = Aes.Decrypt(ta1, key7);
            ta2 = Aes.Decrypt(ta2, key7);
            ta3 = Aes.Decrypt(ta3, key7);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 8
            ta0 = Aes.Decrypt(ta0, key8);
            ta1 = Aes.Decrypt(ta1, key8);
            ta2 = Aes.Decrypt(ta2, key8);
            ta3 = Aes.Decrypt(ta3, key8);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 9
            ta0 = Aes.Decrypt(ta0, key9);
            ta1 = Aes.Decrypt(ta1, key9);
            ta2 = Aes.Decrypt(ta2, key9);
            ta3 = Aes.Decrypt(ta3, key9);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 10
            ta0 = Aes.Decrypt(ta0, key10);
            ta1 = Aes.Decrypt(ta1, key10);
            ta2 = Aes.Decrypt(ta2, key10);
            ta3 = Aes.Decrypt(ta3, key10);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 11
            ta0 = Aes.Decrypt(ta0, key11);
            ta1 = Aes.Decrypt(ta1, key11);
            ta2 = Aes.Decrypt(ta2, key11);
            ta3 = Aes.Decrypt(ta3, key11);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 12
            ta0 = Aes.Decrypt(ta0, key12);
            ta1 = Aes.Decrypt(ta1, key12);
            ta2 = Aes.Decrypt(ta2, key12);
            ta3 = Aes.Decrypt(ta3, key12);
            ta0 = Aes.InverseMixColumns(ta0);
            ta1 = Aes.InverseMixColumns(ta1);
            ta2 = Aes.InverseMixColumns(ta2);
            ta3 = Aes.InverseMixColumns(ta3);

            // ROUND 13 + 14
            ta0 = Aes.Decrypt(ta0, key13);
            ta1 = Aes.Decrypt(ta1, key13);
            ta2 = Aes.Decrypt(ta2, key13);
            ta3 = Aes.Decrypt(ta3, key13);
            ta0 ^= key14;
            ta1 ^= key14;
            ta2 ^= key14;
            ta3 ^= key14;
        }

        #endregion
    }
}