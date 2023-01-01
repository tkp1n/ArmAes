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

        #region KeyGen

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
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9 + 10
            block0 = Aes.Encrypt(block0, key9);
            block0 ^= key10;
            block1 = Aes.Encrypt(block1, key9);
            block1 ^= key10;
            block2 = Aes.Encrypt(block2, key9);
            block2 ^= key10;
            block3 = Aes.Encrypt(block3, key9);
            block3 ^= key10;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9 + 10
            block0 = Aes.Decrypt(block0, key9);
            block0 ^= key10;
            block1 = Aes.Decrypt(block1, key9);
            block1 ^= key10;
            block2 = Aes.Decrypt(block2, key9);
            block2 ^= key10;
            block3 = Aes.Decrypt(block3, key9);
            block3 ^= key10;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        #endregion

        #region 192

        #region KeyGen

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
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key9);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key9);
            block3 = Aes.MixColumns(block3);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key10);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key10);
            block3 = Aes.MixColumns(block3);

            // ROUND 11 + 12
            block0 = Aes.Encrypt(block0, key11);
            block0 ^= key12;
            block1 = Aes.Encrypt(block1, key11);
            block1 ^= key12;
            block2 = Aes.Encrypt(block2, key11);
            block2 ^= key12;
            block3 = Aes.Encrypt(block3, key11);
            block3 ^= key12;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key9);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key9);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key9);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key10);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key10);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key10);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 11 + 12
            block0 = Aes.Decrypt(block0, key11);
            block0 ^= key12;
            block1 = Aes.Decrypt(block1, key11);
            block1 ^= key12;
            block2 = Aes.Decrypt(block2, key11);
            block2 ^= key12;
            block3 = Aes.Decrypt(block3, key11);
            block3 ^= key12;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        #endregion

        #region 256

        #region KeyGen

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
            var block0 = Aes.Encrypt(ta0, key0);
            block0 = Aes.MixColumns(block0);
            var block1 = Aes.Encrypt(ta1, key0);
            block1 = Aes.MixColumns(block1);
            var block2 = Aes.Encrypt(ta2, key0);
            block2 = Aes.MixColumns(block2);
            var block3 = Aes.Encrypt(ta3, key0);
            block3 = Aes.MixColumns(block3);

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key1);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key1);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key1);
            block3 = Aes.MixColumns(block3);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key2);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key2);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key2);
            block3 = Aes.MixColumns(block3);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key3);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key3);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key3);
            block3 = Aes.MixColumns(block3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key4);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key4);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key4);
            block3 = Aes.MixColumns(block3);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key5);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key5);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key5);
            block3 = Aes.MixColumns(block3);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key6);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key6);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key6);
            block3 = Aes.MixColumns(block3);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key7);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key7);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key7);
            block3 = Aes.MixColumns(block3);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key8);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key8);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key8);
            block3 = Aes.MixColumns(block3);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key9);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key9);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key9);
            block3 = Aes.MixColumns(block3);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key10);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key10);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key10);
            block3 = Aes.MixColumns(block3);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key11);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key11);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key11);
            block3 = Aes.MixColumns(block3);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block0 = Aes.MixColumns(block0);
            block1 = Aes.Encrypt(block1, key12);
            block1 = Aes.MixColumns(block1);
            block2 = Aes.Encrypt(block2, key12);
            block2 = Aes.MixColumns(block2);
            block3 = Aes.Encrypt(block3, key12);
            block3 = Aes.MixColumns(block3);

            // ROUND 13 + 14
            block0 = Aes.Encrypt(block0, key13);
            block0 ^= key14;
            block1 = Aes.Encrypt(block1, key13);
            block1 ^= key14;
            block2 = Aes.Encrypt(block2, key13);
            block2 ^= key14;
            block3 = Aes.Encrypt(block3, key13);
            block3 ^= key14;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
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
            var block0 = Aes.Decrypt(ta0, key0);
            block0 = Aes.InverseMixColumns(block0);
            var block1 = Aes.Decrypt(ta1, key0);
            block1 = Aes.InverseMixColumns(block1);
            var block2 = Aes.Decrypt(ta2, key0);
            block2 = Aes.InverseMixColumns(block2);
            var block3 = Aes.Decrypt(ta3, key0);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key1);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key1);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key1);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key2);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key2);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key2);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key3);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key3);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key3);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key4);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key4);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key4);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key5);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key5);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key5);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key6);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key6);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key6);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key7);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key7);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key7);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key8);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key8);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key8);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key9);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key9);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key9);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key10);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key10);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key10);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 11
            block0 = Aes.Decrypt(block0, key11);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key11);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key11);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key11);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 12
            block0 = Aes.Decrypt(block0, key12);
            block0 = Aes.InverseMixColumns(block0);
            block1 = Aes.Decrypt(block1, key12);
            block1 = Aes.InverseMixColumns(block1);
            block2 = Aes.Decrypt(block2, key12);
            block2 = Aes.InverseMixColumns(block2);
            block3 = Aes.Decrypt(block3, key12);
            block3 = Aes.InverseMixColumns(block3);

            // ROUND 13 + 14
            block0 = Aes.Decrypt(block0, key13);
            block0 ^= key14;
            block1 = Aes.Decrypt(block1, key13);
            block1 ^= key14;
            block2 = Aes.Decrypt(block2, key13);
            block2 ^= key14;
            block3 = Aes.Decrypt(block3, key13);
            block3 ^= key14;

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        #endregion
    }
}