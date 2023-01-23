using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ArmAes;

internal static partial class AesUtil
{
    private static class X86
    {
        #region 128

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref Vector128<byte> ta4,
            ref Vector128<byte> ta5,
            ref Vector128<byte> ta6,
            ref Vector128<byte> ta7,
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;
            var block4 = ta4 ^ key0;
            var block5 = ta5 ^ key0;
            var block6 = ta6 ^ key0;
            var block7 = ta7 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);
            block2 = Aes.Encrypt(block2, key1);
            block3 = Aes.Encrypt(block3, key1);
            block4 = Aes.Encrypt(block4, key1);
            block5 = Aes.Encrypt(block5, key1);
            block6 = Aes.Encrypt(block6, key1);
            block7 = Aes.Encrypt(block7, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);
            block2 = Aes.Encrypt(block2, key2);
            block3 = Aes.Encrypt(block3, key2);
            block4 = Aes.Encrypt(block4, key2);
            block5 = Aes.Encrypt(block5, key2);
            block6 = Aes.Encrypt(block6, key2);
            block7 = Aes.Encrypt(block7, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);
            block2 = Aes.Encrypt(block2, key3);
            block3 = Aes.Encrypt(block3, key3);
            block4 = Aes.Encrypt(block4, key3);
            block5 = Aes.Encrypt(block5, key3);
            block6 = Aes.Encrypt(block6, key3);
            block7 = Aes.Encrypt(block7, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);
            block2 = Aes.Encrypt(block2, key4);
            block3 = Aes.Encrypt(block3, key4);
            block4 = Aes.Encrypt(block4, key4);
            block5 = Aes.Encrypt(block5, key4);
            block6 = Aes.Encrypt(block6, key4);
            block7 = Aes.Encrypt(block7, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);
            block2 = Aes.Encrypt(block2, key5);
            block3 = Aes.Encrypt(block3, key5);
            block4 = Aes.Encrypt(block4, key5);
            block5 = Aes.Encrypt(block5, key5);
            block6 = Aes.Encrypt(block6, key5);
            block7 = Aes.Encrypt(block7, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);
            block2 = Aes.Encrypt(block2, key6);
            block3 = Aes.Encrypt(block3, key6);
            block4 = Aes.Encrypt(block4, key6);
            block5 = Aes.Encrypt(block5, key6);
            block6 = Aes.Encrypt(block6, key6);
            block7 = Aes.Encrypt(block7, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);
            block2 = Aes.Encrypt(block2, key7);
            block3 = Aes.Encrypt(block3, key7);
            block4 = Aes.Encrypt(block4, key7);
            block5 = Aes.Encrypt(block5, key7);
            block6 = Aes.Encrypt(block6, key7);
            block7 = Aes.Encrypt(block7, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);
            block2 = Aes.Encrypt(block2, key8);
            block3 = Aes.Encrypt(block3, key8);
            block4 = Aes.Encrypt(block4, key8);
            block5 = Aes.Encrypt(block5, key8);
            block6 = Aes.Encrypt(block6, key8);
            block7 = Aes.Encrypt(block7, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);
            block2 = Aes.Encrypt(block2, key9);
            block3 = Aes.Encrypt(block3, key9);
            block4 = Aes.Encrypt(block4, key9);
            block5 = Aes.Encrypt(block5, key9);
            block6 = Aes.Encrypt(block6, key9);
            block7 = Aes.Encrypt(block7, key9);

            // ROUND 10
            block0 = Aes.EncryptLast(block0, key10);
            block1 = Aes.EncryptLast(block1, key10);
            block2 = Aes.EncryptLast(block2, key10);
            block3 = Aes.EncryptLast(block3, key10);
            block4 = Aes.EncryptLast(block4, key10);
            block5 = Aes.EncryptLast(block5, key10);
            block6 = Aes.EncryptLast(block6, key10);
            block7 = Aes.EncryptLast(block7, key10);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
            ta4 = block4;
            ta5 = block5;
            ta6 = block6;
            ta7 = block7;
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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);
            block2 = Aes.Encrypt(block2, key1);
            block3 = Aes.Encrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);
            block2 = Aes.Encrypt(block2, key2);
            block3 = Aes.Encrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);
            block2 = Aes.Encrypt(block2, key3);
            block3 = Aes.Encrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);
            block2 = Aes.Encrypt(block2, key4);
            block3 = Aes.Encrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);
            block2 = Aes.Encrypt(block2, key5);
            block3 = Aes.Encrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);
            block2 = Aes.Encrypt(block2, key6);
            block3 = Aes.Encrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);
            block2 = Aes.Encrypt(block2, key7);
            block3 = Aes.Encrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);
            block2 = Aes.Encrypt(block2, key8);
            block3 = Aes.Encrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);
            block2 = Aes.Encrypt(block2, key9);
            block3 = Aes.Encrypt(block3, key9);

            // ROUND 9
            block0 = Aes.EncryptLast(block0, key10);
            block1 = Aes.EncryptLast(block1, key10);
            block2 = Aes.EncryptLast(block2, key10);
            block3 = Aes.EncryptLast(block3, key10);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);

            // ROUND 9
            block0 = Aes.EncryptLast(block0, key10);
            block1 = Aes.EncryptLast(block1, key10);

            ta0 = block0;
            ta1 = block1;
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

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            return Aes.EncryptLast(block, key10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt128(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref Vector128<byte> ta4,
            ref Vector128<byte> ta5,
            ref Vector128<byte> ta6,
            ref Vector128<byte> ta7,
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;
            var block4 = ta4 ^ key0;
            var block5 = ta5 ^ key0;
            var block6 = ta6 ^ key0;
            var block7 = ta7 ^ key0;

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block1 = Aes.Decrypt(block1, key1);
            block2 = Aes.Decrypt(block2, key1);
            block3 = Aes.Decrypt(block3, key1);
            block4 = Aes.Decrypt(block4, key1);
            block5 = Aes.Decrypt(block5, key1);
            block6 = Aes.Decrypt(block6, key1);
            block7 = Aes.Decrypt(block7, key1);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block1 = Aes.Decrypt(block1, key2);
            block2 = Aes.Decrypt(block2, key2);
            block3 = Aes.Decrypt(block3, key2);
            block4 = Aes.Decrypt(block4, key2);
            block5 = Aes.Decrypt(block5, key2);
            block6 = Aes.Decrypt(block6, key2);
            block7 = Aes.Decrypt(block7, key2);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block1 = Aes.Decrypt(block1, key3);
            block2 = Aes.Decrypt(block2, key3);
            block3 = Aes.Decrypt(block3, key3);
            block4 = Aes.Decrypt(block4, key3);
            block5 = Aes.Decrypt(block5, key3);
            block6 = Aes.Decrypt(block6, key3);
            block7 = Aes.Decrypt(block7, key3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block1 = Aes.Decrypt(block1, key4);
            block2 = Aes.Decrypt(block2, key4);
            block3 = Aes.Decrypt(block3, key4);
            block4 = Aes.Decrypt(block4, key4);
            block5 = Aes.Decrypt(block5, key4);
            block6 = Aes.Decrypt(block6, key4);
            block7 = Aes.Decrypt(block7, key4);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block1 = Aes.Decrypt(block1, key5);
            block2 = Aes.Decrypt(block2, key5);
            block3 = Aes.Decrypt(block3, key5);
            block4 = Aes.Decrypt(block4, key5);
            block5 = Aes.Decrypt(block5, key5);
            block6 = Aes.Decrypt(block6, key5);
            block7 = Aes.Decrypt(block7, key5);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block1 = Aes.Decrypt(block1, key6);
            block2 = Aes.Decrypt(block2, key6);
            block3 = Aes.Decrypt(block3, key6);
            block4 = Aes.Decrypt(block4, key6);
            block5 = Aes.Decrypt(block5, key6);
            block6 = Aes.Decrypt(block6, key6);
            block7 = Aes.Decrypt(block7, key6);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block1 = Aes.Decrypt(block1, key7);
            block2 = Aes.Decrypt(block2, key7);
            block3 = Aes.Decrypt(block3, key7);
            block4 = Aes.Decrypt(block4, key7);
            block5 = Aes.Decrypt(block5, key7);
            block6 = Aes.Decrypt(block6, key7);
            block7 = Aes.Decrypt(block7, key7);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block1 = Aes.Decrypt(block1, key8);
            block2 = Aes.Decrypt(block2, key8);
            block3 = Aes.Decrypt(block3, key8);
            block4 = Aes.Decrypt(block4, key8);
            block5 = Aes.Decrypt(block5, key8);
            block6 = Aes.Decrypt(block6, key8);
            block7 = Aes.Decrypt(block7, key8);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block1 = Aes.Decrypt(block1, key9);
            block2 = Aes.Decrypt(block2, key9);
            block3 = Aes.Decrypt(block3, key9);
            block4 = Aes.Decrypt(block4, key9);
            block5 = Aes.Decrypt(block5, key9);
            block6 = Aes.Decrypt(block6, key9);
            block7 = Aes.Decrypt(block7, key9);

            // ROUND 10
            block0 = Aes.DecryptLast(block0, key10);
            block1 = Aes.DecryptLast(block1, key10);
            block2 = Aes.DecryptLast(block2, key10);
            block3 = Aes.DecryptLast(block3, key10);
            block4 = Aes.DecryptLast(block4, key10);
            block5 = Aes.DecryptLast(block5, key10);
            block6 = Aes.DecryptLast(block6, key10);
            block7 = Aes.DecryptLast(block7, key10);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
            ta4 = block4;
            ta5 = block5;
            ta6 = block6;
            ta7 = block7;
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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block1 = Aes.Decrypt(block1, key1);
            block2 = Aes.Decrypt(block2, key1);
            block3 = Aes.Decrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block1 = Aes.Decrypt(block1, key2);
            block2 = Aes.Decrypt(block2, key2);
            block3 = Aes.Decrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block1 = Aes.Decrypt(block1, key3);
            block2 = Aes.Decrypt(block2, key3);
            block3 = Aes.Decrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block1 = Aes.Decrypt(block1, key4);
            block2 = Aes.Decrypt(block2, key4);
            block3 = Aes.Decrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block1 = Aes.Decrypt(block1, key5);
            block2 = Aes.Decrypt(block2, key5);
            block3 = Aes.Decrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block1 = Aes.Decrypt(block1, key6);
            block2 = Aes.Decrypt(block2, key6);
            block3 = Aes.Decrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block1 = Aes.Decrypt(block1, key7);
            block2 = Aes.Decrypt(block2, key7);
            block3 = Aes.Decrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block1 = Aes.Decrypt(block1, key8);
            block2 = Aes.Decrypt(block2, key8);
            block3 = Aes.Decrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block1 = Aes.Decrypt(block1, key9);
            block2 = Aes.Decrypt(block2, key9);
            block3 = Aes.Decrypt(block3, key9);

            // ROUND 10
            block0 = Aes.DecryptLast(block0, key10);
            block1 = Aes.DecryptLast(block1, key10);
            block2 = Aes.DecryptLast(block2, key10);
            block3 = Aes.DecryptLast(block3, key10);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Decrypt128(ref byte keySchedule, Vector128<byte> input)
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

            var block = input ^ key0;
            block = Aes.Decrypt(block, key1);
            block = Aes.Decrypt(block, key2);
            block = Aes.Decrypt(block, key3);
            block = Aes.Decrypt(block, key4);
            block = Aes.Decrypt(block, key5);
            block = Aes.Decrypt(block, key6);
            block = Aes.Decrypt(block, key7);
            block = Aes.Decrypt(block, key8);
            block = Aes.Decrypt(block, key9);
            return Aes.DecryptLast(block, key10);
        }

        #endregion

        #region 192

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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);
            block2 = Aes.Encrypt(block2, key1);
            block3 = Aes.Encrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);
            block2 = Aes.Encrypt(block2, key2);
            block3 = Aes.Encrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);
            block2 = Aes.Encrypt(block2, key3);
            block3 = Aes.Encrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);
            block2 = Aes.Encrypt(block2, key4);
            block3 = Aes.Encrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);
            block2 = Aes.Encrypt(block2, key5);
            block3 = Aes.Encrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);
            block2 = Aes.Encrypt(block2, key6);
            block3 = Aes.Encrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);
            block2 = Aes.Encrypt(block2, key7);
            block3 = Aes.Encrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);
            block2 = Aes.Encrypt(block2, key8);
            block3 = Aes.Encrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);
            block2 = Aes.Encrypt(block2, key9);
            block3 = Aes.Encrypt(block3, key9);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block1 = Aes.Encrypt(block1, key10);
            block2 = Aes.Encrypt(block2, key10);
            block3 = Aes.Encrypt(block3, key10);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block1 = Aes.Encrypt(block1, key11);
            block2 = Aes.Encrypt(block2, key11);
            block3 = Aes.Encrypt(block3, key11);

            // ROUND 12
            block0 = Aes.EncryptLast(block0, key12);
            block1 = Aes.EncryptLast(block1, key12);
            block2 = Aes.EncryptLast(block2, key12);
            block3 = Aes.EncryptLast(block3, key12);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt192(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block1 = Aes.Encrypt(block1, key10);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block1 = Aes.Encrypt(block1, key11);

            // ROUND 12
            block0 = Aes.EncryptLast(block0, key12);
            block1 = Aes.EncryptLast(block1, key12);

            ta0 = block0;
            ta1 = block1;
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

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            block = Aes.Encrypt(block, key10);
            block = Aes.Encrypt(block, key11);
            return Aes.EncryptLast(block, key12);
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

            // ROUND 0 - whitening
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block1 = Aes.Decrypt(block1, key1);
            block2 = Aes.Decrypt(block2, key1);
            block3 = Aes.Decrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block1 = Aes.Decrypt(block1, key2);
            block2 = Aes.Decrypt(block2, key2);
            block3 = Aes.Decrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block1 = Aes.Decrypt(block1, key3);
            block2 = Aes.Decrypt(block2, key3);
            block3 = Aes.Decrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block1 = Aes.Decrypt(block1, key4);
            block2 = Aes.Decrypt(block2, key4);
            block3 = Aes.Decrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block1 = Aes.Decrypt(block1, key5);
            block2 = Aes.Decrypt(block2, key5);
            block3 = Aes.Decrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block1 = Aes.Decrypt(block1, key6);
            block2 = Aes.Decrypt(block2, key6);
            block3 = Aes.Decrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block1 = Aes.Decrypt(block1, key7);
            block2 = Aes.Decrypt(block2, key7);
            block3 = Aes.Decrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block1 = Aes.Decrypt(block1, key8);
            block2 = Aes.Decrypt(block2, key8);
            block3 = Aes.Decrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block1 = Aes.Decrypt(block1, key9);
            block2 = Aes.Decrypt(block2, key9);
            block3 = Aes.Decrypt(block3, key9);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block1 = Aes.Decrypt(block1, key10);
            block2 = Aes.Decrypt(block2, key10);
            block3 = Aes.Decrypt(block3, key10);

            // ROUND 11
            block0 = Aes.Decrypt(block0, key11);
            block1 = Aes.Decrypt(block1, key11);
            block2 = Aes.Decrypt(block2, key11);
            block3 = Aes.Decrypt(block3, key11);

            // ROUND 12
            block0 = Aes.DecryptLast(block0, key12);
            block1 = Aes.DecryptLast(block1, key12);
            block2 = Aes.DecryptLast(block2, key12);
            block3 = Aes.DecryptLast(block3, key12);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        #endregion

        #region 256

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref Vector128<byte> ta4,
            ref Vector128<byte> ta5,
            ref Vector128<byte> ta6,
            ref Vector128<byte> ta7,
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;
            var block4 = ta4 ^ key0;
            var block5 = ta5 ^ key0;
            var block6 = ta6 ^ key0;
            var block7 = ta7 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);
            block2 = Aes.Encrypt(block2, key1);
            block3 = Aes.Encrypt(block3, key1);
            block4 = Aes.Encrypt(block4, key1);
            block5 = Aes.Encrypt(block5, key1);
            block6 = Aes.Encrypt(block6, key1);
            block7 = Aes.Encrypt(block7, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);
            block2 = Aes.Encrypt(block2, key2);
            block3 = Aes.Encrypt(block3, key2);
            block4 = Aes.Encrypt(block4, key2);
            block5 = Aes.Encrypt(block5, key2);
            block6 = Aes.Encrypt(block6, key2);
            block7 = Aes.Encrypt(block7, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);
            block2 = Aes.Encrypt(block2, key3);
            block3 = Aes.Encrypt(block3, key3);
            block4 = Aes.Encrypt(block4, key3);
            block5 = Aes.Encrypt(block5, key3);
            block6 = Aes.Encrypt(block6, key3);
            block7 = Aes.Encrypt(block7, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);
            block2 = Aes.Encrypt(block2, key4);
            block3 = Aes.Encrypt(block3, key4);
            block4 = Aes.Encrypt(block4, key4);
            block5 = Aes.Encrypt(block5, key4);
            block6 = Aes.Encrypt(block6, key4);
            block7 = Aes.Encrypt(block7, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);
            block2 = Aes.Encrypt(block2, key5);
            block3 = Aes.Encrypt(block3, key5);
            block4 = Aes.Encrypt(block4, key5);
            block5 = Aes.Encrypt(block5, key5);
            block6 = Aes.Encrypt(block6, key5);
            block7 = Aes.Encrypt(block7, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);
            block2 = Aes.Encrypt(block2, key6);
            block3 = Aes.Encrypt(block3, key6);
            block4 = Aes.Encrypt(block4, key6);
            block5 = Aes.Encrypt(block5, key6);
            block6 = Aes.Encrypt(block6, key6);
            block7 = Aes.Encrypt(block7, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);
            block2 = Aes.Encrypt(block2, key7);
            block3 = Aes.Encrypt(block3, key7);
            block4 = Aes.Encrypt(block4, key7);
            block5 = Aes.Encrypt(block5, key7);
            block6 = Aes.Encrypt(block6, key7);
            block7 = Aes.Encrypt(block7, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);
            block2 = Aes.Encrypt(block2, key8);
            block3 = Aes.Encrypt(block3, key8);
            block4 = Aes.Encrypt(block4, key8);
            block5 = Aes.Encrypt(block5, key8);
            block6 = Aes.Encrypt(block6, key8);
            block7 = Aes.Encrypt(block7, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);
            block2 = Aes.Encrypt(block2, key9);
            block3 = Aes.Encrypt(block3, key9);
            block4 = Aes.Encrypt(block4, key9);
            block5 = Aes.Encrypt(block5, key9);
            block6 = Aes.Encrypt(block6, key9);
            block7 = Aes.Encrypt(block7, key9);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block1 = Aes.Encrypt(block1, key10);
            block2 = Aes.Encrypt(block2, key10);
            block3 = Aes.Encrypt(block3, key10);
            block4 = Aes.Encrypt(block4, key10);
            block5 = Aes.Encrypt(block5, key10);
            block6 = Aes.Encrypt(block6, key10);
            block7 = Aes.Encrypt(block7, key10);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block1 = Aes.Encrypt(block1, key11);
            block2 = Aes.Encrypt(block2, key11);
            block3 = Aes.Encrypt(block3, key11);
            block4 = Aes.Encrypt(block4, key11);
            block5 = Aes.Encrypt(block5, key11);
            block6 = Aes.Encrypt(block6, key11);
            block7 = Aes.Encrypt(block7, key11);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block1 = Aes.Encrypt(block1, key12);
            block2 = Aes.Encrypt(block2, key12);
            block3 = Aes.Encrypt(block3, key12);
            block4 = Aes.Encrypt(block4, key12);
            block5 = Aes.Encrypt(block5, key12);
            block6 = Aes.Encrypt(block6, key12);
            block7 = Aes.Encrypt(block7, key12);

            // ROUND 13
            block0 = Aes.Encrypt(block0, key13);
            block1 = Aes.Encrypt(block1, key13);
            block2 = Aes.Encrypt(block2, key13);
            block3 = Aes.Encrypt(block3, key13);
            block4 = Aes.Encrypt(block4, key13);
            block5 = Aes.Encrypt(block5, key13);
            block6 = Aes.Encrypt(block6, key13);
            block7 = Aes.Encrypt(block7, key13);

            // ROUND 14
            block0 = Aes.EncryptLast(block0, key14);
            block1 = Aes.EncryptLast(block1, key14);
            block2 = Aes.EncryptLast(block2, key14);
            block3 = Aes.EncryptLast(block3, key14);
            block4 = Aes.EncryptLast(block4, key14);
            block5 = Aes.EncryptLast(block5, key14);
            block6 = Aes.EncryptLast(block6, key14);
            block7 = Aes.EncryptLast(block7, key14);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
            ta4 = block4;
            ta5 = block5;
            ta6 = block6;
            ta7 = block7;
        }

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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);
            block2 = Aes.Encrypt(block2, key1);
            block3 = Aes.Encrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);
            block2 = Aes.Encrypt(block2, key2);
            block3 = Aes.Encrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);
            block2 = Aes.Encrypt(block2, key3);
            block3 = Aes.Encrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);
            block2 = Aes.Encrypt(block2, key4);
            block3 = Aes.Encrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);
            block2 = Aes.Encrypt(block2, key5);
            block3 = Aes.Encrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);
            block2 = Aes.Encrypt(block2, key6);
            block3 = Aes.Encrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);
            block2 = Aes.Encrypt(block2, key7);
            block3 = Aes.Encrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);
            block2 = Aes.Encrypt(block2, key8);
            block3 = Aes.Encrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);
            block2 = Aes.Encrypt(block2, key9);
            block3 = Aes.Encrypt(block3, key9);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block1 = Aes.Encrypt(block1, key10);
            block2 = Aes.Encrypt(block2, key10);
            block3 = Aes.Encrypt(block3, key10);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block1 = Aes.Encrypt(block1, key11);
            block2 = Aes.Encrypt(block2, key11);
            block3 = Aes.Encrypt(block3, key11);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block1 = Aes.Encrypt(block1, key12);
            block2 = Aes.Encrypt(block2, key12);
            block3 = Aes.Encrypt(block3, key12);

            // ROUND 13
            block0 = Aes.Encrypt(block0, key13);
            block1 = Aes.Encrypt(block1, key13);
            block2 = Aes.Encrypt(block2, key13);
            block3 = Aes.Encrypt(block3, key13);

            // ROUND 14
            block0 = Aes.EncryptLast(block0, key14);
            block1 = Aes.EncryptLast(block1, key14);
            block2 = Aes.EncryptLast(block2, key14);
            block3 = Aes.EncryptLast(block3, key14);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Encrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;

            // ROUND 1
            block0 = Aes.Encrypt(block0, key1);
            block1 = Aes.Encrypt(block1, key1);

            // ROUND 2
            block0 = Aes.Encrypt(block0, key2);
            block1 = Aes.Encrypt(block1, key2);

            // ROUND 3
            block0 = Aes.Encrypt(block0, key3);
            block1 = Aes.Encrypt(block1, key3);

            // ROUND 4
            block0 = Aes.Encrypt(block0, key4);
            block1 = Aes.Encrypt(block1, key4);

            // ROUND 5
            block0 = Aes.Encrypt(block0, key5);
            block1 = Aes.Encrypt(block1, key5);

            // ROUND 6
            block0 = Aes.Encrypt(block0, key6);
            block1 = Aes.Encrypt(block1, key6);

            // ROUND 7
            block0 = Aes.Encrypt(block0, key7);
            block1 = Aes.Encrypt(block1, key7);

            // ROUND 8
            block0 = Aes.Encrypt(block0, key8);
            block1 = Aes.Encrypt(block1, key8);

            // ROUND 9
            block0 = Aes.Encrypt(block0, key9);
            block1 = Aes.Encrypt(block1, key9);

            // ROUND 10
            block0 = Aes.Encrypt(block0, key10);
            block1 = Aes.Encrypt(block1, key10);

            // ROUND 11
            block0 = Aes.Encrypt(block0, key11);
            block1 = Aes.Encrypt(block1, key11);

            // ROUND 12
            block0 = Aes.Encrypt(block0, key12);
            block1 = Aes.Encrypt(block1, key12);

            // ROUND 13
            block0 = Aes.Encrypt(block0, key13);
            block1 = Aes.Encrypt(block1, key13);

            // ROUND 14
            block0 = Aes.EncryptLast(block0, key14);
            block1 = Aes.EncryptLast(block1, key14);

            ta0 = block0;
            ta1 = block1;
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

            var block = input ^ key0;
            block = Aes.Encrypt(block, key1);
            block = Aes.Encrypt(block, key2);
            block = Aes.Encrypt(block, key3);
            block = Aes.Encrypt(block, key4);
            block = Aes.Encrypt(block, key5);
            block = Aes.Encrypt(block, key6);
            block = Aes.Encrypt(block, key7);
            block = Aes.Encrypt(block, key8);
            block = Aes.Encrypt(block, key9);
            block = Aes.Encrypt(block, key10);
            block = Aes.Encrypt(block, key11);
            block = Aes.Encrypt(block, key12);
            block = Aes.Encrypt(block, key13);
            return Aes.EncryptLast(block, key14);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Decrypt256(
            ref Vector128<byte> ta0,
            ref Vector128<byte> ta1,
            ref Vector128<byte> ta2,
            ref Vector128<byte> ta3,
            ref Vector128<byte> ta4,
            ref Vector128<byte> ta5,
            ref Vector128<byte> ta6,
            ref Vector128<byte> ta7,
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;
            var block4 = ta4 ^ key0;
            var block5 = ta5 ^ key0;
            var block6 = ta6 ^ key0;
            var block7 = ta7 ^ key0;

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block1 = Aes.Decrypt(block1, key1);
            block2 = Aes.Decrypt(block2, key1);
            block3 = Aes.Decrypt(block3, key1);
            block4 = Aes.Decrypt(block4, key1);
            block5 = Aes.Decrypt(block5, key1);
            block6 = Aes.Decrypt(block6, key1);
            block7 = Aes.Decrypt(block7, key1);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block1 = Aes.Decrypt(block1, key2);
            block2 = Aes.Decrypt(block2, key2);
            block3 = Aes.Decrypt(block3, key2);
            block4 = Aes.Decrypt(block4, key2);
            block5 = Aes.Decrypt(block5, key2);
            block6 = Aes.Decrypt(block6, key2);
            block7 = Aes.Decrypt(block7, key2);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block1 = Aes.Decrypt(block1, key3);
            block2 = Aes.Decrypt(block2, key3);
            block3 = Aes.Decrypt(block3, key3);
            block4 = Aes.Decrypt(block4, key3);
            block5 = Aes.Decrypt(block5, key3);
            block6 = Aes.Decrypt(block6, key3);
            block7 = Aes.Decrypt(block7, key3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block1 = Aes.Decrypt(block1, key4);
            block2 = Aes.Decrypt(block2, key4);
            block3 = Aes.Decrypt(block3, key4);
            block4 = Aes.Decrypt(block4, key4);
            block5 = Aes.Decrypt(block5, key4);
            block6 = Aes.Decrypt(block6, key4);
            block7 = Aes.Decrypt(block7, key4);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block1 = Aes.Decrypt(block1, key5);
            block2 = Aes.Decrypt(block2, key5);
            block3 = Aes.Decrypt(block3, key5);
            block4 = Aes.Decrypt(block4, key5);
            block5 = Aes.Decrypt(block5, key5);
            block6 = Aes.Decrypt(block6, key5);
            block7 = Aes.Decrypt(block7, key5);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block1 = Aes.Decrypt(block1, key6);
            block2 = Aes.Decrypt(block2, key6);
            block3 = Aes.Decrypt(block3, key6);
            block4 = Aes.Decrypt(block4, key6);
            block5 = Aes.Decrypt(block5, key6);
            block6 = Aes.Decrypt(block6, key6);
            block7 = Aes.Decrypt(block7, key6);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block1 = Aes.Decrypt(block1, key7);
            block2 = Aes.Decrypt(block2, key7);
            block3 = Aes.Decrypt(block3, key7);
            block4 = Aes.Decrypt(block4, key7);
            block5 = Aes.Decrypt(block5, key7);
            block6 = Aes.Decrypt(block6, key7);
            block7 = Aes.Decrypt(block7, key7);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block1 = Aes.Decrypt(block1, key8);
            block2 = Aes.Decrypt(block2, key8);
            block3 = Aes.Decrypt(block3, key8);
            block4 = Aes.Decrypt(block4, key8);
            block5 = Aes.Decrypt(block5, key8);
            block6 = Aes.Decrypt(block6, key8);
            block7 = Aes.Decrypt(block7, key8);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block1 = Aes.Decrypt(block1, key9);
            block2 = Aes.Decrypt(block2, key9);
            block3 = Aes.Decrypt(block3, key9);
            block4 = Aes.Decrypt(block4, key9);
            block5 = Aes.Decrypt(block5, key9);
            block6 = Aes.Decrypt(block6, key9);
            block7 = Aes.Decrypt(block7, key9);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block1 = Aes.Decrypt(block1, key10);
            block2 = Aes.Decrypt(block2, key10);
            block3 = Aes.Decrypt(block3, key10);
            block4 = Aes.Decrypt(block4, key10);
            block5 = Aes.Decrypt(block5, key10);
            block6 = Aes.Decrypt(block6, key10);
            block7 = Aes.Decrypt(block7, key10);

            // ROUND 11
            block0 = Aes.Decrypt(block0, key11);
            block1 = Aes.Decrypt(block1, key11);
            block2 = Aes.Decrypt(block2, key11);
            block3 = Aes.Decrypt(block3, key11);
            block4 = Aes.Decrypt(block4, key11);
            block5 = Aes.Decrypt(block5, key11);
            block6 = Aes.Decrypt(block6, key11);
            block7 = Aes.Decrypt(block7, key11);

            // ROUND 12
            block0 = Aes.Decrypt(block0, key12);
            block1 = Aes.Decrypt(block1, key12);
            block2 = Aes.Decrypt(block2, key12);
            block3 = Aes.Decrypt(block3, key12);
            block4 = Aes.Decrypt(block4, key12);
            block5 = Aes.Decrypt(block5, key12);
            block6 = Aes.Decrypt(block6, key12);
            block7 = Aes.Decrypt(block7, key12);

            // ROUND 13
            block0 = Aes.Decrypt(block0, key13);
            block1 = Aes.Decrypt(block1, key13);
            block2 = Aes.Decrypt(block2, key13);
            block3 = Aes.Decrypt(block3, key13);
            block4 = Aes.Decrypt(block4, key13);
            block5 = Aes.Decrypt(block5, key13);
            block6 = Aes.Decrypt(block6, key13);
            block7 = Aes.Decrypt(block7, key13);

            // ROUND 14
            block0 = Aes.DecryptLast(block0, key14);
            block1 = Aes.DecryptLast(block1, key14);
            block2 = Aes.DecryptLast(block2, key14);
            block3 = Aes.DecryptLast(block3, key14);
            block4 = Aes.DecryptLast(block4, key14);
            block5 = Aes.DecryptLast(block5, key14);
            block6 = Aes.DecryptLast(block6, key14);
            block7 = Aes.DecryptLast(block7, key14);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
            ta4 = block4;
            ta5 = block5;
            ta6 = block6;
            ta7 = block7;
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
            var block0 = ta0 ^ key0;
            var block1 = ta1 ^ key0;
            var block2 = ta2 ^ key0;
            var block3 = ta3 ^ key0;

            // ROUND 1
            block0 = Aes.Decrypt(block0, key1);
            block1 = Aes.Decrypt(block1, key1);
            block2 = Aes.Decrypt(block2, key1);
            block3 = Aes.Decrypt(block3, key1);

            // ROUND 2
            block0 = Aes.Decrypt(block0, key2);
            block1 = Aes.Decrypt(block1, key2);
            block2 = Aes.Decrypt(block2, key2);
            block3 = Aes.Decrypt(block3, key2);

            // ROUND 3
            block0 = Aes.Decrypt(block0, key3);
            block1 = Aes.Decrypt(block1, key3);
            block2 = Aes.Decrypt(block2, key3);
            block3 = Aes.Decrypt(block3, key3);

            // ROUND 4
            block0 = Aes.Decrypt(block0, key4);
            block1 = Aes.Decrypt(block1, key4);
            block2 = Aes.Decrypt(block2, key4);
            block3 = Aes.Decrypt(block3, key4);

            // ROUND 5
            block0 = Aes.Decrypt(block0, key5);
            block1 = Aes.Decrypt(block1, key5);
            block2 = Aes.Decrypt(block2, key5);
            block3 = Aes.Decrypt(block3, key5);

            // ROUND 6
            block0 = Aes.Decrypt(block0, key6);
            block1 = Aes.Decrypt(block1, key6);
            block2 = Aes.Decrypt(block2, key6);
            block3 = Aes.Decrypt(block3, key6);

            // ROUND 7
            block0 = Aes.Decrypt(block0, key7);
            block1 = Aes.Decrypt(block1, key7);
            block2 = Aes.Decrypt(block2, key7);
            block3 = Aes.Decrypt(block3, key7);

            // ROUND 8
            block0 = Aes.Decrypt(block0, key8);
            block1 = Aes.Decrypt(block1, key8);
            block2 = Aes.Decrypt(block2, key8);
            block3 = Aes.Decrypt(block3, key8);

            // ROUND 9
            block0 = Aes.Decrypt(block0, key9);
            block1 = Aes.Decrypt(block1, key9);
            block2 = Aes.Decrypt(block2, key9);
            block3 = Aes.Decrypt(block3, key9);

            // ROUND 10
            block0 = Aes.Decrypt(block0, key10);
            block1 = Aes.Decrypt(block1, key10);
            block2 = Aes.Decrypt(block2, key10);
            block3 = Aes.Decrypt(block3, key10);

            // ROUND 11
            block0 = Aes.Decrypt(block0, key11);
            block1 = Aes.Decrypt(block1, key11);
            block2 = Aes.Decrypt(block2, key11);
            block3 = Aes.Decrypt(block3, key11);

            // ROUND 12
            block0 = Aes.Decrypt(block0, key12);
            block1 = Aes.Decrypt(block1, key12);
            block2 = Aes.Decrypt(block2, key12);
            block3 = Aes.Decrypt(block3, key12);

            // ROUND 13
            block0 = Aes.Decrypt(block0, key13);
            block1 = Aes.Decrypt(block1, key13);
            block2 = Aes.Decrypt(block2, key13);
            block3 = Aes.Decrypt(block3, key13);

            // ROUND 14
            block0 = Aes.DecryptLast(block0, key14);
            block1 = Aes.DecryptLast(block1, key14);
            block2 = Aes.DecryptLast(block2, key14);
            block3 = Aes.DecryptLast(block3, key14);

            ta0 = block0;
            ta1 = block1;
            ta2 = block2;
            ta3 = block3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Decrypt256(ref byte keySchedule, Vector128<byte> input)
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

            var block = input ^ key0;
            block = Aes.Decrypt(block, key1);
            block = Aes.Decrypt(block, key2);
            block = Aes.Decrypt(block, key3);
            block = Aes.Decrypt(block, key4);
            block = Aes.Decrypt(block, key5);
            block = Aes.Decrypt(block, key6);
            block = Aes.Decrypt(block, key7);
            block = Aes.Decrypt(block, key8);
            block = Aes.Decrypt(block, key9);
            block = Aes.Decrypt(block, key10);
            block = Aes.Decrypt(block, key11);
            block = Aes.Decrypt(block, key12);
            block = Aes.Decrypt(block, key13);
            return Aes.DecryptLast(block, key14);
        }

        #endregion
    }
}