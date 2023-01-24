using System.Collections.Generic;
using System.IO;
using Xunit;

namespace ArmAes.Tests;

public class NistXtsTestVectors
{
    public static IEnumerable<object[]> GetTestVectors()
    {
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Directory.GetCurrentDirectory(), "XTSTestVectors"), "*.rsp", SearchOption.AllDirectories))
        {
            var encrypt = true;
            TestSet? testSet = null;
            foreach (var line in File.ReadLines(file))
            {
                if (line.StartsWith("#")) continue;
                if (string.IsNullOrWhiteSpace(line)) continue;

                if (line.StartsWith("[ENCRYPT]"))
                    encrypt = true;
                if (line.StartsWith("[DECRYPT]"))
                    encrypt = false;


                if (line.StartsWith("COUNT"))
                {
                    if (testSet != null) yield return new object[] {testSet};

                    testSet = new TestSet
                    {
                        Name = Path.GetFileName(file).Split(".")[0],
                        Encrypt = encrypt,
                        Count = int.Parse(line.Split(" = ")[1])
                    };
                }

                if (testSet is null) continue;

                if (line.StartsWith("DataUnitLen")) testSet.DataUnitLen = nuint.Parse(line.Split(" = ")[1]);
                if (line.StartsWith("Key")) testSet.Key = line.Split(" = ")[1].ToByteArray();
                if (line.StartsWith("DataUnitSeqNumber")) testSet.DataUnitSeqNumber = long.Parse(line.Split(" = ")[1]);
                if (line.StartsWith("i")) testSet.Iv = line.Split(" = ")[1].ToByteArray();
                if (line.StartsWith("PT")) testSet.Plaintext = line.Split(" = ")[1].ToByteArray();
                if (line.StartsWith("CT")) testSet.Ciphertext = line.Split(" = ")[1].ToByteArray();
            }

            if (testSet != null) yield return new object[] {testSet};
        }
    }

    [SkippableTheory]
    [MemberData(nameof(GetTestVectors))]
    public void TestKatVector(TestSet testSet)
    {
        Skip.If(testSet.DataUnitLen % 8 != 0);

        if (testSet.Encrypt)
        {
            var actualCt = new byte[testSet.Ciphertext?.Length ?? 0];
            var key = new XtsKey(testSet.Key);
            if (testSet.Iv is not null)
            {
                Xts.EncryptXts(testSet.Plaintext, actualCt, testSet.Iv, key, testSet.DataUnitLen / 8);
            }
            else
            {
                Xts.EncryptXts(testSet.Plaintext, actualCt, testSet.DataUnitSeqNumber, key, testSet.DataUnitLen / 8);
            }

            Assert.Equal(testSet.Ciphertext, actualCt);
        }
        else
        {
            var actualPt = new byte[testSet.Plaintext?.Length ?? 0];
            var key = new XtsKey(testSet.Key);
            if (testSet.Iv is not null)
            {
                Xts.DecryptXts(testSet.Ciphertext, actualPt, testSet.Iv, key, testSet.DataUnitLen / 8);
            }
            else
            {
                Xts.DecryptXts(testSet.Ciphertext, actualPt, testSet.DataUnitSeqNumber, key, testSet.DataUnitLen / 8);
            }

            Assert.Equal(testSet.Plaintext, actualPt);
        }
    }

    public class TestSet
    {
        public string Name { get; set; } = default!;
        public bool Encrypt { get; set; }
        public int Count { get; set; }
        public nuint DataUnitLen { get; set; }
        public byte[] Key { get; set; } = default!;
        public long DataUnitSeqNumber { get; set; }
        public byte[]? Iv { get; set; }
        public byte[] Plaintext { get; set; } = default!;
        public byte[] Ciphertext { get; set; } = default!;

        public override string ToString()
        {
            return $"{Name} {(Encrypt ? "enc" : "dec")} {(Iv is not null ? "IV" : "DUSN")} DUL: {DataUnitLen} DL: {Plaintext.Length}";
        }
    }
}
