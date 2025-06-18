import base64

from Crypt import CryptHash

sha512t_sum_hex = "ae8faee10e5e7c7edb976772a692fc91b4a67bd5b8647e7953f06d3eea648374"
sha512t_sum_bin = b"\xae\x8f\xae\xe1\x0e^|~\xdb\x97gr\xa6\x92\xfc\x91\xb4\xa6{\xd5\xb8d~yS\xf0m>\xead\x83t"
sha256_sum_hex = "928e0b67a0ab1a71d77d9288b58b8ff03993fb63c392a23065eb0ffe08a77fd2"


class TestCryptBitcoin:

    def testSha(self, site):
        file_path = site.storage.getPath("dbschema.json")
        assert CryptHash.sha512sum(file_path) == sha512t_sum_hex
        assert CryptHash.sha512sum(open(file_path, "rb")) == sha512t_sum_hex
        assert CryptHash.sha512sum(open(file_path, "rb"), format="digest") == sha512t_sum_bin

        assert CryptHash.sha256sum(file_path) == sha256_sum_hex
        assert CryptHash.sha256sum(open(file_path, "rb")) == sha256_sum_hex

        with open(file_path, "rb") as f:
            hash = CryptHash.Sha512t(f.read(100))
            hash.hexdigest() != sha512t_sum_hex
            hash.update(f.read(1024 * 1024))
            assert hash.hexdigest() == sha512t_sum_hex

    def testRandom(self):
        assert len(CryptHash.random(64)) == 64
        assert CryptHash.random() != CryptHash.random()
        assert bytes.fromhex(CryptHash.random(encoding="hex"))
        assert base64.b64decode(CryptHash.random(encoding="base64"))
