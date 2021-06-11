import assert from "assert";
import Cryptography from "./Cryptography";
import crypto from "@trust/webcrypto";

const crypt = Cryptography({
  atob: (base64: string) => Buffer.from(base64, "base64").toString("utf-8"),
  btoa: (str: string) => Buffer.from(str, "utf-8").toString("base64"),
  crypto,
} as any);

describe("Cryptography", function () {
  let cipherInfo: any,
    cipherTextBase64: string,
    keyBase64: string,
    ivBase64: string;

  describe("isSupported", function () {
    assert.strictEqual(true, crypt.isSupported);
  });

  describe("#encryptMessage", function () {
    it("should encrypt a string into a cipher object", async function () {
      cipherInfo = await crypt.encryptMessage("abc123");
      assert.strictEqual(true, cipherInfo.ciphertext instanceof ArrayBuffer);
      // assert.strictEqual(true, cipherInfo.key instanceof CryptoKey);
      assert.strictEqual(true, cipherInfo.iv instanceof Uint8Array);
    });
  });

  describe("#cryptoKeyToBase64", function () {
    it("should convert a CryptoKey object into a portable base64 string", async function () {
      keyBase64 = await crypt.cryptoKeyToBase64(cipherInfo.key);
      assert.strictEqual("string", typeof keyBase64);
    });
  });

  describe("#arrayBufferOrUint8ArrayToBase64", function () {
    it("should convert a ArrayBuffer or UInt8Array object into a portable base64 string", function () {
      cipherTextBase64 = crypt.arrayBufferOrUint8ArrayToBase64(
        cipherInfo.ciphertext
      );
      ivBase64 = crypt.arrayBufferOrUint8ArrayToBase64(cipherInfo.iv);
      assert.strictEqual("string", typeof cipherTextBase64);
      assert.strictEqual("string", typeof ivBase64);
    });
  });

  describe("#decryptMessage", function () {
    it("should convert ciphertext into the original plain text", async function () {
      const key = await crypt.base64ToCryptoKey(keyBase64);
      const iv = new Uint8Array(crypt.base64ToArrayBuffer(ivBase64));
      const ciphertext = crypt.base64ToArrayBuffer(cipherTextBase64);

      assert.strictEqual(
        "abc123",
        await crypt.decryptMessage({ key, iv, ciphertext })
      );
    });
  });
});
