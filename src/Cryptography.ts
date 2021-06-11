interface ICipherInfo {
  iv: Uint8Array;
  key: CryptoKey;
  ciphertext: ArrayBuffer;
}

export default function Cryptography(root: Window = window) {
  return {
    isSupported: !!(root.crypto && root.crypto.subtle),

    algo: {
      name: "AES-CBC",
      length: 256,
    },

    keyUsages: ["encrypt", "decrypt"],

    getMessageEncoding(data: string) {
      const enc = new TextEncoder();
      return enc.encode(data);
    },

    async encryptMessage(data: string): Promise<ICipherInfo> {
      const encoded: Uint8Array = this.getMessageEncoding(data);
      // iv will be needed for decryption
      const key = await (root.crypto.subtle as any).generateKey(
        this.algo,
        true,
        this.keyUsages
      );
      const iv = root.crypto.getRandomValues(new Uint8Array(16));
      return {
        iv,
        key,
        ciphertext: await root.crypto.subtle.encrypt(
          {
            name: "AES-CBC",
            iv,
          },
          key,
          encoded
        ),
      };
    },

    async decryptMessage(cipherInfo: ICipherInfo): Promise<string> {
      const decrypted = await root.crypto.subtle.decrypt(
        {
          name: "AES-CBC",
          iv: cipherInfo.iv,
        },
        cipherInfo.key,
        cipherInfo.ciphertext
      );

      const dec = new TextDecoder();
      return dec.decode(decrypted);
    },

    async cryptoKeyToBase64(key: CryptoKey): Promise<string> {
      const decoded = await root.crypto.subtle.exportKey("raw", key);
      return this.arrayBufferOrUint8ArrayToBase64(decoded);
    },

    async base64ToCryptoKey(base64: string): Promise<CryptoKey> {
      const arrayBuffer = this.base64ToArrayBuffer(base64);
      return await (root.crypto.subtle as any).importKey(
        "raw",
        arrayBuffer,
        this.algo,
        true,
        this.keyUsages
      );
    },

    base64ToArrayBuffer(base64Str: string): ArrayBuffer {
      const binaryString = root.atob(base64Str);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    },

    arrayBufferOrUint8ArrayToBase64(buf: ArrayBuffer | Uint8Array): string {
      const uint8: Uint8Array =
        buf instanceof Uint8Array ? buf : new Uint8Array(buf);
      return root.btoa(String.fromCharCode(...uint8));
    },
  };
}
