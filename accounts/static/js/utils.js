// Helper functions for modular arithmetic
function mod(a, p) {
    const result = a % p;
    return result >= 0n ? result : result + p;
   }
   
   function modInv(a, p) {
    // Fermat's little theorem for prime p
    if (a === 0n) throw new Error("No inverse for 0");
    return powMod(a, p - 2n, p);
   }
   
   function powMod(a, b, p) {
    let res = 1n;
    a = mod(a, p);
    while (b > 0n) {
        if (b % 2n === 1n) res = mod(res * a, p);
        a = mod(a * a, p);
        b = b >> 1n;
    }
    return res;
   }
   
   // Sign determination functions
   function Fpsgn0(x, p) {
    const thresh = (p - 1n) / 2n;
    let sign = 0;
    if (x > thresh) sign = -1;
    else if (x > 0n) sign = 1;
    return sign === 0 ? 1 : sign;
   }
   
   // Byte conversion utilities
   function I2OSP(x, length) {
    if (x < 0n || x >= (1n << (BigInt(length) * 8n))) return null;
    
    const res = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = Number(x & 0xFFn);
        x = x >> 8n;
    }
    return res;
   }
   
   function OS2IP(bytes) {
    let res = 0n;
    for (const byte of bytes) {
        res = (res << 8n) + BigInt(byte);
    }
    return res;
   }
   
   // P-256 curve parameters
   const P256params = {
    Field_Prime: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    Curve_A: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
    Curve_B: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    Curve_Order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    Generator_X: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    Generator_Y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
   };
   
   function EllipticCurve(params) {
    const _p = params.Field_Prime;
    const _a = params.Curve_A;
    const _b = params.Curve_B;
    const _n = params.Curve_Order;
    const _gx = params.Generator_X;
    const _gy = params.Generator_Y;
    
    // Helper functions for point operations
    function _addAffine(x1, y1, x2, y2, p) {
        const lambda = mod((y1 - y2) * modInv(x1 - x2, p), p);
        const x = mod(lambda * lambda - x1 - x2, p);
        const y = mod(lambda * (x1 - x) - y1, p);
        return [x, y];
    }
    
    function _doubleAffine(x1, y1, p) {
        const lambda = mod((3n * x1 * x1 + _a) * modInv(2n * y1, p), p);
        const x = mod(lambda * lambda - 2n * x1, p);
        const y = mod(lambda * (x1 - x) - y1, p);
        return [x, y];
    }
    
    function _rsqrt(x, p) {
        if ((p & 3n) === 3n) {
            const res = powMod(x, (p + 1n) >> 2n, p);
            if (mod(res * res * modInv(x, p), p) !== 1n) return null;
            return res;
        }
        return null;
    }
    
    // Calculate byte size needed for serialization
    const _sizeInBytes = Number((_p.toString(2).length + 7) >> 3);
    
    class Point {
        constructor(x, y) {
            if (x === null) {
                // Point at infinity
                this.infinity = true;
                this.x = 0n;
                this.y = 0n;
            } else {
                this.x = mod(typeof x === 'bigint' ? x : BigInt(x), _p);
                
                if (y === undefined) {
                    // Need to calculate y
                    const ySquared = mod(this.x * this.x * this.x + _a * this.x + _b, _p);
                    const yVal = _rsqrt(ySquared, _p);
                    if (yVal === null) throw new TypeError("Invalid curve point parameters");
                    this.infinity = false;
                    this.y = yVal;
                } else {
                    this.y = mod(typeof y === 'bigint' ? y : BigInt(y), _p);
                    this.infinity = false;
                    
                    // Verify point is on curve
                    if (mod(this.y * this.y, _p) !== 
                        mod(this.x * this.x * this.x + _a * this.x + _b, _p)) {
                        throw new TypeError("Invalid curve point parameters");
                    }
                }
            }
        }
        
        toString() {
            return this.infinity ? "Infinity" : `(${this.x.toString(16)}, ${this.y.toString(16)})`;
        }
        
        toBytes() {
            // ZCash serialization format
            const C_bit = 1, I_bit = Number(this.infinity);
            let S_bit = 0;
            if (!this.infinity) {
                S_bit = (1 + Fpsgn0(this.y, _p)) >> 1;
            }
            
            const m_byte = (C_bit << 7) | (I_bit << 6) | ((S_bit & 1) << 5);
            const x_bytes = this.infinity ? 
                new Uint8Array(_sizeInBytes) : 
                I2OSP(this.x, _sizeInBytes);
            
            const result = new Uint8Array(1 + x_bytes.length);
            result[0] = m_byte;
            result.set(x_bytes, 1);
            return result;
        }
        
        static fromBytes(bytes) {
            if (bytes.length < 1) throw new TypeError("Invalid compressed point format");
            
            const m_byte = bytes[0] & 0xE0;
            const data = bytes.slice(1);
            
            if (m_byte === 0xE0) throw new TypeError("Invalid compressed point format");
            
            if (m_byte & 0x80) {
                if (data.length !== _sizeInBytes) throw new TypeError("Invalid compressed point format");
            } else {
                if (data.length !== (_sizeInBytes * 2)) throw new TypeError("Invalid compressed point format");
            }
            
            if (m_byte & 0x40) {
                // Infinity point
                if (data.some(byte => byte !== 0)) throw new TypeError("Invalid compression of an infinity point");
                return new Point(null);
            } else {
                if (data.length === (_sizeInBytes * 2)) {
                    // Uncompressed format
                    const x = OS2IP(data.slice(0, _sizeInBytes));
                    const y = OS2IP(data.slice(_sizeInBytes));
                    return new Point(x, y);
                } else {
                    // Compressed format
                    const x = OS2IP(data);
                    const ySquared = mod(x * x * x + _a * x + _b, _p);
                    const y = _rsqrt(ySquared, _p);
                    if (y === null) throw new TypeError("Invalid point: not on the curve");
                    
                    const expectedSign = (m_byte & 0x20) !== 0;
                    const actualSign = ((Fpsgn0(y, _p) + 1) >> 1) === 1;
                    
                    return new Point(x, expectedSign === actualSign ? y : mod(-y, _p));
                }
            }
        }
        
        toBase64() {
            return btoa(String.fromCharCode(...this.toBytes()));
        }
        
        static fromBase64(str) {
            const bytes = new Uint8Array([...atob(str)].map(c => c.charCodeAt(0)));
            return Point.fromBytes(bytes);
        }
        
        add(other) {
            if (this.infinity) return other.infinity ? new Point(null) : new Point(other.x, other.y);
            if (other.infinity) return new Point(this.x, this.y);
            
            if (this.x === other.x) {
                if (this.y === other.y) {
                    const [x, y] = _doubleAffine(this.x, this.y, _p);
                    return new Point(x, y);
                } else {
                    return new Point(null); // P + (-P) = infinity
                }
            } else {
                const [x, y] = _addAffine(this.x, this.y, other.x, other.y, _p);
                return new Point(x, y);
            }
        }
        
        neg() {
            return this.infinity ? new Point(null) : new Point(this.x, mod(-this.y, _p));
        }
        
        sub(other) {
            return this.add(other.neg());
        }
        
        equals(other) {
            if (this.infinity || other.infinity) return this.infinity === other.infinity;
            return this.x === other.x && this.y === other.y;
        }
        
        multiply(scalar) {
            if (typeof scalar !== 'bigint' && typeof scalar !== 'number') {
                throw new TypeError("Invalid scalar value for multiplication");
            }
            
            scalar = mod(BigInt(scalar), _n);
            if (scalar < 0n) return this.multiply(-scalar).neg();
            
            let result = new Point(null);
            let current = new Point(this.x, this.y);
            
            while (scalar > 0n) {
                if (scalar & 1n) {
                    result = result.add(current);
                }
                current = current.add(current); // Double
                scalar = scalar >> 1n;
            }
            
            return result;
        }
        
        static async randomPoint() {
            // Use crypto.getRandomValues for secure randomness
            const randomBytes = new Uint8Array(_sizeInBytes);
            crypto.getRandomValues(randomBytes);
            let x = OS2IP(randomBytes) % _p;
            
            let ySquared, y;
            do {
                ySquared = mod(x * x * x + _a * x + _b, _p);
                y = _rsqrt(ySquared, _p);
                if (y === null) x = mod(x + 1n, _p);
            } while (y === null);
            
            return new Point(x, y);
        }
        
        static async randomScalar() {
            const randomBytes = new Uint8Array(_sizeInBytes);
            crypto.getRandomValues(randomBytes);
            return OS2IP(randomBytes) % _n;
        }
        
        static generator() {
            return new Point(_gx, _gy);
        }
    }
    
    // Attach curve parameters to the Point class
    Point.Order = _n;
    Point.Prime = _p;
    
    return Point;
   }
   
   // Create the P-256 curve
   const P256 = EllipticCurve(P256params);
   
   async function encrypt_aes_cbc(message, key) {
       // Générer un vecteur d'initialisation (IV)
       const iv = window.crypto.getRandomValues(new Uint8Array(16)); // AES.block_size = 16 octets
     
       // Encoder le message en UTF-8
       const encoder = new TextEncoder();
       let data = encoder.encode(message);
     
       // Appliquer le padding pour correspondre à la taille du bloc (16 octets)
       const blockSize = 16;
       const paddingLength = blockSize - (data.length % blockSize);
       const paddedData = new Uint8Array(data.length + paddingLength);
       paddedData.set(data);
       paddedData.set(new Uint8Array(paddingLength).fill(paddingLength), data.length);
     
       // Créer un objet AES en mode CBC
       const keyBuffer = await window.crypto.subtle.importKey(
         'raw', 
         key, 
         { name: 'AES-CBC' }, 
         false, 
         ['encrypt']
       );
     
       // Chiffrer le message
       const encryptedMessage = await window.crypto.subtle.encrypt(
         { name: 'AES-CBC', iv: iv },
         keyBuffer,
         paddedData
       );
     
       // Combiner IV et message chiffré
       const encryptedData = new Uint8Array(iv.length + encryptedMessage.byteLength);
       encryptedData.set(iv);
       encryptedData.set(new Uint8Array(encryptedMessage), iv.length);
     
       // Encoder en base64 pour faciliter le stockage/transmission
       return btoa(String.fromCharCode.apply(null, encryptedData));
     }
   
     async function encrypt_aes_cbc_file(data, key) {
       // Générer un vecteur d'initialisation (IV)
       const iv = window.crypto.getRandomValues(new Uint8Array(16)); // AES block size = 16 octets
     
       // Appliquer padding manuel (PKCS#7) pour AES-CBC
       const blockSize = 16;
       const paddingLength = blockSize - (data.length % blockSize);
       const paddedData = new Uint8Array(data.length + paddingLength);
       paddedData.set(data);
       paddedData.set(new Uint8Array(paddingLength).fill(paddingLength), data.length);
     
       // Importer la clé AES
       const keyBuffer = await window.crypto.subtle.importKey(
         'raw', 
         key, 
         { name: 'AES-CBC' }, 
         false, 
         ['encrypt']
       );
     
       // Chiffrer
       const encryptedMessage = await window.crypto.subtle.encrypt(
         { name: 'AES-CBC', iv: iv },
         keyBuffer,
         paddedData
       );
     
       // Combiner IV et message chiffré
       const encryptedData = new Uint8Array(iv.length + encryptedMessage.byteLength);
       encryptedData.set(iv);
       encryptedData.set(new Uint8Array(encryptedMessage), iv.length);
     
       return encryptedData; // Retourner en brut, pas en base64
     }
   async function decrypt_aes_cbc(encryptedBase64, key) {
       // Décoder le base64 en Uint8Array
       const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
     
       // Extraire IV et message chiffré
       const iv = encryptedData.slice(0, 16); // AES.block_size = 16 octets
       const encryptedMessage = encryptedData.slice(16);
     
       // Importer la clé
       const cryptoKey = await crypto.subtle.importKey(
         'raw',
         key,
         { name: 'AES-CBC' },
         false,
         ['decrypt']
       );
     
       // Déchiffrer
       const decryptedBuffer = await crypto.subtle.decrypt(
         { name: 'AES-CBC', iv },
         cryptoKey,
         encryptedMessage
       );
     
       // Enlever le padding (PKCS#7)
       const decryptedArray = new Uint8Array(decryptedBuffer);
       const paddingLength = decryptedArray[decryptedArray.length - 1];
       const unpadded = decryptedArray.slice(0, decryptedArray.length - paddingLength);
     
       // Convertir en texte
       return new TextDecoder().decode(unpadded);
   }
   async function decrypt_aes_cbc_file(encryptedData, key) {
    // Extract IV (first 16 bytes)
    const iv = encryptedData.slice(0, 16);
    
    // Extract actual encrypted data (after IV)
    const ciphertext = encryptedData.slice(16);
    
    // Import the AES key
    const keyBuffer = await window.crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-CBC' },
        false,
        ['decrypt']
    );
    
    // Decrypt the data
    const decryptedData = await window.crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv },
        keyBuffer,
        ciphertext
    );
    
    // Remove PKCS#7 padding
    const decryptedBytes = new Uint8Array(decryptedData);
    const paddingLength = decryptedBytes[decryptedBytes.length - 1];
    const unpaddedData = decryptedBytes.slice(0, decryptedBytes.length - paddingLength);
    
    return unpaddedData;
}
    
   async function chiffrer_msg(message, Pkb_base64,type_message) {
     let c;
     const curve = EllipticCurve(P256params);
     const g = curve.generator();
   
     // Générer une clé AES 256 bits aléatoire
     const k_aes = window.crypto.getRandomValues(new Uint8Array(32));
     const k_int = OS2IP(k_aes);
   
     // k2 = k_int * g
     const k2 = await g.multiply(k_int);
     const k2_bytes = (await k2.toBytes()).slice(0, 32);
     if(type_message === 'text' ){
       c = await encrypt_aes_cbc(message, k2_bytes);
   
     }else{
       c = await encrypt_aes_cbc_file(message, k2_bytes);
   
     }
     // Chiffrer le message avec AES-CBC
     // c2 = k_int * Pkb
     const Pkb = curve.fromBase64(Pkb_base64);
   
   
     const c2_point = await Pkb.multiply(k_int);
     const c2 = c2_point.toBase64();
     return { c, c2 };
   
   }
   
   // Génère une clé AES aléatoire (Uint8Array de 32 octets)
   function generer_k() {
     return window.crypto.getRandomValues(new Uint8Array(32));
   }
   async function generateKeys() {
       const curve = EllipticCurve(P256params);
       const g = curve.generator();
       const S = await curve.randomScalar();
       let Pk = await g.multiply(S);
       Pk = Pk.toBase64();
       const S_bytes = I2OSP(S, 32);
       const S_base64 = btoa(String.fromCharCode(...S_bytes));
   
   
       return { S_base64, Pk };
     }
   
     async function dechiffrer_msg(c, S_b_base64, c2_point_base64,type_message) {
       const curve = EllipticCurve(P256params);
   
       const n = curve.Order;
   
       // Convertir S_b en entier
       const S_b_bytes = Uint8Array.from(atob(S_b_base64), c => c.charCodeAt(0));
       const S_b = BigInt('0x' + [...S_b_bytes].map(x => x.toString(16).padStart(2, '0')).join(''));
     
       // Calculer l'inverse modulo n
       const S_b_inv = modInverse(S_b, n);
     
       // Convertir c2 en point elliptique
       const c2_point = curve.fromBase64(c2_point_base64);
     
       // Multiplier par l'inverse
       const new_k2 = c2_point.multiply(S_b_inv);
       const new_k2_bytes = new_k2.toBytes().slice(0, 32);
       if(type_message === 'text'){
        return await decrypt_aes_cbc(c, new_k2_bytes);

       }else{
        return await decrypt_aes_cbc_file(c, new_k2_bytes);

       }
       // Déchiffrer le message
     }
     
     // Fonction pour calculer l'inverse modulo (BigInt)
     function modInverse(a, m) {
       a = BigInt(a);
       m = BigInt(m);
       let m0 = m, t, q;
       let x0 = 0n, x1 = 1n;
     
       if (m === 1n) return 0n;
     
       while (a > 1n) {
         q = a / m;
         t = m;
         m = a % m;
         a = t;
         t = x0;
         x0 = x1 - q * x0;
         x1 = t;
       }
     
       return x1 < 0n ? x1 + m0 : x1;
     }
   
     function ECDSA(params) {
       class ECDSA {
         static curve = EllipticCurve(P256params);
         static Generator = ECDSA.curve.generator();
         static CurveOrder = params.Curve_Order;
         static sigByteSize = Math.ceil(ECDSA.CurveOrder.toString(2).length / 8);
     
         static async sign(message, secretKeyBase64) {
   
           const S_bytes = Uint8Array.from(atob(secretKeyBase64), c => c.charCodeAt(0));
           const secretKey = BigInt('0x' + [...S_bytes].map(x => x.toString(16).padStart(2, '0')).join(''));
           const kE = await ECDSA.curve.randomScalar(); // Make sure this returns a BigInt
           const R = ECDSA.Generator.multiply(kE);
           const r = mod(R.x, ECDSA.CurveOrder);
           const hashBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message)));
           const hash = BigInt('0x' + [...hashBytes].map(x => x.toString(16).padStart(2, '0')).join('')) % ECDSA.CurveOrder;
           const sig = ((hash + (secretKey * r)) * modInverse(kE, ECDSA.CurveOrder)) % ECDSA.CurveOrder;
     
           const r_bytes = I2OSP(r, ECDSA.sigByteSize);
           const s_bytes = I2OSP(sig, ECDSA.sigByteSize);
           const signature = btoa(String.fromCharCode(...r_bytes, ...s_bytes));
     
           return { signature, hash: hash.toString() };
         }
     
         static async verify(message, signatureBase64, publicKeyBase64) {
           const publicKey = ECDSA.curve.fromBase64(publicKeyBase64);
           const bytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
           const r = OS2IP(bytes.slice(0, ECDSA.sigByteSize));
           const s = OS2IP(bytes.slice(ECDSA.sigByteSize));
           const hashBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message)));
           const hash = BigInt('0x' + [...hashBytes].map(x => x.toString(16).padStart(2, '0')).join('')) % ECDSA.CurveOrder;
           const w = modInverse(s, ECDSA.CurveOrder);
           const u1 = (w * hash) % ECDSA.CurveOrder;
           const u2 = (w * r) % ECDSA.CurveOrder;
           const P1 = ECDSA.Generator.multiply(u1); // u1 * G
           const P2 = publicKey.multiply(u2);       // u2 * publicKey
           const P = P1.add(P2);                   // P1 + P2
           return P.x === r;
         }
       }
       return ECDSA;
   }
   
   async function derivePBKDF2(password, saltBytes) {
       const encoder = new TextEncoder();
       const keyMaterial = await crypto.subtle.importKey(
         "raw",
         encoder.encode(password),
         { name: "PBKDF2" },
         false,
         ["deriveBits"]
       );
   
       const derivedBits = await crypto.subtle.deriveBits(
         {
           name: "PBKDF2",
           salt: saltBytes,
           iterations: 390000,
           hash: "SHA-256"
         },
         keyMaterial,
         256
       );
   
       return new Uint8Array(derivedBits);
     }
   
   function toHex(buffer) {
       return Array.from(buffer)
         .map(b => b.toString(16).padStart(2, "0"))
         .join("");
   }
   
   function generateSalt(length = 16) {
       return crypto.getRandomValues(new Uint8Array(length));
   }
   
   



   function base64ToBytes(base64) {
    try {
        // Decode base64 to binary string
        const binary = atob(base64);
        // Convert binary string to Uint8Array
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch (e) {
        console.error('Base64 decoding error:', e);
        throw new Error('Invalid base64 string');
    }
}

async function decompressData(compressedData) {
    if (!compressedData) throw new Error('No data provided for decompression');
    
    try {
        // Convert to Uint8Array if it isn't already
        const inputData = compressedData instanceof Uint8Array 
            ? compressedData 
            : new Uint8Array(compressedData);
        
        // Decompress using pako
        const decompressed = pako.inflate(inputData);
        
        console.log(`Decompression: ${inputData.length} → ${decompressed.length} bytes`);
        return decompressed;
    } catch (error) {
        console.error('Decompression failed:', error);
        throw new Error('Decompression failed - data may not be compressed');
    }
}
async function compressData(fileData) {
    if (!fileData) return null;

    try {
      const inputData = fileData instanceof Uint8Array ? fileData : new Uint8Array(data);

        // Compress Uint8Array directly
        const compressed = pako.deflate(inputData);
        //const compressed = pako.gzip(fileData);
        console.log('Original size (bytes):', fileData.length);
        console.log('Compressed size (bytes):', compressed.length);

        //// Convert Uint8Array to base64 efficiently
  const binary = compressed.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
  const compressedBase64 = btoa(binary);
  console.log('Base64 size (bytes):', compressedBase64.length);
  return compressed;
    } catch (e) {
        console.error('Compression error:', e);
        throw e;
    }
  }
function analyzeImageData(data) {
    const bytes = new Uint8Array(data);
    console.log("First 16 bytes:", Array.from(bytes.slice(0, 16)).map(b => b.toString(16)));
    
    // Check for common image headers
    const header = bytes.slice(0, 4);
    if (header[0] === 0xFF && header[1] === 0xD8) {
        console.log("JPEG signature found");
    } else if (header[0] === 0x89 && header[1] === 0x50) {
        console.log("PNG signature found");
    } else {
        console.log("Unknown file signature");
    }
}