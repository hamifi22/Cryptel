import gmpy2
import gmpy2 as gmp
import random
from hashlib import sha256
import logging
import base64
from gmpy2 import mpz
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

#---------------------------------------------------------------------------------------------------------------------------------------------------------
#   sgn0 "sign" of x: returns -1 if x is lexically larger than  -x and, else returns 1
#   https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-05#section-4.1
#---------------------------------------------------------------------------------------------------------------------------------------------------------
def FpMsgn0(x,p):
    thresh = (p - 1) // 2
    sign = 0
    for xi in reversed(x._raw):
        if xi > thresh:
            sign = -1 if sign == 0 else sign
        elif xi > 0:
            sign = 1 if sign == 0 else sign
    sign = 1 if sign == 0 else sign
    return sign

def Fpsgn0(x,p):
    thresh = (p - 1) // 2
    sign = 0
    if x > thresh:sign = -1 if sign == 0 else sign
    elif x > 0:sign = 1 if sign == 0 else sign
    sign = 1 if sign == 0 else sign
    return sign
#---------------------------------------------------------------------------------------------------------------------------------------------------------
#   I2OSP converts a nonnegative integer to an octet string of a specified length. RFC 3447, section 4.1 https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
#---------------------------------------------------------------------------------------------------------------------------------------------------------
def I2OSP(x,length):
    if x < 0 or x >= (1 << (length<<3)):return None
    else :
        res=[0]*length
        for i in reversed(range(length)):
            res[i]=x & 0xFF
            x=x>>8
        return bytes(res)
#---------------------------------------------------------------------------------------------------------------------------------------------------------
#   OS2IP converts an octet string to a nonnegative integer. RFC 3447, section 4.2 https://datatracker.ietf.org/doc/html/rfc3447#section-4.2
#---------------------------------------------------------------------------------------------------------------------------------------------------------
def OS2IP(byts):
    res = 0
    for i in byts:res = (res << 8)+i
    return res    

P256params = {
            "Field_Prime":gmp.mpz(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff),
            "Curve_A": gmp.mpz(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc),
            "Curve_B": gmp.mpz(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b),
            "Curve_Order": gmp.mpz(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
            "Generator_X":gmp.mpz(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296),
            "Generator_Y":gmp.mpz(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
            }

    
def  EllipticCurve(params):
    _p  = params["Field_Prime"]
    _a  = params["Curve_A"]
    _b  = params["Curve_B"]   
    _n  = params["Curve_Order"]   
    _gx = params["Generator_X"]
    _gy = params["Generator_Y"]
    

    def _addAffine(x1, y1, x2, y2, p):                  # Two points addition on elliptic curve with respect to affine coordinates scheme
        lamda = ((y1 - y2) * gmp.invert(x1 - x2, p)) % p
        return (x:=((lamda**2) - x1 - x2) % p) , (lamda * (x1 - x) - y1) % p
    
    def _doubleAffine(x1, y1, p):                       # Point doubling on elliptic curve with respect to affine coordinates scheme
        lamda = (3 * (x1**2)+_a) * gmp.invert(2 * y1, p)
        return (x:=((lamda**2) - (2 * x1)) % p) , (lamda * (x1 - x) - y1) % p
    
    def _rsqrt(x,p):
        if p & 3==3:
            res = pow(x,(p+1)>>2,p) 
            if ((res**2) * pow(x, -1 , p )) % p != 1: return None ## check if 'x' is a quadratic Residu modulo p using Euler's Criterion
            else: return res

    class EllipticCurve :
        def __init__(self,x,y=None,dotest=False):           # Class's Constructeur
            if x is None:                                   # If x is None, it represents the point at infinity.             
                self.infinity = True
                self.x, self.y = 0, 0                       #(0, 0), representation of the point at infinity in ECC
            else:
                if y is None:                               #If y is not provided
                    self.x = x % _p if type(x)==gmp.mpz else gmp.mpz(x) % _p    # Compute y of the point based on x using the _rsqrt function.
                    _ = _rsqrt((x**3+x*_a+_b) % _p,_p)
                    if (_ != None) : self.infinity, self.y, self.z = False, _, gmp.mpz(1)
                    else :raise TypeError("Invalide curve point parametres ...")
                else:           # If y is provided, validates the curve parameters and initializes the point.
                                # If y is already an instance of gmp.mpz, then y % _p is calculated directly.
                                # else  converts y into a gmp.mpz object using gmp.mpz(y) and then performs the modulus operation with _p
                    self.x = x % _p if type(x)==gmp.mpz else gmp.mpz(x) % _p
                    self.y = y % _p if type(y)==gmp.mpz else gmp.mpz(y) % _p
                    self.z = gmp.mpz(1)
                    self.infinity = False
                    # checks(x, y) lies on the curve equation y^2 ≡ x^3 + ax + b (mod p). If not, it raises a TypeError
                    if (y**2 % _p != (x**3+x*_a+_b) % _p) : raise TypeError("Invalide curve point parametres ...")
       
        def __str__(self):      # provide string representations of the curve points.
            return "("+str(self.x)+" , "+str(self.y)+")" if not self.infinity else "Infinity"
        __repr__ = __str__  
          
        
        def  tobytes(self):
            #     Point compression/Serialization as described by ZCach serialization format
            #     https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html#name-zcash-serialization-format-
            C_bit, I_bit, S_bit = 1, int(self.infinity), 0 if self.infinity else ((1+Fpsgn0(self.y, _p)) >>1)
            m_byte   = (C_bit << 7) | (I_bit << 6) | (((S_bit + 1) >> 1) << 5)
            x_string = I2OSP(0, _sizeInBytes) if self.infinity else I2OSP(self.x, _sizeInBytes)
            return bytes([m_byte]) + x_string 
        
        def fromBytes(bytearray):
            #     Point de-compression/de-Serialization as described by ZCach serialization format
            #     https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html#name-zcash-serialization-format-
            m_byte= bytearray[0] & 0xE0
            bytearray = bytearray[1:]
            if (m_byte == 0xE0) : raise TypeError("Invalide compressed point format ...") 
            if m_byte & 0x80 != 0 :
                if len(bytearray) != _sizeInBytes : raise TypeError("Invalide compressed point format ...")
            else :
                if len(bytearray) != (_sizeInBytes << 1) : raise TypeError("Invalide compressed point format ...")
            if (m_byte & 0x40 != 0) :
                if (any([e != 0 for e in bytearray])) : raise TypeError("Invalide compression of an infinity point ...")
                else : return EllipticCurve(None)
            else :
                if len(bytearray) == (_sizeInBytes << 1) :
                    x = gmp.mpz(OS2IP(bytearray[:_sizeInBytes]))
                    y = gmp.mpz(OS2IP(bytearray[_sizeInBytes:]))
                    return EllipticCurve(x, y, dotest = True)
                else :
                    x = gmp.mpz(OS2IP(bytearray))
                    y = _rsqrt((x**3 +x*_a+_b) % _p, _p)
                    if y is None : raise TypeError("Invalide point: not in the curve ...")
                    else :
                        if ((Fpsgn0(y,_p) + 1)>>1) == int(m_byte & 0x20 != 0) : return EllipticCurve(x,y)
                        else : return EllipticCurve(x, _p-y)

        def toBase64(self):
         return base64.b64encode(self.tobytes()).decode("ascii")
    
        def fromBase64(str):
         return EllipticCurve.fromBytes(base64.b64decode(str)) 
        
        def __add__(p,q):
            if p.infinity:
                if q.infinity : return EllipticCurve(None)
                else : return EllipticCurve(q.x,q.y)
            else:
                if q.infinity : return p.copy()
                else:
                    if p.x == q.x:
                        if p.y == q.y:return EllipticCurve((res := _doubleAffine(p.x, p.y))[0], res[1])
                        else : return EllipticCurve(None)
                    else : 
                        res =_addAffine(p.x,p.y,q.x,q.y,_p) 
                        return EllipticCurve(res[0],res[1])

        def __neg__(p)  : return EllipticCurve(p.x,-p.y)
        def __sub__(p,q): return p + (-q)               # invoke the __add__ method
        def __eq__(p,q) : return (p.x == q.x) & (p.y == q.y) if not(p.infinity | q.infinity) else (p.infinity == q.infinity)
        def __ne__(p,q) : return (p.infinity != q.infinity) | (p.x != q.x) | (p.y != q.y)
       
        def __rmul__(p,b):
            if (type(b) != int) & (type(b) != gmp.mpz) : raise TypeError("Invalide scalar value for multiplication ...")
            else :           
                if b==2:
                    _res = _doubleAffine(p.x,p.y,_p)
                    return EllipticCurve(_res[0],_res[1])
                else :
                    b=abs(b)
                    mask = (1 << (b.bit_length() - 2))  
                    _res = EllipticCurve(p.x, p.y)
                    while (mask!=0):
                        _res = 2 * _res
                        if (mask & b) != 0: _res = _res + p
                        mask = mask >> 1
                    return _res
       
        def RandomPoint():
            _x = random.randint(0, _p - 1)              # generates a random integer _x as the x coordinate
            _y = _rsqrt(_x**3+_a * _x + _b, _p)         # Computes the y-coordinate 
            while (_y == None):                         # Repeat until a valid point is found
                _x = _x + 1                             # Increments x and revaluate y         
                _y = _rsqrt(_x**3+_a * _x + _b, _p)
            return EllipticCurve(_x,_y)                 # An instance of the EllipticCurve class is created with these coordinates and returned as the random point on the elliptic curve.    

        def RandomScalar(): return random.randint(0, _n - 1)
        def GetGenerator(): return EllipticCurve(_gx,_gy)
       

    
    EllipticCurve.Order = _n
    EllipticCurve.Prime = _p
    _sizeInBytes = (_p.bit_length() // 8)+int(_p.bit_length() % 8 != 0)
    return EllipticCurve  
def generer_k() : return get_random_bytes(32)
           

def encrypt_aes_cbc(message, key):

    # Générer un vecteur d'initialisation (IV)
    iv = get_random_bytes(AES.block_size)

    # Créer un objet AES en mode CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Chiffrer le message
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    # Combiner IV et message chiffré
    encrypted_data = iv + encrypted_message

    # Encoder en base64 pour faciliter le stockage/transmission
    return base64.b64encode(encrypted_data).decode('utf-8')



def decrypt_aes_cbc(encrypted_message, key):

    # Décoder la chaîne base64
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))

    # Extraire l'IV et le message chiffré
    iv = encrypted_data[:AES.block_size]
    encrypted_message = encrypted_data[AES.block_size:]

    # Créer un objet AES en mode CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Déchiffrer le message
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    # Retourner le message déchiffré
    return decrypted_message.decode('utf-8')


def generate_keys():
 curve  = EllipticCurve(P256params)
 g = curve.GetGenerator()
 S = curve.RandomScalar()
 Pk = S * g  
 Pk = Pk.toBase64()
 S = I2OSP(S,32)
 S = base64.b64encode(S).decode("ascii")

 return S, Pk

def chiffrer_msg(message, Pkb):
    curve = EllipticCurve(P256params)
    g = curve.GetGenerator()
    k_aes = generer_k()  # Clé AES 256 bits
    k_int = int.from_bytes(k_aes, byteorder='big')

    k2 = k_int * g  

    k2_byte = k2.tobytes()[:32] 
    c = encrypt_aes_cbc(message, k2_byte)  
 
    Pkb = curve.fromBase64(Pkb)  

    c2 = k_int * Pkb  
    c2 = c2.toBase64()
    return c, c2    

def dechiffrer_msg(c, S_b, c2):
    curve = EllipticCurve(P256params)
    n = curve.Order
    S_bytes = base64.b64decode(S_b)
    S_b = OS2IP(S_bytes) 
    S_b = gmpy2.mpz(S_b)
    Sb_inverse = pow(S_b, -1, n)
    c2_point = curve.fromBase64(c2)
    new_k2 = c2_point.__rmul__(Sb_inverse)
    new_k2_byte = new_k2.tobytes()[:32]  # Utiliser les 32 premiers octets

    m = decrypt_aes_cbc(c, new_k2_byte)  # Déchiffrer avec la clé elliptique

    
    return m  # Retourner le message déchiffré


def ECDSA(params):
    class ECDSA:                   
        
        def Ecdsa_sign(message,secreteKey,format ="int"):
            S_bytes = base64.b64decode(secreteKey)
            secreteKey = OS2IP(S_bytes) 
            print(secreteKey)
            _kE   = ECDSA.Curve.RandomScalar()
            _r    = (_kE * ECDSA.Generator).x   
            _hash = int.from_bytes(sha256(message.encode("utf-8")).digest(), 'big') % _CurveOrder
            secreteKey = gmpy2.mpz(secreteKey)

            _sig  = ((_hash + (secreteKey * _r)) * gmp.invert(_kE,_CurveOrder)) % _CurveOrder 
            signature = base64.b64encode(
                I2OSP(_r, _sigByessize) + I2OSP(_sig, _sigByessize)
                ).decode("ascii")  
            
            return signature, int(_hash) 
           
        def Ecdsa_verify(message,signature,publicKey):
            pk = ECDSA.Curve.fromBase64(publicKey)   
            if type(signature) == str :
                    bytearray = base64.b64decode(signature)  
                    signature = [gmp.mpz(OS2IP(bytearray[:_sigByessize])), gmp.mpz(OS2IP(bytearray[_sigByessize:]))]
            else :
                if type(signature) == bytes:
                    signature = [gmp.mpz(OS2IP(signature[:_sigByessize])), gmp.mpz(OS2IP(signature[_sigByessize:]))]           
            _hash = int.from_bytes(sha256(message.encode("utf-8")).digest(), 'big') % _CurveOrder 
            w     = gmp.invert(signature[1], _CurveOrder)   
            u1    = (w * _hash)        % _CurveOrder
            u2    = (w * signature[0]) % _CurveOrder 
            P     = (u1 * ECDSA.Generator) + (u2 * pk)
            result=P.x == signature[0]
            return  result
    
    ECDSA.Curve     = EllipticCurve(params)
    ECDSA.Generator = ECDSA.Curve.GetGenerator()            
    _CurveOrder     = params["Curve_Order"]
    _sigByessize = (_CurveOrder.bit_length() // 8) + int(_CurveOrder.bit_length() % 8 != 0)
    return ECDSA
