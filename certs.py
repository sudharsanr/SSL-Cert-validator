# OCSP Client implementaion for X509 certificates

from Crypto.Util.asn1 import *
from binascii import hexlify,unhexlify
from Crypto.Hash import SHA256,SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from copy import deepcopy
import requests
import sys

#TODO
#1. Feature - Add support for CRLDP , CRL checking
#2. Fixes :-
    # add support for verification of signature by iss name

class DerGeneralName(DerOctetString):
    def __init__(self, value = b'', implicit = None,explicit= None):
        DerObject.__init__(self, 0x04, value, implicit,explicit=explicit)


class OID:
    SHA1_OID = "1.3.14.3.2.26"
    SHA256_OID = "2.16.840.1.101.3.4.2.1"
    SHA1_RSA_OID = "1.3.14.3.2.29"
    SHA256_RSA_OID = "1.2.840.113549.1.1.11"
    CRLDP_OID = "2.5.29.31"
    AKI_OID = "2.5.29.35"
    AIA_OID = "1.3.6.1.5.5.7.1.1"
    OCSP_OID = "1.3.6.1.5.5.7.48.1"

class X509:
    
    def __init__(self,cert):
        if not isinstance(cert,bytes):
            raise TypeError("Certificate expected in bytes format")
        self.cert = DerSequence().decode(cert)
        self.tbs = DerSequence().decode(deepcopy(self.cert[0]))
        self.issuer = deepcopy(self.tbs[3])
        self.pubkey = DerSequence().decode(deepcopy(self.tbs[6]))
        self.serial = self.tbs[1]
        self._ext = deepcopy(self.tbs[-1])

    def get_issuer(self):          
        return self.issuer

    def get_public_key(self):
        return DerObject().decode(self.pubkey[1]).payload[1:]

    def get_crldp(self):
        ext = self.get_ext()
        if not ext:
            return
        data = ext.get(OID.CRLDP_OID)
        dpname = DerSequence().decode(DerSequence().decode(DerOctetString().decode(data).payload).payload).payload
        dp = DerObject().decode(DerObject().decode(dpname).payload).payload
        if dp[0] == 0x86: # only url is supported
            return DerObject().decode(dp).payload.decode()

    def get_ocsp_url(self):
        ext = self.get_ext()
        if not ext:
            return
        data = ext.get(OID.AIA_OID)
        if data is None:
            raise Exception("AIA information is not present")
        s_ext = DerSequence().decode(DerOctetString().decode(data).payload)
        for i in s_ext:
            res = DerSequence().decode(i)
            if DerObjectId().decode(res[0]).value == OID.OCSP_OID:
                return DerObject().decode(res[1]).payload.decode()

    def get_aki(self):
        ext = self.get_ext()
        if not ext:
            return
        data = ext.get(OID.AKI_OID)
        if data is None:
            raise Exception("AKI information is not present")
        aki = DerSequence().decode(DerOctetString().decode(data).payload).payload
        if aki[0] == 0x80: # only key identifier is supported
            return DerObject().decode(aki).payload

    def get_ext(self):
        if hasattr(self, 'ext'):
            return self.ext        
        if self._ext[0] == 0xa3:
            ext = DerSequence().decode(DerObject().decode(self._ext).payload)
            d = dict()
            for i in range(len(ext)):
                res = DerSequence().decode(ext[i])
                oid = DerObjectId().decode(res[0]).value
                d[oid] = res[1]
            self.ext = d
            return self.ext

class OCSP:
    ocsp_status = ["successful","malformedRequest",
                   "internalError","not used","tryLater","sigRequired",
                   "unauthorized"]

    def __init__(self, issuer,subject):
        if not isinstance(issuer, bytes) or not isinstance(subject,bytes):
            raise TypeError("Issuer and Subject certificate buffer expected")
        self.subject = subject
        self.issuer = issuer

    def get_version(self):
        return DerInteger(0, explicit=0).encode()
    
    def req_name(self,name):
        return DerGeneralName(name.encode(),explicit=1).encode()

    def digest_algorithm_id(self,oid):
        sequence = DerSequence()
        sequence.append(DerObjectId(oid).encode())
        sequence.append(DerNull())
        return sequence.encode()

    def get_hash(self,data,sha1=False):
        if sha1:
            return DerOctetString(SHA1.new(data).digest()).encode()
        return DerOctetString(SHA256.new(data).digest()).encode()

    def request(self,ha,iss,key,sno):
        sequence = DerSequence()
        if ha == 'sha1':
            oid = OID.SHA1_OID
            sha1= True
        else:
            oid = OID.SHA256_OID
            sha1= False
        da = self.digest_algorithm_id(oid)
        iss_hash = self.get_hash(iss,sha1=sha1)
        key_hash = self.get_hash(key,sha1=True)
        if not sha1:
            key_hash = self.get_hash(key,sha1=sha1)
        sequence.append(da)
        sequence.append(iss_hash)
        sequence.append(key_hash)
        sequence.append(sno)
        return DerSequence().append(
                    DerSequence().append(
                    sequence.encode())
                    .encode()).encode()

    def compose(self):
        self.sx509 = X509(self.subject)
        self.ix509 = X509(self.issuer)
        sequence = DerSequence()
        sno = self.sx509.serial
        #sequence.append(self.req_name("sudharsan"))
        sequence.append(
            self.request('sha1',
                        self.sx509.get_issuer(),
                        self.ix509.get_public_key(),
                        sno))
        return DerSequence().append(
            sequence.encode()).encode()

    @classmethod
    def get_cert_status(cls,resp):
        try:
            sequence = DerSequence()
            return cls.ocsp_status[sequence.decode(resp)[0][-1]]
        except Exception as e:
            print ("Response error",e )

    def _verify_pkcs(self,data,digest_alg,signature,certificate=None,key=None,iss=None):
        try:
            if digest_alg == OID.SHA1_RSA_OID:
                hash = SHA1.new(data)
            elif digest_alg == OID.SHA256_RSA_OID:
                hash = SHA256.new(data)
            else:
                raise Exception("Unsupported signature algorithm")

            if not certificate:
               if not key and not iss:
                   raise Exception("Cannot find key/issuer info for signature verification")
               #get certificate info from responder id
               temp = DerSequence().decode(data)
               if temp[0][0] == 0xa1:
                   # find by iss name
                   raise Exception("Mechanism not implemented")
               elif temp[0][0] == 0xa2:
                   # find by key hash
                   keyhash = SHA1.new(key).digest()
                   if keyhash == DerOctetString().decode((DerObject().decode(temp[0]).payload)).payload:
                       pubkey = key
                       print ( "Matching key found")
                   else:
                       raise Exception("Supplied public key cannot be used for verification")
               else:
                   raise Exception("Cannot find certificate info for verification")
            else: 
                pubkey = X509(certificate).get_public_key()

            key = RSA.import_key(pubkey)
            signer = PKCS1_v1_5.new(key)
            result = signer.verify(hash,signature)
            print ( "Result ", result )
            return result
        except Exception as e:
            print("Error during verification ", e)

    @classmethod
    def verify_signature(cls,resp, key = None,iss = None):
        sequence = DerSequence()
        resb = sequence.decode(resp)
        if len(resb) != 2:
            return
        resb = resb[1]
        if resb[0] != 0xa0:
            return
        resp = DerSequence().decode(
            DerOctetString().decode(
            DerSequence().decode(
            DerObject().decode(
            resb).payload)[1]).payload)
        data = resp[0]
        digest_alg = DerObjectId().decode(DerSequence().decode(resp[1])[0]).value
        signature = DerBitString().decode(resp[2]).payload[1:]
        if len(resp) != 4 or resp[3][0] != 0xa0:
            return cls._verify_pkcs(cls,data,digest_alg,signature,key=key,iss=iss)
        cert = DerSequence().decode(DerObject().decode(resp[3]).payload)[0]
        return cls._verify_pkcs(cls,data,digest_alg,signature,cert)

class CRLParse:
    
    def __init__(self,data):
        self.data = data
        self.crl = DerSequence().decode(self.data)
        self.tbscertlist = DerSequence().decode(self.crl[0])
        self.sigalg = DerObjectId().decode(DerSequence().decode(self.crl[1])[0]).value
        self.signature = DerBitString().decode(self.crl[2]).payload[1:]
        if self.tbscertlist[-1][0] == 0xa0:
            self.ext = DerObject().decode(self.tbscertlist[-1]).payload

    def parse(self):
        if hasattr(self,'clist'):
            return self.clist
        index = -1
        if self.tbscertlist[index][0] == 0xa0: index = -2
        revoked_certs = self.tbscertlist[index]
        rc_list = DerSequence().decode(revoked_certs)
        d = {}
        for cinfo in rc_list:
            res = DerSequence().decode(cinfo)
            d[res[0]] = DerObject().decode(res[1]).payload
        self.clist = d
        return self.clist

    def get_cert_status(self,serial):
        if not isinstance(serial,int):
            raise TypeError("Serialno expected in integer format")
        if not hasattr(self,'clist'):
            raise AttributeError("Call parse method")
        if serial in self.clist:
            print ( "Certificate is revoked")
            print ( "Revocation time ",self.clist[serial])
        else:
            print ( "Certificate is valid")

    def _verify(self,caki,saki,isspub,signature,sigalg):
        if not caki or not saki:
            raise Exception("AKI not found")
        if caki != saki:
            raise Exception("AKI mismatch")
        # check sig alg
        if sigalg == OID.SHA1_RSA_OID:
            hash_alg = OID.SHA1_OID
            hash = SHA1.new(self.crl[0])
        elif sigalg == OID.SHA256_RSA_OID:
            hash_alg = OID.SHA256_OID
            hash = SHA256.new(self.crl[0])
        else:
            raise Exception("Unsupported Signature algorithm")
        
        #verify signature by taking pubkey from issuer
        key = RSA.import_key(isspub)
        signer = PKCS1_v1_5.new(key)
        result = signer.verify(hash,signature)
        print ( "Result ", result )
        return result


    def verify_signature(self,subject_aki,iss_pub):
        # get authority key identifier
        # check against one present in issuer
        # if no match return error
        # if match check sig al and then proceeed
        if not hasattr(self, 'ext'):
            raise Exception("CRL Extensions not present")
        ext = DerSequence().decode(self.ext)
        for i in ext:
            res = DerSequence().decode(i)
            if DerObjectId().decode(res[0]).value == OID.AKI_OID:
                aki = DerSequence().decode(DerOctetString().decode(res[1]).payload).payload
                if aki[0] != 0x80: # only key identifier supported
                    raise ("Unsupported Key identifier ")
                return self._verify(DerObject().decode(aki).payload,subject_aki,iss_pub,self.signature,self.sigalg)
        

def verify_crl():
    # sample snippets to verify 
    subject = 'c:/users/sudharsan/desktop/3.cer'
    issuer = 'c:/users/sudharsan/desktop/2.cer'
    crl_response = 'c:/users/sudharsan/desktop/GIAG2.crl'
    sdata = open(subject,'rb').read()
    idata = open(issuer, 'rb').read()

    scert = X509(sdata)
    icert = X509(idata)
    #get crl url from certificate
    scert = X509(sdata)
    url = scert.get_crldp()
    r = requests.get(url)
    result = r.content
    #result = open(crl_response,'rb').read()
    crl = CRLParse(result)
    l = crl.parse()
    crl.get_cert_status(scert.serial)
    crl.verify_signature(scert.get_aki(),icert.get_public_key())

def ocsp_verify():
    # sample snippets to verify 
    subject = 'c:/users/sudharsan/desktop/3.cer'
    issuer = 'c:/users/sudharsan/desktop/2.cer'
    crl_response = 'c:/users/sudharsan/desktop/GIAG2.crl'

    sdata = open(subject,'rb').read()
    idata = open(issuer, 'rb').read()

    scert = X509(sdata)

    #get ocsp url from certificate
    url = scert.get_ocsp_url()
    print (url )
    ocsp = OCSP(idata,sdata)
    data = ocsp.compose()
    header = {'content-type':'application/ocsp-request'}
    r = requests.post(url,headers = header,data = data)
    result = r.content
    print ( "Response",result)
    #result = open(crl_response,'rb').read()
    ocsp.get_cert_status(result)
    #resp, key = None,iss = None):
    ocsp.verify_signature(result,key = ocsp.ix509.get_public_key())


if __name__ == '__main__':
    #verify_crl()
    #ocsp_verify()
