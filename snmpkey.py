import hashlib

class snmpkey:
    """This class generates localized snmp keys according to https://www.ietf.org/rfc/rfc2574.txt 
    for use in SNMPv3. Many vendors for reasons known to no one do not offer the option of inputing plain text.
    
    Attributes:
        authkey (hex string): 32 or 40 (md5 or sha) byte authentication key 
        privkey (hex string): first 32 bytes of auth key
        
    Author:
        Preston Taylor 
        preston@yourpreston.com
    """
    def __init__(self, password, engineid, method):
        self.password = password
        self.engineid = engineid
        self.method = method
        if(not method == 'md5' and not method =='sha'):
            raise Exception('method must be sha or md5')
        kuhasher = hashlib.sha1()
        if(method == 'md5'):
            kuhasher = hashlib.md5()
        passwordindex=0
        count = 0
        while (count < 1048576):
            passwordbuffer = ''
            while(passwordbuffer.__len__() < 64):
                passwordbuffer = passwordbuffer + password[passwordindex % password.__len__()]
                passwordindex += 1
            kuhasher.update(passwordbuffer.encode('utf-8'))
            count += 64
        keyku = kuhasher.digest()
        kulhasher = hashlib.sha1()
        if(method == 'md5'):
            kulhasher = hashlib.md5()
        kulhasher.update(keyku)
        kulhasher.update(bytes.fromhex(engineid))
        kulhasher.update(keyku)
        self.authkey = kulhasher.hexdigest()
    @property
    def authkey(self):
        return self.__authkey
    @authkey.setter
    def authkey(self,value):
        self.__authkey = value
    @property
    def privkey(self):
        return self.__authkey[0:32]
    def __str__(self):
        return self.authkey + '\n' + self.privkey

# x = snmpkey('maplesyrup','000000000000000000000002','md5')
# print(x.privkey)
# print(x.authkey)