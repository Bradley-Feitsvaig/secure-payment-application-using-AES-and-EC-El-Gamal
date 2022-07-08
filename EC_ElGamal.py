import random
import hashlib
import math

class EC_ElGamal():
    def __init__(self):
        self.p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
        self.order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        #curve configuration
        # y^2 = x^3 + a*x + b = y^2 = x^3 + 7
        self.a = 0
        self.b = 7
        #base point on the curve
        self.G = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]
        self.generate_key()

    def generate_key(self):
        self.private_key = random.randint(1, self.p-1)
        self.public_key = self.applyDoubleAndAddMethod(self.G[0], self.G[1], self.private_key, self.a, self.b, self.p)   

    def msgToPointOnCurve(self,message):
        X=message
        Y=math.sqrt((X**3+self.a*X+self.b)%self.p)
        message_point_onCurve=(int(X),int(Y))
        return message_point_onCurve

    def encrypt(self,publickKeyOther,message):
        plain_coordinates = self.msgToPointOnCurve(message)
        k = random.randint(1, self.p-1)
        c1 = self.applyDoubleAndAddMethod(self.G[0], self.G[1], k, self.a, self.b, self.p)
        c2 = self.applyDoubleAndAddMethod(publickKeyOther[0], publickKeyOther[1],k, self.a, self.b, self.p)
        c2 = self.pointAddition(c2[0], c2[1], plain_coordinates[0], plain_coordinates[1], self.a, self.b, self.p)
        return c1,c2

    def decrypt(self,c1, c2):
        #secret key times c1
        dx, dy = self.applyDoubleAndAddMethod(c1[0], c1[1],self.private_key , self.a, self.b, self.p)
        #-secret key times c1
        dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found
        #c2 + secret key * (-c1)
        decrypted = self.pointAddition(c2[0], c2[1], dx, dy, self.a, self.b, self.p)
        return decrypted
    
    def signMessage(self, message):
        e = hashlib.sha256(message.encode('utf-8')).hexdigest()
        e = int(e, 16)
        while True:
            k = random.randint(1, self.order-1)
            randomPointX, randomPointY = self.applyDoubleAndAddMethod(self.G[0], self.G[1], k,self.a, self.b, self.p)
            r = randomPointX % self.order
            s = e + (r * self.private_key)
            s = s * self.findModularInverse(k, self.order)
            s = s % self.order
            if r != 0 and s != 0:
                break
        return r,s


    def verifySignature(self, message, r, s,Qother):
        e = hashlib.sha256(message.encode('utf-8')).hexdigest()
        e = int(e, 16)
        w = self.findModularInverse(s, self.order)
        u1 = self.applyDoubleAndAddMethod(self.G[0], self.G[1], (e * w) % self.order, self.a, self.b, self.p)
        u2 = self.applyDoubleAndAddMethod(Qother[0], Qother[1], (r * w) % self.order, self.a, self.b, self.p)	
        checkpointX, checkpointY = self.pointAddition(u1[0], u1[1], u2[0],u2[1], self.a, self.b, self.p)
        if(checkpointX == r):
            return "signature is valid"
        else:
            return "signature is invalid"
        
    def findModularInverse(self,a, mod):	
    	while(a < 0):
    		a = a + mod
    	x1 = 1; x2 = 0; x3 = mod
    	y1 = 0; y2 = 1; y3 = a
    	q = int(x3 / y3)
    	t1 = x1 - q*y1
    	t2 = x2 - q*y2
    	t3 = x3 - (q*y3)
    	while(y3 != 1):
    		x1 = y1; x2 = y2; x3 = y3
    		y1 = t1; y2 = t2; y3 = t3
    		q = int(x3 / y3)
    		t1 = x1 - q*y1
    		t2 = x2 - q*y2
    		t3 = x3 - (q*y3)
    	while(y2 < 0):
    		y2 = y2 + mod
    	return y2
    
    def pointAddition(self,x1, y1, x2, y2, a, b, mod):
    	if x1 == x2 and y1 == y2:
    		beta = (3*x1*x1 + a) * (self.findModularInverse(2*y1, mod))
    	else:
    		beta = (y2 - y1)*(self.findModularInverse((x2 - x1), mod))
    	x3 = beta*beta - x1 - x2
    	y3 = beta*(x1 - x3) - y1
    	x3 = x3 % mod
    	y3 = y3 % mod
    	while(x3 < 0):
    		x3 = x3 + mod
    	while(y3 < 0):
    		y3 = y3 + mod
    	return x3, y3
    
    def applyDoubleAndAddMethod(self,x0, y0, k, a, b, mod):
    	x_temp = x0
    	y_temp = y0
    	kAsBinary = bin(k) 
    	kAsBinary = kAsBinary[2:len(kAsBinary)] 
    	for i in range(1, len(kAsBinary)):
    		currentBit = kAsBinary[i: i+1]
    		x_temp, y_temp = self.pointAddition(x_temp, y_temp, x_temp, y_temp, a, b, mod)
    		if currentBit == '1':
    			x_temp, y_temp = self.pointAddition(x_temp, y_temp, x0, y0, a, b, mod)
    	return x_temp, y_temp
