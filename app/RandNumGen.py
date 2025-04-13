class WELL1024a:
    def __init__(self,seed):
        self.R = 32
        self.M1 = 3
        self.M2 = 24
        self.M3 = 10
        self.MASK = 0xFFFFFFFF
        self.STATE = [s & self.MASK for s in seed]
        self.state_n = 0


    def MAT3POS(self, t, v):
        return v ^ (v >> t)

    def MAT3NEG(self, t, v):
        return v ^ (v << (-t))

    def Identity(self, v):
        return v
    def V0(self):
        return self.STATE[self.state_n]

    def VM1(self):
        return self.STATE[(self.state_n + self.M1) & 0x0000001F]
    def VM2(self):
        return self.STATE[(self.state_n + self.M2) & 0x0000001F]
    def VM3(self):
        return self.STATE[(self.state_n + self.M3) & 0x0000001F]
    def VRm1(self):
        return self.STATE[(self.state_n + 31) & 0x0000001F]
    def newV0(self):
        return self.STATE[(self.state_n + 31) & 0x0000001F]


    def next(self):
        z0 = self.VRm1()
        z1 = self.Identity(self.V0()) ^ self.MAT3POS(8,self.VM1())
        z1 &= self.MASK
        z2 = self.MAT3NEG(-19, self.VM2()) ^ self.MAT3NEG(-14,self.VM3())
        z2 &= self.MASK
        self.STATE[(self.state_n + self.M1) & 0x0000001F] = (z1 ^ z2) & self.MASK
        self.STATE[(self.state_n + 31) & 0x0000001F] = (self.MAT3NEG(-11,z0) ^ self.MAT3NEG(-7,z1) ^ self.MAT3NEG(-13,z2)) & self.MASK
        self.state_n = (self.state_n + 31) & 0x0000001F
        return (self.STATE[self.state_n] * 2.32830643653869628906e-10)


