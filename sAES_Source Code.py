sBox = [[0x9,0xD,0x6,0xC],[0x4,0x1,0x2,0xE],[0xA,0x8,0x0,0xF],[0xB,0x5,0x3,0x7]]
InversesBox = [[0xA,0x1,0x6,0xC],[0x5,0x7,0x0,0x4],[0x9,0x8,0x2,0xD],[0xB,0xF,0x3,0xE]]

def toStateMatrix(n):
    l = []
    temp = []
    for i in range(0,4):
        tem = n>>(4*(4-i-1))   #bits shifted to last pos and picked up
        if len(temp)==2:
             l.append(temp.copy())
             temp = []
        temp.append(tem & 0b1111)
    l.append(temp.copy())
    temp = l[0][1]
    l[0][1] = l[1][0]
    l[1][0] = temp

    # print(l)
    # print("___")
    return l.copy()

def toOutput(m):
    temp = m[0][1]
    m[0][1] = m[1][0]
    m[1][0] = temp
    out = 0
    for i in range(0,2):
        for j in range(0,2):
            if i==1:c=2
            else:c=0
            temp = m[i][j]<<(4*(4-j-c-1))     #bits shifted to last pos and picked up
            out+=temp
    #print(hex(out))
    return out

def add_round_key(s1, s2):
    #Simple XOR with the key in rach row and col
    l = []
    for i in range(0,2):
        temp = []
        for j in range(0,2):
            temp.append(s1[i][j] ^ s2[i][j])
        l.append(temp)
    #print(l)
    return l.copy()

def NS(sbox, state):
    # AS the left most bits tell os row value
    # And the right most bits tell us col value
    # Obs the binary values we will observe that writing the Sbox rowwose
    # Will give us an advantage as it will be the value of the index 
    l = []
    for i in range(0,2):
        temp = []
        for j in range(0,2):
            nibble = state[i][j]
            col = nibble & 0b11
            row = (nibble>>2) & 0b11
            temp.append(sbox[col][row])
        l.append(temp)
    #print(l)
    # print("___")
    return l.copy()

def SR(state):
    #As only bottom row elements swap places
    return [[state[0][0], state[0][1]],[state[1][1],state[1][0]]]

def GF(a, b):
    product = 0
    a = a & 0b1111
    b = b & 0b1111
    while a and b:
        if b & 1:
            product ^= a
        a<<=1
        # If a is not in GF(2^4)
        # it is XOR with an irreducible polynomial
        # Irreducable Polynomial is x^4+x^2+1
        if a & (1 << 4):
            a ^= 0b10011
        b >>= 1
    return product

def MC(state):
    l = []
    temp = []
    #print(state)
    temp.append(state[0][0]^GF(4, state[1][0]))
    temp.append(state[0][1]^GF(4, state[1][1]))
    l.append(temp.copy())
    temp = []
    temp.append(state[1][0]^GF(4, state[0][0]))
    temp.append(state[1][1]^GF(4, state[0][1]))
    l.append(temp.copy())
    #print(l)
    return l.copy()

def IMC(state):
    l = []
    temp = []
    #print(state)
    temp.append(GF(9,state[0][0])^GF(2,state[1][0]))
    temp.append(GF(9,state[0][1])^GF(2,state[1][1]))
    l.append(temp.copy())
    temp = []
    temp.append(GF(9,state[1][0])^GF(2,state[0][0]))
    temp.append(GF(9,state[1][1])^GF(2,state[0][1]))
    l.append(temp.copy())
    #print(l)
    return l.copy()


def RotNib(word):
    # RotNib() is “rotate the nibbles”, which is equivalent to swapping the nibbles
    return ((word & 0b1111) << 4) + ((word >> 4) & 0b1111)

def SubNib(word):
    N0 = word >> 4
    n0r = (N0>>2)& 0b11
    n0c = N0 & 0b11
    n1r = (word>>2)& 0b11
    n1c = word & 0b11
    N0_= sBox[n0c][n0r]
    N1_= sBox[n1c][n1r]
    return (N1_<< 4 + N0_)

def g(w,Rcon):
    return (SubNib(RotNib(w)) ^ Rcon)

def key_expansion(key):
    Rcon= [0b10000000,0b00110000]
    w = []
    w.append((key >> 8) & 0b11111111)
    w.append(key & 0b11111111)
    w.append(w[0] ^ g(w[1],Rcon[0]))
    w.append(w[2] ^ w[1])
    w.append(w[2] ^ g(w[3],Rcon[1]))
    w.append(w[4] ^ w[3])

    l = [toStateMatrix((w[0] << 8) + w[1]),toStateMatrix((w[2] << 8) + w[3]),toStateMatrix((w[4] << 8) + w[5])]
    return l.copy()

def encrypt(plaintext,key):
    l =  key_expansion(key)
    key = l[0]
    round1 = l[1]
    round2 = l[2]
    p = toStateMatrix(plaintext) 
    state = add_round_key(key,p)
    l = NS(sBox, state)
    l = SR(l)
    state = MC(l)
    state = add_round_key(round1, state)
    l = NS(sBox, state)
    state = SR(l)
    state = add_round_key(round2, state)
    return toOutput(state)

def decrypt(ciphertext,key):
    l =  key_expansion(key)
    key = l[0]
    round1 = l[1]
    round2 = l[2]
    c = toStateMatrix(ciphertext)
    state = add_round_key(round2,c)
    state = SR(state)
    state = NS(InversesBox,state)
    state = add_round_key(round1, state)
    state = IMC(state)
    state = SR(state)
    state = NS(InversesBox,state)
    state = add_round_key(key, state)
    return toOutput(state)

plaintext = int(input("Input 16 bit binary plaintext: "), 2)
key = int(input("Input 16 bit binary Key: "), 2)
print("plaintext=",plaintext)
ciphertext = encrypt(plaintext,key)
print("ciphertext=",ciphertext)
plaintext = decrypt(ciphertext,key)
print("plaintext=",plaintext)
print("Binary plaintext=",bin(plaintext))