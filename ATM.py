import requests
from app.RandNumGen import WELL1024a
import math
import time
import os
a = 2
b = 3
prime = "0xeb628434bcc2b89bafb2fe3e64a932dc8be90c11e954589c1120c938882ee8bba786be21787305a9bcb63c9f7ac3c2838f0c8458acfc2b62e7cbf8c1598a6d8c0d9e343662e37e37aefbe49b3fce5caafb36f03aa154fd996f15d6cec4e8f8f163182ff7c533eb40140e36861cf38e592e45127e3e02a284fcf956b0d84efc6d000ecd9b6d089f122a84725478e2cf86fce5170960c9ce838a2d71703e4ba6bcdf4e303fff1fb1e8236e02484e87f1da1857a8dabdeb5eb045673b1a06c1ff08c5c21271a432c35c6c9b38137102d9929311903afbd1ae0573e72b4b381eb6bd154236073eaa422bc98be4f141bb722a51b68a287a896bf53a79c43646842eff"
prime = int(prime, 16)
x = 8079629832748665471902491202754605629108498070590073899616823369580272488719577641816337461430140829897813658289231290010883620477997124866769462929171873071809184136192209499816940637980534335291194100333295238984275985581222853932975836282544254031335326857776775282715960112928362233385052194065052437514259591589256186655259511862081516928567966837318130972724350327596708739949588002757094234955519406440854982489020559321201359583418910221932134475560223571718938041582520821937127972784766572179331600656708622564180708799359209874132296663799581627363125426657282085409957783097906736296634087493373640866408
y = 2203772622731522579052962394475977197831023010335570151215139156508813625824089218792546257255580494331659996348183218438616526340739511725153781925643705120877251650249947326133313588916446737766811903601790542308833582853933678603162992360326735215988862365377995928015344838122052080197990610609908846044715922481149686850277302273987283535540897195091419760619661753292481125378239807262525779410513934106186217534137027380518602522976757339408305089467940297011150158944609035920100501115238876221760364851911516723717009398682105467370649922236992484994294246593757432056211293709910508917913994305037544979088
G = (x, y)  # Base point on the curve
n = 500000  # Private key space [1, n]

session_key = None

data = {
    "account_id": 0,
    "password": "",
    "action":-1,
    "deposit":0,
    "withdraw":0
}

seedstring = str(prime) #producing hopefully enough entropy
start = math.ceil((time.time_ns()) + os.getpid() + os.getppid()) % len(seedstring)
seed = []
for i in range(1,33):
    temp = ""
    for j in range(10):
        temp += seedstring[start]
        start = (start + j) % len(seedstring)
    seed.append(int(temp) & 0xFFFFFFFF)

rng = WELL1024a(seed)
temp = ""
for j in range(6):
    temp += seedstring[start]
    start = (start + j) % len(seedstring)
    rng.next()
for i in range(int(temp)):
    rng.next()

def inverse_mod(k, p):
    return pow(k, p - 2, p)

def ecc_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None  # Point at infinity

    if p1 == p2:
        if y1 == 0:
            return None  # Tangent is vertical
        # Slope for point doubling
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, prime)
    else:
        # Slope for regular addition
        m = (y2 - y1) * inverse_mod(x2 - x1, prime)

    m = m % prime

    x3 = (m * m - x1 - x2) % prime
    y3 = (m * (x1 - x3) - y1) % prime

    return (x3, y3)

def ecc_mul(k, point):
    result = None  # Identity (point at infinity)
    addend = point

    while k:
        if k & 1:
            result = ecc_add(result, addend)
        addend = ecc_add(addend, addend)
        k >>= 1

    return result

def start_secure_session():
    global session_key
    priv = math.ceil(rng.next()*n)
    pub = ecc_mul(priv, G)
    res = requests.post("http://localhost:8000/handshake", json={"client_pub": pub})
    server_pub = tuple(res.json()["server_pub"])
    shared = ecc_mul(priv, server_pub)
    session_key = shared[0]

def resetdata(local_data):
    local_data["account_id"] = 0
    local_data["password"] = ""
    local_data["action"] = -1
    local_data["deposit"] = 0
    local_data["withdraw"] = 0

def resetnonaccountdata(local_data):
    local_data["action"] = -1
    local_data["deposit"] = 0
    local_data["withdraw"] = 0



def mainloop(data):
    message = ""
    curr_data = data

    while (message != "quit"):
        print("Welcome to Bank of Money")
        print("Type 'check bal' to check balance")
        print("Type 'deposit money' to deposit money")
        print("Type 'withdraw money' to withdraw money")
        print("Type 'quit' to quit")
        message = input("What would you like to do?")

        if (message == "check bal"):
            curr_data["action"] = 0
            res = requests.post("http://localhost:8000/", json=curr_data)
            resetnonaccountdata(curr_data)

            if (res.json()["success"] == 0):
                print("current bal: " + str(res.json()["money"]))
            else:
                print("error please call an employee to help out")
        elif(message == "deposit money"):
            message = input("Insert cash to deposit")
            curr_data["action"] = 1
            curr_data["deposit"] = int(message)
            res = requests.post("http://localhost:8000/", json=curr_data)
            resetnonaccountdata(curr_data)

            if (res.json()["success"] == 0):
                print("Successfuly deposited: " + str(res.json()["money"]))
            else:
                print("error please call an employee to help out")

        elif(message == "withdraw money"):
            message = input("How much money to withdraw")
            curr_data["action"] = 2
            curr_data["withdraw"] = int(message)
            res = requests.post("http://localhost:8000/", json=curr_data)
            resetnonaccountdata(curr_data)

            if (res.json()["success"] == 0):
                print("Successfuly withdrawn: " + str(res.json()["money"]))
            elif(res.json()["success"] == 3):
                print("Not enough money to withdraw")
            else:
                print("error please call an employee to help out")


        elif (message == "quit"):
            return
        
def loginloop():
    message = ""
    curr_data = {
        "account_id": 0,
        "password": "",
        "action":-1,
        "deposit":0,
        "wtihdraw":0
    }
    
    while (message != "quit"):
        print("Welcome to Bank of Money")
        message = input("Input account id or type 'quit' to quit")
        if (message == "quit"):
            return
        curr_data["account_id"] = int(message)
        message = input("Input passowrd")
        curr_data["password"] = message
        message = ""

        curr_data["action"] = 4
        res = requests.post("http://localhost:8000/", json=curr_data)
        if (res.json()["success"] == 0):
            print("Logging in")
            mainloop(curr_data)
            return
        else:
            print("Invalid Account id or Password")
        

def creatnewaccountloop():
    message = ""
    curr_data = {
        "account_id": 0,
        "password": "",
        "action":-1,
        "deposit":0,
        "wtihdraw":0
    }
    while (message != "quit"):
        print("Welcome to Bank of Money")
        message = input("Input account id or type 'quit' to quit")
        if (message == "quit"):
            return
        curr_data["account_id"] = int(message)
        message = input("Input passowrd")
        curr_data["password"] = message
        message = ""

        curr_data["action"] = 3
        res = requests.post("http://localhost:8000/", json=curr_data)
        if (res.json()["success"] == 0):
            print("Logging in")
            mainloop(curr_data)
            return
        else:
            print("Invalid Account id")


def welcomeloop():
    start_secure_session()
    message = ""
    while (message != "shut down"):
        print("Welcome to Bank of Money")
        message = input("Type 'Log in' to Log in or 'Create new Account' to Create a new account")
        if (message == "Log in"):
            loginloop()
        if (message == "Create new Account"):
            creatnewaccountloop()
        if (message == "sess"):
            print(session_key)
            res = requests.get("http://localhost:8000/")
            print(res.json()['session_id'])

welcomeloop()