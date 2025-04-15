# Twofish implementation:  
**keysize:** 256 bits  
**blocksize:** 128bits  
**key schedule:** 256bit key is split into 40 32bit subkeys. first 4 keys are used for input whitening the last 4 for output whitening. The other 32 are used for each round of the fesital loop.
(because twofiish uses a dual layer F function 2 subkeys are needed each round)  
**sbox generation:** this simplified version of twofishe's sbox generation still creates key dependent sboxes using RS-MDS, but does so by xoring each element of a base reversed SBOX (255,254,253...) using a simplified RS_MDS encoding of the key.  
**q-perms:** Base nibble arrays: [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4], [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5]
are defined for twofish and used to build 256 entry lookup tables. these permutations are used on the first and last 2 bytes in the g function (which is the main part of the f function)  
**dual feistal loop:** twofish uses 16 round feistal loop but splits the 64 bit half into 2 32 quarters applies g function to each half (each with a unique subkey) then the outputs are combined using a PHT(pseudo harmond transform)  
**g_function:** heart of the cipher, appies q perms and sboxes and feeds substituted bytes into MDS multiplication routine. used in f function during encrypt/decrypt as well as part of the h_function as part of the key schedule.

#Generate Seed:
Generates a start int by using time.time_ns, os.getpid() and os.getppid()
Ueses that int to loop through the prime number and creat 32 10 digit numbers to create the seed for the random number generator
Then creates a 6 digit number by looping through the prime and runs rng.next that many times to create entropy.

#Random number generator:
Takes a 32 array seed and uses WELL1024a as a pseudo random number generator.
WELL1024a works by circular 32 integer buffer and every next call uses XORs and other functions to generate a pseudo random number.
It then updates its state for the next call and returns a float between 0 (inclusive) and 1 (exculsive) by multipling it by 1 / 2^32

#Handshake implementation:
Uses a predetermined x, y, a, b, n, prime, and G
Uses eliptec curve cryptography to generate the shared key. Both the ATM and the Bank create their own private key using a random number generator.
First the ATM generates the random number generator for its private key, then it shares the public key by preforming ecc multiplication on the private key and point G
The ATM sends that to the Bank, which generates its own private key using a random number generator. It then performes ecc multiplication on the bank's private key
and the result that was sent to the Bank. The x value of the resulting point is stored as the shared key for the bank. The Bank then returns the result
of ecc multiplication of the bank's private key and G. Finally the ATM calculates the shared key by performing ecc multiplication on its private key
and the servers response and stores it.

#Decryption and encryption:
To Use Twofish properly the shared key is broken into 256 bits and the json is broken into 128 bits. 
Every time the ATM encrypts data it then uses the next 256 bits of the shared key
Every time the Bank decrypts data it then uses the next 256 bits of the shared key

For encryption the json is converted to base64 and uses twofish encryption with whatever part of the shared key the counter is on.
It then creates chunks of the base64 and padds the last one until they are all 128 bits.
It then ecrypts all the chunks and conbines them.

For decryption the base64 is first broken into chunks, padds the last one until they are all 128 bits. 
Uses twofish encryption with whatever part of the shared key the counter is on.
decrypts all the chunks and converts it to json.

#ATM implementation:
Upon launch performes the 'Handshake' and generates the shared key for the Bank and the ATM.
The user then can 'Log in' or 'Create new Account'

Log in:
The user will be asked for an account id (or 'quit' to quit) and a password, once they are provided, the ATM will send an encrypted message to the BANK
conting the account id and password. The BANK will send back and encrypted message if it was successful or not.
If it was successful it will send the user to the main loop else it will resset the Log in loop.

Create new account loop:
Very similar to Log in except it atempts to create a new account (new id, password, and 0 money)

Main loop:
The user has 4 options, deposit money, withdraw money, check bal, or quit. In the main loop it has the username and password saved.
For the first 3 options it will send encrypt and send the data to the bank and respond apropriatly the data would look like:
encrypt( data {
'username':1231,
'password':password,
'action': 3,
'money':400, #if action requres it
})

#Bank implementation:
Upon launch the Bank creats all the structers to store session keys, passwords, and money.
It will then wait for a POST request either to '/' or to '/handshake'

'/handshake':
perfomers Handshake with the requester

'/':
First decypts the data using the sesson key and reads, the username, password and action.
If they all are valid perfomrres the given aciton
Then sends an appropriate encrypted response
