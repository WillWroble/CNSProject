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




