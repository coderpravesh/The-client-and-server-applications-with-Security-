
											 

There is  Basic Socket Programming which simply sends the strings from client to the server in the same pc or same network.
I have first connected the server with client and entered the public and private key on both side .Then we have asked on client side for a plain text and a 16 bit key and generated the encrypted secret key and cipher text and we have sent it to the server side .Then on server it is decrypting the secret key cipher text and varyfying signature using rsa and also varyfying the message digest and signature using rsa.

There are two files client.java and server.java and we have used
### Server Socket
*new ServerSocket(7999)*
> Create a server on the port 7999

### Client Socket
*new Socket(7999)*
> Connect to the server running on localhost and port 7999
 
### All the function in client:
> main function
>function for substitute nibble -> sub_nib()

>shift rows nibbles 16-bit ->row_shifting()

>key generation function used -> key_generation ()
	
>generating roundkeys ->Round_Key()	

>add round key-> ark()

>polynomial multiplication > gmul

>bitwise polynomial modulo 19 multiplication ->Bit_mod
> Advance rsa for encryption and decryption  -> rsa1

## All function workings 
**Mix Column** 
> for multiply the matrix with nibbles of cipher text
> mix columns [1,4 ; 4,1] 
> encoding Inv Mix columns [9,2;2,9]

**encryption rounds** 
	-round0() 
	-round1()
	-round2()

> function to convert Integer to binary ->sixteenbitbinary()
> function to convert haxadecimal to string -> HexadecimalToString()

## All the function in server
> main  function
>function for substitute nibble -> substitute_nibble()
**Substitute Nibble**
	-Divide all 16bits into Nibble  & store int x1,x2,x3,x4 variable and using s - box or S-Inv-box  
	- Finally merge all the value of x1,x2,x3,x4 and return it.
>shift rows nibbles 16-bit-> Shift_Rows()

**key generation**
	1st :- divide the key into two sub key w0,w1
	2nd :- Find aint other subkeys using for loop,w0,w1
	key_generation()

>generating roundkeys ->RoundKey()	

>add round key -> ark()

>polynomial multiplication -> gmul

>bitwise polynomial modulo 19 multiplication ->Bit_mod

**Mix Column**
> for multiply the matrix with nibbles of cipher text
> mix columns [1,4 ; 4,1] 
> encoding Inv Mix columns [9,2;2,9]

**encryption rounds**
	-round0()
	-round1()
	-round2()

>function to convert integer to binary -> sixteenTobinary()

>function to convert string to hexadecimal ->StringToHexadecimal()

**In RSA** 
  -the public key is made of the modulus n, and the public (or encryption) exponent e.
  -The personal key is made of p,q and the private (or decryption) exponent d, which must be kept secret.
  
**Advance rsa** 
	-Rsa1 function is using a hashing function technique to generate a secret key which is further used to encrypt and decrypt the information.



