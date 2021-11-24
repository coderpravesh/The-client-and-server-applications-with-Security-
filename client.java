import java.net.*;
import java.io.*;
import java.lang.Math;
import java.util.*;
import java.math.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class client{
	
	// some varibles with there known meaning
	
	public static BigInteger p,q,N,phi,e,e1,d,d1;
	public static BigInteger ONE = new BigInteger("1");
	public static int length=20,count=0;
	public static long avgm=0;
	
	//	some of the well known varibles used in the rsa encryption and decryption 
	
	public static boolean encrypt = false;
	public static int[] Sbox = new int[]{9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
	public static int[] RoundConstant = new int[]{128,170,48};
	public static int[][] MixMat = {{1,4},{4,1}};
	public static int ciph,msg,key;
	public static int[] skey = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static int[] intArray = new int[]{1,2,3,4,5,6,7,8,9,10};
	public static String preround="",round1sn="",round1sr="",round1mix="",round1ark="",round2sn="",round2sr="",round2ark="";


	//shift rows nibbles 16-bit
	public static int row_shifting(int x){
	    if(encrypt==true) return ((x & 3840)>>8 | (x & 15)<<8 | (x & 61680));
	    else return ((x & 240)>>4 | (x & 15)<<4);
	}
	
	//function for substitute nibble 
	public static int sub_nib(int x)
	{
	    if(encrypt==true)
	    {
	        int x1=(61440 & x)>>12;
	        int x2=(3840 & x)>>8;
	        int x3=(240 & x)>>4;
	        int x4=(15 & x);
	        return ((Sbox[x1]<<12) | (Sbox[x2]<<8) | (Sbox[x3]<<4) | (Sbox[x4]));
	    }
	    else
	    {
	        int var1=(x & 240)>>4;
	        int var2=(x & 15);
	        return (Sbox[var1]<<4 | Sbox[var2]);
	    }
	}
	
	
	//key generation
	//1st :- divide the key into two sub key w0,w1
	//2nd :- Find aint other subkeys using for loop,w0,w1
	
	public static void key_genration()
	{
	    w[0]=(65280 & key)>>8;
	    w[1]=(255 & key);
	    int i;
	    for(i=2;i<=5;i++)
	    {
	        if(i%2==0)
	        w[i]=w[i-2]^RoundConstant[i-2]^sub_nib(row_shifting(w[i-1]));
	        else
	        w[i]=w[i-1]^w[i-2];
	    }
	}
	
	//polynomial multiplication
	public static int  gmul(int  x,int  y){
	    int val=0,j=0;
	    while(x>0){
	        val=((x&1)*(y<<j))^val;
	        x=x>>1;
	        j=j+1;
	    }
	    return val;
	}
	
	//generating roundkeys
	public static void Round_key()
	{
	    skey[0]=(w[0]<<8 | w[1]);
	    skey[1]=(w[2]<<8 | w[3]);
	    skey[2]=(w[4]<<8 | w[5]);
	}
	
	//add round key
	public static int ark(int m,int k){
	    return (m^k);
	}
	
	
	//bitwise polynomial modulo 19 multiplication
	public static int bit_mod(int b1,int b2)
	{
	    int mul=gmul(b1,b2);
	    int shift=0;
	    while(mul>15){
	        shift=(int)(Math.ceil(Math.log(mul+1)/Math.log(2)))-(int)(Math.ceil(Math.log(19)/Math.log(2)));
	        mul=mul^(19<<shift);
	    }
	    return mul;
	}
	
	//mix columns [1,4 ; 4,1] encoding
	public static int column_mixing(int c){
	    int[] s = new int[4];
	    int[] st = new int[4];
	    s[0]=((61440 & c)>>12)&15;
        s[1]=(3840 & c)>>8;
        s[2]=(240 & c)>>4;
        s[3]=(15 & c);

        st[0]=bit_mod(MixMat[0][0],s[0])^bit_mod(MixMat[0][1],s[1]);
        
        st[1]=bit_mod(MixMat[0][1],s[0])^bit_mod(MixMat[0][0],s[1]);
        
        st[2]=bit_mod(MixMat[1][1],s[2])^bit_mod(MixMat[1][0],s[3]);
        
        st[3]=bit_mod(MixMat[1][0],s[2])^bit_mod(MixMat[1][1],s[3]);
        
        
        return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}

	// Encryption starts
	//round0
	public static void round0()
	{
	    encrypt = true;
	    ciph=ark(msg,skey[0]);
	    preround=preround+Integer.toHexString(ciph);
	}
	//Round1
	public static void round1()
	{
	    ciph=sub_nib(ciph);
	    round1sn=round1sn+Integer.toHexString(ciph);
	    
	    ciph=row_shifting(ciph);
	    round1sr=round1sr+Integer.toHexString(ciph);
	    
	    ciph=column_mixing(ciph);
	    round1mix=round1mix+Integer.toHexString(ciph);
	    
	    ciph=ark(ciph,skey[1]);
	    round1ark=round1ark+Integer.toHexString(ciph);
	}
	// round2 
	public static void round2()
	{
	    ciph=sub_nib(ciph);
	    round2sn=round2sn+Integer.toHexString(ciph);
	    
	    ciph=row_shifting(ciph);
	    round2sr=round2sr+Integer.toHexString(ciph);
	    
	    ciph=ark(ciph,skey[2]);
	    round2ark=round2ark+Integer.toHexString(ciph);
	   	
	    encrypt = false;
	}
	
	//function converting string to hexadecimal string 
	public static String StringToHexadecimal(String input)
	{
		StringBuffer sb = new StringBuffer();
	    char ch[] = input.toCharArray();
	    for(int i = 0; i < ch.length; i++)
	    {
	        String hexString = Integer.toHexString(ch[i]);
	        sb.append(hexString);
	    }
	    String result = sb.toString();
	   	return result;
	}
	
	
	public static String ProperString(String str,int len)
	{
		String res = String.join("", Collections.nCopies(Math.max(len-str.length(),0), "0")) + str;
		return res;
	}
	
	// function for changing decimal into binary 
	public static String sixteenbitbinary(int c)
	{
		String ret = Integer.toBinaryString(c);
		String res = String.join("", Collections.nCopies(16-ret.length(), "0")) + ret;
		return res;
	}
	
	// function for advance rsa
	public static void RSA1()
	{
		Random rand = new Random();
		N=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		e1=BigInteger.probablePrime(length, rand); 
		for(BigInteger i=BigInteger.ZERO; i.compareTo(N)<0 ; i.add(BigInteger.ONE)){
			
			if((e1.gcd(phi).equals(BigInteger.ONE)) && (e1.compareTo(phi)<0) && ((BigInteger.ONE).compareTo(e1)<0))
				break;
			else
				e1=BigInteger.probablePrime(length, rand);
		}
		d1=e1.modInverse(phi);
	}
	
	// function for simple RSA
	public static void simple_RSA()
	{
		N=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	}
	
	public static String readFileAsString(String fileName) throws Exception
	{
	    String data = "";
	    data = new String(Files.readAllBytes(Paths.get(fileName)));
	    return data;
	}
	
	public static BigInteger toBigInteger(String input)
	{
	    return new BigInteger(input.getBytes());
	}

	public static String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}
	
	public static BigInteger encrypt(BigInteger mssg)
	{ 
		BigInteger t=mssg.modPow(e, N);	 
		return t;
	}
	
	
	public static BigInteger decrypt(BigInteger mssg)
	{
		BigInteger w=mssg.modPow(d1, N);
		return w;
	}

	public static BigInteger hashing_function(String input)
    {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            return no;

        } 
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
    	}
    }


	public static void main(String[] args) throws IOException{
		
		ServerSocket ss = new ServerSocket(7999);
		Socket s = ss.accept();

		System.out.println("Server Connected");
		Scanner in = new Scanner(System.in);
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);
		PrintWriter out = new PrintWriter(s.getOutputStream());

		String serverpublickey = bf.readLine();
		e = new BigInteger(serverpublickey);

        // All the inputs required 
		String t1  = in.nextLine();
		p = new BigInteger(t1);
		String t2 = in.nextLine();
		q = new BigInteger(t2);
		System.out.println("Enter the plain text: ");
		String message = in.nextLine();
		System.out.println("Enter the 16-bit key: ");
		String secretkey = in.nextLine();
		String z = secretkey;
		int zz = Integer.parseInt(z,2);
		simple_RSA();
		
		BigInteger inn = BigInteger.valueOf(zz);
		System.out.println("Secrete Key "+inn);
		BigInteger encryptedsecretkey=encrypt(inn);


		key = Integer.parseInt(secretkey,2);

		int len = message.length();
		String ret="";

		key_genration();
		Round_key();

		for(int i=0;i+1<len;i+=2)
		{
			msg = Integer.parseInt(StringToHexadecimal(message.substring(i,i+2)),16);
			round0();
			round1();
			round2();
			String res = Integer.toHexString(ciph);
			ret=ret.concat(ProperString(res,4));
		}

		if(len%2==1)
		{
			msg = Integer.parseInt(StringToHexadecimal(message.substring(len-1,len)),16);
			round0();
			round1();
			round2();
			String res = Integer.toHexString(ciph);
			ret=ret.concat(ProperString(res,2));
		}

		String ciphertext = ret;
		BigInteger messagedigest = hashing_function(message);
		BigInteger temp4 = messagedigest.modPow(ONE, N);	 
		System.out.println("messagedigest: "+ temp4);
		RSA1();
		BigInteger clientsignature = decrypt(temp4);
		
		// ouputs
		System.out.println("Client_Signature is "+clientsignature); 
		System.out.println("Cipher_Text is "+ ciphertext);
		System.out.println("Encrypted_Secret_Key is "+ encryptedsecretkey);
		String temp = clientsignature.toString(10);
		out.println(""+temp);// bigInteger
		out.println(""+ciphertext); // string
		String temp2 = encryptedsecretkey.toString(10);
		out.println(""+temp2);
		String temp3 = e1.toString(10);
		out.println(""+ temp3); // string
		out.flush();
	}
}
