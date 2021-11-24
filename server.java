import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;
import java.lang.Math;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class server{

	// some known varibles 
	public static BigInteger p,q,N,e,e1,phi,d,d1;
	public static BigInteger ONE= new BigInteger("1");
	public static int length=20,count=0;
	public static long avgm=0;
	
	//	some of the well known varibles used in the advance rsa
		 
	public static boolean decrypt = false;
	public static int[] Sbox = new int[]{9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
	public static int[] SIbox = new int[]{10,5,9,11,1,7,8,15,6,0,2,3,12,4,13,14};
	public static int[] RoundConstant = new int[]{128,170,48};
	public static int[][] InMixMat = {{9,2},{2,9}};
	public static int ciph,dmsg,key;
	public static int[] skey = new int[]{0,0,0};
	public static int[] w = new int[]{0,0,0,0,0,0};
	public static int[] intArray = new int[]{1,2,3,4,5,6,7,8,9,10};
	public static String preround="",round1sn="",round1sr="",round1mix="",round1ark="",round2sn="",round2sr="",round2ark="";
	
	
	//shift rows nibbles 16-bit
	public static int Shift_Rows(int c)
	{
	    if(decrypt==true) return ((c & 3840)>>8 | (c & 15)<<8 | (c & 61680));
	    else return ((c & 240)>>4 | (c & 15)<<4);
	}
	
	// functions for substitute nibble 
	public static int sub_nib(int c)
	{
	    if(decrypt==true){
	        int x1=(61440 & c)>>12;
	        int x2=(3840 & c)>>8;
	        int x3=(240 & c)>>4;
	        int x4=(15 & c);
	        
	        return ((SIbox[x1]<<12) | (SIbox[x2]<<8) | (SIbox[x3]<<4) | (SIbox[x4]));
	    }else{
	        int var1=(c & 240)>>4;
	        int var2=(c & 15);

	        return (Sbox[var1]<<4 | Sbox[var2]);
	    }
	}
		
	//key generation
	public static void Key_generation()
	{
	    w[0]=(65280 & key)>>8;
	    w[1]=(255 & key);
	    for(int i=2;i<=5;i++)
	    {
	        if(i%2==0)
	        w[i]=w[i-2]^RoundConstant[i-2]^sub_nib(Shift_Rows(w[i-1]));
	        else
	        w[i]=w[i-1]^w[i-2];
	    }
	}
	
	//generating Round_keys
	public static void Round_key(){
	    skey[0]=(w[0]<<8 | w[1]);
	    skey[1]=(w[2]<<8 | w[3]);
	    skey[2]=(w[4]<<8 | w[5]);
	}
	
	//add round key
	public static int ark(int m,int k){
	    return (m^k);
	}

	//polynomial multiplication
	public static int  gmul(int  m1,int  m2)
	{
	    int res=0x0;
	    int j=0;
	    while(m1>0){
	        res=((m1&1)*(m2<<j))^res;
	        m1=m1>>1;
	        j=j+1;
	    }
	    return res;
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
	public static int column_mixing(int c)
	{
	    int[] s = new int[4];
	    int[] st = new int[4];
	    s[0]=((61440 & c)>>12)&15;
	    s[1]=(3840 & c)>>8;
	    s[2]=(240 & c)>>4;
	    s[3]=(15 & c);
	    st[0]=bit_mod(InMixMat[0][0],s[0])^bit_mod(InMixMat[0][1],s[1]);
        
        st[1]=bit_mod(InMixMat[0][1],s[0])^bit_mod(InMixMat[0][0],s[1]);
        
        st[2]=bit_mod(InMixMat[1][1],s[2])^bit_mod(InMixMat[1][0],s[3]);
        
        st[3]=bit_mod(InMixMat[1][0],s[2])^bit_mod(InMixMat[1][1],s[3]);;
	        
	    return ((st[0]<<12) | (st[1]<<8) | (st[2]<<4) | (st[3]));
	}
	// Decryption starts
	//dround0
	public static void dround0()
	{
	    decrypt = true;
	    dmsg=ark(ciph,skey[2]);
	    preround=preround+Integer.toHexString(dmsg);
	}
	// dround1
	public static void dround1()
	{
	    dmsg=sub_nib(dmsg);
	    round1sn=round1sn+Integer.toHexString(dmsg);

	   	dmsg=Shift_Rows(dmsg);
	    round1sr=round1sr+Integer.toHexString(dmsg);
	    
	    dmsg=ark(dmsg,skey[1]);
	    round1ark=round1ark+Integer.toHexString(dmsg);
	    
	    dmsg=column_mixing(dmsg);
	    round1mix=round1mix+Integer.toHexString(dmsg);
	}
	//dround2
	public static void dround2()
	{
	    dmsg=sub_nib(dmsg);
	    round2sn=round2sn+Integer.toHexString(dmsg);

	    dmsg=Shift_Rows(dmsg);
	    round2sr=round2sr+Integer.toHexString(dmsg);

	    dmsg=ark(dmsg,skey[0]);
	    round2ark=round2ark+Integer.toHexString(dmsg);
	    decrypt = false;
	}
	
	//function to convert haxadecimal to string 
	public static String HexadecimalToString(String str)
	{
		String result = new String();
      	char[] charArray = str.toCharArray();
      	for(int i = 0; i < charArray.length; i=i+2)
      	{
         	String st = ""+charArray[i]+""+charArray[i+1];
         	char ch = (char)Integer.parseInt(st, 16);
        	result = result + ch;
      	}
      	return result;
	}

	public static String sixteenbitbinary(int c)
	{
		String ret = Integer.toBinaryString(c);
		String res = String.join("", Collections.nCopies(16-ret.length(), "0")) + ret;
		return res;
	}
	public static void RSA1()
	{
		Random rand = new Random();
		N=p.multiply(q);
		
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		e1=BigInteger.probablePrime(length, rand); 
		
		for(BigInteger i=BigInteger.ZERO;i.compareTo(N)<0;i.add(BigInteger.ONE))
		{
			
			if((e1.gcd(phi).equals(BigInteger.ONE)) && (e1.compareTo(phi)<0) && ((BigInteger.ONE).compareTo(e1)<0))
				break;
			else
				e1=BigInteger.probablePrime(length, rand);
		}
		d1=e1.modInverse(phi);
	}
	public static void simple_RSA()
	{
		N=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	}
	public static BigInteger encryptt(BigInteger mssg)
	{ 
		BigInteger t=mssg.modPow(e, N);	 
		return t;
	}
	public static BigInteger decryptt(BigInteger mssg)
	{
		BigInteger w=mssg.modPow(d1, N);
		return w;
	}
	public static BigInteger toBigInteger(String input)
	{
	    return new BigInteger(input.getBytes());
	}

	public static String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}
	// hash function for mapping of key and value 
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
		Socket s = new Socket("localhost",7999);
		Scanner in = new Scanner(System.in);
		PrintWriter out = new PrintWriter(s.getOutputStream());
		InputStreamReader inp = new InputStreamReader(s.getInputStream());
		BufferedReader bf = new BufferedReader(inp);


		String t1  = in.nextLine();
		p = new BigInteger(t1);
		String t2 = in.nextLine();
		q = new BigInteger(t2);
		RSA1();

		String t3 = e1.toString(10); 
		out.println(""+t3);
		out.flush();

		// taking input from client side
		String clientsignature = bf.readLine();
		String ciphertext = bf.readLine();
		String encryptedsecretkey = bf.readLine();
		String clientpublickey = bf.readLine();
		BigInteger cs = new BigInteger(clientsignature); //cs => clientsignature
		BigInteger  esk = new BigInteger(encryptedsecretkey); // esk  => encryptedsecretkey
		e = new BigInteger(clientpublickey);

		BigInteger temp = decryptt(esk);
		String secretkey = temp.toString(2);
		System.out.println("Secret_Key is "+secretkey);

		String binnum1 = ciphertext;

		String binnum2 = secretkey;
		key = Integer.parseInt(binnum2,2);

		String ret="";
		int len = binnum1.length();

		Key_generation();
		Round_key();

		for(int i=0;i+3<len;i+=4)
		{
			ciph = Integer.parseInt(binnum1.substring(i,i+4),16);

			dround0();
	    	dround1();
	    	dround2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(HexadecimalToString(res));
		}

		if(len%4!=0)
		{
			ciph = Integer.parseInt(binnum1.substring(len-2,len),16);

			dround0();
	    	dround1();
	    	dround2();

	    	String res = Integer.toHexString(dmsg);
	    	ret = ret.concat(HexadecimalToString(res));
		}

    	System.out.println("Decoded cipher text: "+ret);
		BigInteger messagedigest = hashing_function(ret);
		BigInteger value = messagedigest.modPow(ONE, N);
		System.out.println("Message_digest: "+ value);
		BigInteger signature = encryptt(cs);
		System.out.println("intermediate_varification_code "+signature);
		
		int comparevalue = messagedigest.compareTo(signature); // comparing big integer for varification
		if( comparevalue == 1 ) 
		System.out.println("verified");
		else System.out.println("not verified");

	}
}
