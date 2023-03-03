import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class RSASample {
    
    private static final String Public_Key_File = "Public.key";
    private static final String Private_Key_File = "Private.key";

    public static void main(String [] args) throws IOException{
     
        try{
            System.out.println(" ********** Public key ve private key üretme (Generate Public and Private key) *********");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            System.out.println("Pulling out parameters which makes keypair");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey,RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey,RSAPrivateKeySpec.class);
            
            System.out.println("Saving public key and private key to files");
            RSASample rsaObject = new RSASample();
            rsaObject.saveKeys(Public_Key_File,rsaPublicKeySpec.getModulus(),rsaPublicKeySpec.getPublicExponent());
            rsaObject.saveKeys(Private_Key_File,rsaPrivateKeySpec.getModulus(), rsaPrivateKeySpec.getPrivateExponent());
            
            byte[] encryptedData = rsaObject.encryptData("Data to encrypt");
            
            rsaObject.decryptData(encryptedData);
        }
          catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            System.out.println(e);
        }
    }
        private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException{
            FileOutputStream fos = null;
            ObjectOutputStream oos = null;
            
            try{
                System.out.println("Generating: " +fileName + "...");
                fos = new FileOutputStream(fileName);
                oos = new ObjectOutputStream(new BufferedOutputStream(fos));
                oos.writeObject(mod);
                oos.writeObject(exp);
                System.out.println(fileName + "generated successfully");
            }
            catch(Exception e){
                e.printStackTrace();
            }
            finally{
                if(oos != null){
                    oos.close();
                    if(fos != null){
                        fos.close();
                    }
                }
            }
        }
        private byte[] encryptData(String data)throws IOException{
            System.out.println("encryption start");
            System.out.println("Data before encryption: " +data);
            byte[] dataToEncrypt = data.getBytes();
            byte[] encryptedData = null;
            try{
                PublicKey pubkey = readPublicKeyFromFile(this.Public_Key_File);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE,pubkey);
                encryptedData = cipher.doFinal(dataToEncrypt);
                
                System.out.println("Encrypted Data: " +new String(encryptedData));
            }
            catch(IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
                e.printStackTrace();
            }
            System.out.println("Encryption : ");
            return encryptedData;   
        }
        
        private byte[] decryptData(byte[] data)throws IOException{
            System.out.println("Decryption");
            byte[] descryptedData = null;
            try{
                PrivateKey privateKey = readPrivateKeyFromFile(this.Private_Key_File);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE,privateKey);
                descryptedData = cipher.doFinal(data);
                System.out.println("Decrypted data: " + new String(descryptedData));
            }
            catch(IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
                e.printStackTrace();
            }
            System.out.println("Decrypted");
            return descryptedData;
        }
        
        
        public PublicKey readPublicKeyFromFile(String fileName) throws IOException{
            FileInputStream fis = null;
            ObjectInputStream ois = null;
            
            try{
                fis = new FileInputStream(new File(fileName));
                ois = new ObjectInputStream(fis);
                BigInteger modulus = (BigInteger) ois.readObject();
                BigInteger exponent = (BigInteger) ois.readObject();
                RSAPublicKeySpec rsaPublicKeySpec  = new RSAPublicKeySpec(modulus,exponent);
                KeyFactory fact = KeyFactory.getInstance("RSA");
                PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
                return publicKey;
                
            }
            catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
                e.printStackTrace();
            }
            finally {
                if(ois != null){
                    ois.close();
                    if(fis != null){
                        fis.close();
                    }
                }
            }
            return null;
        }
        
        public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
            FileInputStream fis = null;
            ObjectInputStream ois = null;
            
            try{
                fis = new FileInputStream (new File(fileName));
                ois = new ObjectInputStream(fis);
                BigInteger modulus = (BigInteger) ois.readObject();
                BigInteger exponent = (BigInteger) ois.readObject();
                RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus,exponent);
                KeyFactory fact = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
                
                return privateKey;
            }
            catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
                e.printStackTrace();
            }
            finally {
                if(ois != null){
                    ois.close();
                    if(fis != null){
                        fis.close();
                    }
                }
            }
                    return null;
       }        
}
