package com.cryptull.alexandra.ecdh;

import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

public class MainActivity extends AppCompatActivity {

//    static {
//        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
//    }

    BigInteger q = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
    BigInteger a = new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16);
    BigInteger b = new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16);
    BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");
    byte[] G_hex = Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf");
    ECPoint G;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        //Security.insertProviderAt(new BouncyCastleProvider(), 1);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @RequiresApi(api = Build.VERSION_CODES.O)
                    @Override
                    public void run() {
                        ceshi();
                    }
                }).start();
            }
        });
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void ceshi(){
        ECCurve curve2 = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        ECParameterSpec ecSpec2 = new ECParameterSpec(curve2,
                curve2.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        KeyPairGenerator keyGen = null;

        try {
            keyGen = KeyPairGenerator.getInstance("ECDH", new BouncyCastleProvider());

//                    ECCurve curve = new ECCurve.Fp( q, a, b);
//                    G = curve.decodePoint(G_hex);
//                    ECParameterSpec ecSpec = new ECParameterSpec( curve, G, n);
            keyGen.initialize(ecSpec2, new SecureRandom());

            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            KeyPair aPair = keyGen.generateKeyPair();
            KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            KeyPair bPair = keyGen.generateKeyPair();

            aKeyAgree.init(aPair.getPrivate());
            bKeyAgree.init(bPair.getPrivate());

            aKeyAgree.doPhase(bPair.getPublic(), true);
            bKeyAgree.doPhase(aPair.getPublic(), true);

            MessageDigest hash = MessageDigest.getInstance("SHA1", new BouncyCastleProvider());

            String signResult = sign(Base64.encodeToString(aKeyAgree.generateSecret(),Base64.DEFAULT),bPair.getPrivate());
            boolean verifyResult = verify(Base64.encodeToString(aKeyAgree.generateSecret(),Base64.DEFAULT),bPair.getPublic(),signResult);
            //Log.e("test2", String.valueOf(verifyResult));

            String cifrardateResult = AES.cifrar1("zhubinsheng",aKeyAgree);
            Log.e("test3", cifrardateResult);
            String descifrardateResult = AES.descifrar1(cifrardateResult,bKeyAgree);
            Log.e("test3", descifrardateResult);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }


    /**
     * 验签方法
     * @param textContent 解密明文
     * @param pubKey 公钥
     * @param signData 签名
     * @return
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    private static boolean verify(String textContent, PublicKey pubKey, String signData) {
        try {
            //byte[] keyBytes = Base64.getMimeDecoder().decode(pubKey.getBytes("utf-8"));
            byte[] contentBytes = Base64.decode(textContent.getBytes(), Base64.DEFAULT);
            byte[] signBytes = Base64.decode(signData.getBytes("utf-8"),Base64.DEFAULT);
            //X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            //KeyFactory keyFactory = KeyFactory.getInstance("EC");
            //PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Log.e("test2", textContent);
            Log.e("test2", Arrays.toString(signBytes));
            Signature signature = Signature.getInstance("SHA256withECDSA",new BouncyCastleProvider());
            signature.initVerify(pubKey);
            signature.update(contentBytes);
            //Log.e("contentBytes", Arrays.toString(contentBytes));
            return signature.verify(signBytes);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return Boolean.parseBoolean(null);
    }


    /**
     * 生成签名数据
     * @param content 加密数据
     * @param priKey 私钥
     * @return
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    private String sign(String content, PrivateKey priKey) {
        try {
//            byte[] keyBytes = Base64.getMimeDecoder().decode(priKey.getBytes("utf-8"));
//            byte[] contentBytes = Base64.getMimeDecoder().decode(content.getBytes("utf-8"));
//
//            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
//            KeyFactory keyFactory = KeyFactory.getInstance("EC");
//            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            byte[] contentBytes = Base64.decode(content.getBytes(), Base64.DEFAULT);
            byte[] sign1 = signData("SHA256withECDSA", contentBytes, priKey);

//            Signature signature = Signature.getInstance("SHA1withECDSA");
////            Provider provider = new BouncyCastleProvider();
////            Signature signature = Signature.getInstance("SHA256withECDSA",provider);
//            signature.initSign(privateKey);
//            signature.update(contentBytes);
            //Log.e("test2", Arrays.toString(sign1));
            return Base64.encodeToString(sign1,Base64.DEFAULT);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] signData(String algorithm, byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance(algorithm,new BouncyCastleProvider());
        signer.initSign(key);
        signer.update(data);
        //Log.e("contentBytes", Arrays.toString(data));
        return (signer.sign());
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
