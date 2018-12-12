package com.webberis.ms.authenticationserver.secrets;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.webberis.ms.authenticationserver.exception.WebberisGlobalException;

public class KeyPairFile {
	
    private File jksFile;
    private char[] password;
    private File publicKey;
    
    public KeyPairFile(String alias) {
        build(alias);
    }

    public File getJksFile() {
        return jksFile;
    }

    private void setJksFile(File jksFile) {
        this.jksFile = jksFile;
    }

    public char[] getPassword() {
        return password;
    }

    private void setPassword(char[] password) {
        this.password = password;
    }
    
    public File getPublicKey() {
        return publicKey;
    }

    private void setPublicKey(PublicKey pKey) throws IOException {
        File tmpFile = File.createTempFile("keystore", ".pub");
        FileOutputStream fos = new FileOutputStream(tmpFile);
        fos.write(pKey.getEncoded());
        fos.close();
        this.publicKey = tmpFile;
    }

    private void build(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = UUID.randomUUID().toString().toCharArray();
            ks.load(null, password);
            File tmpFile = File.createTempFile("keystore", ".jks");
            
            addKeyPairToStore(ks, alias, password);
            
            FileOutputStream fos = new FileOutputStream(tmpFile);
            ks.store(fos, password);
            fos.close();
            
            this.setJksFile(tmpFile);
            this.setPassword(password);
        } catch (Exception e) {
            throw new WebberisGlobalException("Could not create key pair -> " + e.getMessage(), e);
        }
    }
    
    private void addKeyPairToStore(KeyStore ks, String alias, char[] pass) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.genKeyPair();
        X509Certificate certificate = generateCertificate(keyPair);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = certificate;
        ks.setKeyEntry(alias, keyPair.getPrivate(), pass, chain);
        this.setPublicKey(certificate.getPublicKey());
    }

    private static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        
        X500Name issuer = new X500Name("CN=MapviewGlobalLexisNexis");
        
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(30)));
        
        X509v3CertificateBuilder certif = new X509v3CertificateBuilder(issuer, BigInteger.valueOf(now.toEpochMilli()), 
                notBefore, notAfter, issuer, publicKeyInfo);
        
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSA").build(keyPair.getPrivate());
        
        X509CertificateHolder certHolder = certif.build(sigGen);
        
        return new JcaX509CertificateConverter().getCertificate(certHolder);
     }

}
