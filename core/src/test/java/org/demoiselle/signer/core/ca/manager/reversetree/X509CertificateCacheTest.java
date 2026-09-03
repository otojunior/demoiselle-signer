package org.demoiselle.signer.core.ca.manager.reversetree;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class X509CertificateCacheTest {
    private static KeyPair keyPair;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    @Test
    public void shouldStoreIssuerRelationsInTreeNodes() throws Exception {
        X509Certificate root = certificate("Root", 1L);
        X509Certificate issuer = certificate("Issuer", 2L);
        X509Certificate issued = certificate("Issued", 3L);
        X509Certificate rejectedIssuer = certificate("Rejected", 4L);
        X509CertificateCache cache = new X509CertificateCache();

        assertNull(cache.getIsCAofCertificate(issuer, issued));

        cache.setIsCAofCertificate(rejectedIssuer, issued, false);
        assertNull(cache.getIsCAofCertificate(rejectedIssuer, issued));
        assertEquals(0, cache.size());
        assertNull(cache.get(issued));

        cache.setIsCAofCertificate(issuer, issued, true);
        assertTrue(cache.getIsCAofCertificate(issuer, issued));
        assertNull(cache.get(issued));

        cache.add(Arrays.asList(issued, issuer, root));

        List<X509Certificate> path = cache.get(issued).pathToRoot();
        assertEquals(Arrays.asList(issued, issuer, root), path);
        assertTrue(cache.getIsCAofCertificate(root, issuer));
        assertFalse(cache.getIsCAofCertificate(root, issued));
        assertNull(cache.getIsCAofCertificate(rejectedIssuer, issued));
    }

    @Test
    public void shouldStoreSelfSignedRelationWithoutCreatingACycle() throws Exception {
        X509Certificate root = certificate("Root", 1L);
        X509CertificateCache cache = new X509CertificateCache();

        cache.setIsCAofCertificate(root, root, true);

        assertTrue(cache.getIsCAofCertificate(root, root));
        assertTrue(cache.get(root).isRoot());
        assertEquals(Collections.singletonList(root), cache.get(root).pathToRoot());
    }

    private X509Certificate certificate(final String commonName, final long serial) throws Exception {
        X500Name name = new X500Name("CN=" + commonName);
        Date notBefore = new Date(System.currentTimeMillis() - 1000L);
        Date notAfter = new Date(System.currentTimeMillis() + 60000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(serial),
            notBefore,
            notAfter,
            name,
            keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }
}