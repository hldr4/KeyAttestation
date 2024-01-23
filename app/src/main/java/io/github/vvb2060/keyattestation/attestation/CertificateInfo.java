package io.github.vvb2060.keyattestation.attestation;

import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import io.github.vvb2060.keyattestation.AppApplication;

public class CertificateInfo {
    public static final int KEY_FAILED = -1;
    public static final int KEY_UNKNOWN = 0;
    public static final int KEY_AOSP = 1;
    public static final int KEY_GOOGLE = 2;
    public static final int KEY_KNOX = 3;
    public static final int KEY_OEM = 4;

    public static final int CERT_UNKNOWN = 0;
    public static final int CERT_SIGN = 1;
    public static final int CERT_REVOKED = 2;
    public static final int CERT_EXPIRED = 3;
    public static final int CERT_NORMAL = 4;

    private static final String GOOGLE_ROOT_PUBLIC_KEY = "" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU" +
            "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j" +
            "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y" +
            "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X" +
            "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI" +
            "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB" +
            "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q" +
            "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp" +
            "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7" +
            "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82" +
            "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+" +
            "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

    private static final String AOSP_ROOT_EC_PUBLIC_KEY = "" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==";

    private static final String AOSP_ROOT_RSA_PUBLIC_KEY = "" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
            "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
            "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
            "+Vfkl5YLCazOkjWFmwIDAQAB";

    private static final String KNOX_SAKV1_ROOT_PUBLIC_KEY = "" +
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r" +
            "5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDo" +
            "fBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526" +
            "FFAK3slSUgC8RObbxys=";

    private static final String KNOX_SAKV2_ROOT_PUBLIC_KEY = "" +
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA" +
            "46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12" +
            "4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo" +
            "ZsapxB0gAOs0jSPRX5M=";
    
    private static final String KNOX_SAKMV1_ROOT_PUBLIC_KEY = "" +
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX" +
            "2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkL" +
            "oiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKs" +
            "n2fbQPtpGlNxgEfd6Y8=";

    // 1 and 2 are possibly invalid, but can't verify for sure
    private static final String KNOX_UNKNOWN_ROOT_PUBLIC_KEY1 = "" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvtPYbYi7FoEDaDZjXjzk" +
            "u3AAW/ZYCBHvSkCriH7lmbHq1HQETKkKG3FQ8DcDDDBXN/DSVqSFVeZzyqzFeGHJ" +
            "BBeA7TfiHqRGATml0krixMEeCXVYvm6vcWyTg5raE5R4/fKRI/iL1SBZRdMZraum" +
            "V/RUCVtlknoDhcfQvX3EwMvjz7tBEBPuh1z2h6jcMN1qzkbWG2Gh4gPd6Ua7YHXC" +
            "QAPY6t1x81lmsOTcqJF5Kub5gX/e5Qc/luGgAFcdb7vzr63g6mlkWObzQYIfa3s9" +
            "rsB+JJA/gOT1u6b1JBhRMK7xMZZjMhaWBqHrvR2Z5V6k7riI3SkhCrC3wGBGDtHF" +
            "uKmMgoNAGLiQu9qOLxwI2zhotV5v7/pDerXYWWdup63hsjlw2JeUlQFtmv4irbE4" +
            "ZtdLpUtzImQUsQ6jkc4OoDh5XfeM1c3NndrmtOMs1y06q45gMqO5pY2wqrEkMTuR" +
            "IbbZdyk2I1cnVKFfBQXtcTFv1nBZljFQqdoMjNB56pRoHnRf6kYv1pQmEgL1mSbd" +
            "NWJ7JttPGRbPfuMUTbV1a6CH3xklJrwXYEpRyp/LO4IbPgqsuW6SUYDM0b436hqH" +
            "IGIT7A0qF1cIkw/agTuplIrjbt9NACDA2XHKk0uOGBpi1QJxX+QzFivq+1Xa7xD/" +
            "rzXOYttgq2R8MaINwNEHhe0CAwEAAQ==";

    private static final String KNOX_UNKNOWN_ROOT_PUBLIC_KEY2 = "" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOKn9riLhi/nCn6x8I6q" +
            "hzBnxrFIdbVv3UrfqJEf4CQ8MUtoKK9l7g+e/XtwtOfD5nHprgPWX4w/vPLuj7Pc" +
            "W6x69tu26h+T/J5jlmLiKoqYnmH7MbDNdv6v7lBEbPJHjYNH9i3oH1u5UeUrLHk5" +
            "aNPhGPOLQH8VPYsrrfJIIgHKuNnMTR+L3Vf9MqyCeehIh97WZ4rbNxTDmZ+iorcQ" +
            "tVnvhXtMt6v+N65BvkeuL8In1knVJIsfC/H/riEfJ3r5YHpD57kYXJ93epVRK9I5" +
            "IryILL+61V4g5iyjQOvqAO/WzxbOZNJiG3Hdt2bsHl4mEtcUCvOnuG1h0Jkpyfg6" +
            "8QIDAQAB";

    private static final String KNOX_UNKNOWN_ROOT_PUBLIC_KEY3 = "" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4MKBh1Wv0tHgjaNygCO5" +
            "9jGA3wkxBttSsJhamGseXPNQbWa/gqOrJkJ7Wg26Bj/k5A6GVad6WaTD1W3Cm8N+" +
            "wDgzQ8O8hQitZervX2iZTMTnXVWV5IMOKBIWn9TExmwM7xwJgMG1+TVC58fuz4Y6" +
            "Bd2UG6zCfNsgIW5saqQ7i/QVJckyoocAqu510qn7hg7a1sV6vnaoO71uURmj1CCL" +
            "ZzDeI8IpnmvT5PQ+dfuF4G5RRxSyRB3w7OnkxOFF/lBsTooRv1qzCkcNIEQgz4vl" +
            "zfHgG3durSS0kdafTQ1N5TKSWEp0kAZt1V9ROrEy3Vf+WwIerxYMIcJd1120oyQR" +
            "3QIDAQAB"; // Root CA RSA

    private static final String KNOX_UNKNOWN_ROOT_PUBLIC_KEY4 = "" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1GrVFUqLAK4f7GkXKXDv" +
            "083jjYn69sQDTMWVRsvDV08HBYomJ+B2RsuMTkP7tJeoRxXYnPrJnDYelazWM6z8" +
            "K0/v3rqtlR5ZqtoM1GEnT7OaoeDBj/aO4mcGBmpFIUZjap6dXvVyMSJrHBBONQ49" +
            "DbjJGfqsKAhzagT9GuNIWMVHL2w0gJtf1EkrKeicjaT9MQhOTJ//vX+av0RQrKtl" +
            "Q43NscUqJMdjCnYr9nYRmqllN51nDyZQKkFY5qftSIqPEGSAdJUwCGeNH6EYb3Fn" +
            "6L8YPZcjyhQ3z90okYEkRyppIazTVhxlHLSocUJ/cgSSkFjkwDTpG+LBR5JqatDO" +
            "L0t8XHMdkbDbD2XW+EhvOvXhKNZ2H3N46bcFs9/Ln5KYmq6hqGEuQz/p3R5Ff3nc" +
            "o3nvGPmh9Q/36VukcQImev1gQORhitEEQWKGwGkxhIQ51FS8j4T9pJGj2v5KLfQs" +
            "I7rPtczlMhefbQk7gMesOvU8oQDhvz4ej51XM2bF6Kxgzq1v1LeoCINF0fg+s+fm" +
            "LXaeVLFAK/lw6N+H7c8VRQtJhoBq6FP4yHwuL13wECpZQnI88YzpwKjSt2zLNTNz" +
            "zkRDkTaOIgdKB1DVhK/5mhaXO3aoWxklK+c27LFK9kP3+p273OQTNxbW1s3JKMQk" +
            "NFjwIHcQoChMj6agudo0QVMCAwEAAQ==";

    private static final byte[] googleKey = Base64.decode(GOOGLE_ROOT_PUBLIC_KEY, 0);
    private static final byte[] aospEcKey = Base64.decode(AOSP_ROOT_EC_PUBLIC_KEY, 0);
    private static final byte[] aospRsaKey = Base64.decode(AOSP_ROOT_RSA_PUBLIC_KEY, 0);
    private static final byte[] knoxSakV1Key = Base64.decode(KNOX_SAKV1_ROOT_PUBLIC_KEY, 0);
    private static final byte[] knoxSakV2Key = Base64.decode(KNOX_SAKV2_ROOT_PUBLIC_KEY, 0);
    private static final byte[] knoxSakmV1Key = Base64.decode(KNOX_SAKMV1_ROOT_PUBLIC_KEY, 0);
    private static final byte[] knoxKeyU1 = Base64.decode(KNOX_UNKNOWN_ROOT_PUBLIC_KEY1, 0);
    private static final byte[] knoxKeyU2 = Base64.decode(KNOX_UNKNOWN_ROOT_PUBLIC_KEY2, 0);
    private static final byte[] knoxKeyU3 = Base64.decode(KNOX_UNKNOWN_ROOT_PUBLIC_KEY3, 0);
    private static final byte[] knoxKeyU4 = Base64.decode(KNOX_UNKNOWN_ROOT_PUBLIC_KEY4, 0);
    private static final Set<PublicKey> oemKeys = getOemPublicKey();

    private final X509Certificate cert;
    private int issuer = KEY_UNKNOWN;
    private int status = CERT_UNKNOWN;
    private GeneralSecurityException securityException;
    private Attestation attestation;
    private CertificateParsingException certException;

    private Integer certsIssued;

    private CertificateInfo(X509Certificate cert) {
        this.cert = cert;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public int getIssuer() {
        return issuer;
    }

    public int getStatus() {
        return status;
    }

    public GeneralSecurityException getSecurityException() {
        return securityException;
    }

    public Attestation getAttestation() {
        return attestation;
    }

    public CertificateParsingException getCertException() {
        return certException;
    }

    public Integer getCertsIssued() {
        return certsIssued;
    }

    private void checkIssuer() {
        var publicKey = cert.getPublicKey().getEncoded();
        if (Arrays.equals(publicKey, googleKey)) {
            issuer = KEY_GOOGLE;
        } else if (Arrays.equals(publicKey, aospEcKey)) {
            issuer = KEY_AOSP;
        } else if (Arrays.equals(publicKey, aospRsaKey)) {
            issuer = KEY_AOSP;
        } else if (Arrays.equals(publicKey, knoxSakV1Key)
                   || Arrays.equals(publicKey, knoxSakV2Key)
                   || Arrays.equals(publicKey, knoxSakmV1Key)
                   || Arrays.equals(publicKey, knoxKeyU1)
                   || Arrays.equals(publicKey, knoxKeyU2)
                   || Arrays.equals(publicKey, knoxKeyU3)
                   || Arrays.equals(publicKey, knoxKeyU4)) {
            issuer = KEY_KNOX;
        } else if (oemKeys != null) {
            for (var key : oemKeys) {
                if (Arrays.equals(publicKey, key.getEncoded())) {
                    issuer = KEY_OEM;
                    break;
                }
            }
        }
    }

    private void checkStatus(PublicKey parentKey) {
        try {
            status = CERT_SIGN;
            cert.verify(parentKey);
            status = CERT_REVOKED;
            var certStatus = RevocationList.get(cert.getSerialNumber());
            if (certStatus != null) {
                throw new CertificateException("Certificate revocation " + certStatus);
            }
            status = CERT_EXPIRED;
            cert.checkValidity();
            status = CERT_NORMAL;
        } catch (GeneralSecurityException e) {
            securityException = e;
        }
    }

    private boolean checkAttestation() {
        boolean terminate;
        try {
            attestation = Attestation.loadFromCertificate(cert);
            // If key purpose included KeyPurpose::SIGN,
            // then it could be used to sign arbitrary data, including any tbsCertificate,
            // and so an attestation produced by the key would have no security properties.
            // If the parent certificate can attest that the key purpose is only KeyPurpose::ATTEST_KEY,
            // then the child certificate can be trusted.
            var purposes = attestation.getTeeEnforced().getPurposes();
            terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);
        } catch (CertificateParsingException e) {
            certException = e;
            terminate = false;
            checkProvisioningInfo();
        }
        return terminate;
    }

    private void checkProvisioningInfo() {
        // If have more data later, move to separate class
        var bytes = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.30");
        if (bytes == null) return;
        try (var is = new ASN1InputStream(bytes)) {
            var string = (ASN1OctetString) is.readObject();
            var cborBytes = string.getOctets();
            var map = (Map) CborDecoder.decode(cborBytes).get(0);
            for (var key : map.getKeys()) {
                var keyInt = ((Number) key).getValue().intValue();
                if (keyInt == 1) {
                    certsIssued = CborUtils.getInt(map, key);
                } else {
                    Log.w(AppApplication.TAG, "new provisioning info: "
                            + keyInt + " = " + map.get(key));
                }
            }
        } catch (Exception e) {
            Log.e(AppApplication.TAG, "checkProvisioningInfo", e);
        }
    }

    public static AttestationResult parseCertificateChain(List<X509Certificate> certs) {
        var infoList = new ArrayList<CertificateInfo>();

        var parent = certs.get(certs.size() - 1);
        for (int i = certs.size() - 1; i >= 0; i--) {
            var parentKey = parent.getPublicKey();
            var info = new CertificateInfo(certs.get(i));
            infoList.add(info);
            info.checkStatus(parentKey);
            if (parent == info.cert) {
                info.checkIssuer();
            } else {
                parent = info.cert;
            }
            if (info.checkAttestation()) {
                break;
            }
        }

        return AttestationResult.form(infoList);
    }

    private static List<X509Certificate> sortCerts(List<X509Certificate> certs) {
        if (certs.size() < 2) {
            return certs;
        }

        var issuer = certs.get(0).getIssuerX500Principal();
        boolean okay = true;
        for (var cert : certs) {
            var subject = cert.getSubjectX500Principal();
            if (issuer.equals(subject)) {
                issuer = subject;
            } else {
                okay = false;
                break;
            }
        }
        if (okay) {
            return certs;
        }

        var newList = new ArrayList<X509Certificate>(certs.size());
        for (var cert : certs) {
            boolean found = false;
            var subject = cert.getSubjectX500Principal();
            for (var c : certs) {
                if (c == cert) continue;
                if (c.getIssuerX500Principal().equals(subject)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                newList.add(cert);
            }
        }
        if (newList.size() != 1) {
            return certs;
        }

        var oldList = new LinkedList<>(certs);
        oldList.remove(newList.get(0));
        for (int i = 0; i < newList.size(); i++) {
            issuer = newList.get(i).getIssuerX500Principal();
            for (var it = oldList.iterator(); it.hasNext(); ) {
                var cert = it.next();
                if (cert.getSubjectX500Principal().equals(issuer)) {
                    newList.add(cert);
                    it.remove();
                    break;
                }
            }
        }
        if (!oldList.isEmpty()) {
            return certs;
        }
        return newList;
    }

    public static AttestationResult parseCertificateChain(CertPath certPath)
            throws CertificateParsingException {
        // noinspection unchecked
        var certs = (List<X509Certificate>) certPath.getCertificates();
        if (certs.isEmpty()) {
            throw new CertificateParsingException("No certificate found");
        }
        return parseCertificateChain(sortCerts(certs));
    }

    private static Set<PublicKey> getOemPublicKey() {
        var resName = "android:array/vendor_required_attestation_certificates";
        var res = AppApplication.app.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id == 0) {
            return null;
        }
        var set = new HashSet<PublicKey>();
        try {
            var cf = CertificateFactory.getInstance("X.509");
            for (var s : res.getStringArray(id)) {
                var cert = s.replaceAll("\\s+", "\n")
                        .replaceAll("-BEGIN\\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                        .replaceAll("-END\\nCERTIFICATE-", "-END CERTIFICATE-");
                var input = new ByteArrayInputStream(cert.getBytes());
                var publicKey = cf.generateCertificate(input).getPublicKey();
                set.add(publicKey);
            }
        } catch (CertificateException e) {
            Log.e(AppApplication.TAG, "getOemKeys: ", e);
            return null;
        }
        set.removeIf(key -> Arrays.equals(key.getEncoded(), googleKey));
        if (set.isEmpty()) {
            return null;
        }
        set.forEach(key -> Log.i(AppApplication.TAG, "getOemKeys: " + key));
        return set;
    }
}
